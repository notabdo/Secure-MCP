"""AST-based source code scanner using tree-sitter with rich context extraction."""

from pathlib import Path

from tree_sitter_languages import get_parser

from .config import EXT_TO_LANG, RULES, NETWORK_MODULES, SKIP_DIRS
from .models import ScanReport


def text(node, src):
    """Extract text from a tree-sitter node."""
    return src[node.start_byte:node.end_byte].decode(errors="ignore")


def line_text(node, src):
    """Extract the full line containing a node."""
    start = src.rfind(b"\n", 0, node.start_byte) + 1
    end = src.find(b"\n", node.start_byte)
    if end == -1:
        end = len(src)
    return src[start:end].decode(errors="ignore").strip()


def string_literal_value(node, src):
    """Extract string literal value without quotes."""
    t = text(node, src)
    return t.strip("'\"`")



def normalize_module(mod: str) -> str:
    """Normalize module paths like node:fs or fs/promises to fs."""
    mod = mod.removeprefix("node:")
    if mod == "fs/promises":
        return "fs"
    if "/" in mod and mod.split("/")[0] in ("fs", "path", "os"):
        return mod.split("/")[0]
    return mod


def resolve_name(node, src, lang, alias_map):
    """Resolve a node to its fully qualified name using alias resolution."""
    t = node.type
    if t == "identifier":
        name = text(node, src)
        return alias_map.get(name, name)
    if lang == "python" and t == "attribute":
        obj = resolve_name(node.child_by_field_name("object"), src, lang, alias_map)
        attr = text(node.child_by_field_name("attribute"), src)
        return f"{obj}.{attr}"
    if lang in ("javascript", "typescript") and t == "member_expression":
        obj = resolve_name(node.child_by_field_name("object"), src, lang, alias_map)
        prop = text(node.child_by_field_name("property"), src)
        return f"{obj}.{prop}"
    if lang == "rust" and t == "scoped_identifier":
        path_node = node.child_by_field_name("path")
        name_node = node.child_by_field_name("name")
        path = resolve_name(path_node, src, lang, alias_map) if path_node else None
        name = text(name_node, src)
        return f"{path}.{name}" if path else name
    if lang == "rust" and t == "field_expression":
        val = resolve_name(node.child_by_field_name("value"), src, lang, alias_map)
        f = text(node.child_by_field_name("field"), src)
        return f"{val}.{f}"
    if lang == "go" and t == "selector_expression":
        obj = resolve_name(node.child_by_field_name("operand"), src, lang, alias_map)
        f = text(node.child_by_field_name("field"), src)
        return f"{obj}.{f}"
    return text(node, src)


# =========================================================
# Rich Context Extraction
# =========================================================

FUNCTION_NODE_TYPES = {
    "python": {"function_definition", "method_definition", "lambda"},
    "javascript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
    "typescript": {"function_declaration", "function_expression", "arrow_function", "method_definition"},
    "rust": {"function_item", "closure_expression"},
    "go": {"function_declaration", "func_literal", "method_declaration"},
}

CLASS_NODE_TYPES = {
    "python": {"class_definition"},
    "javascript": {"class_declaration"},
    "typescript": {"class_declaration"},
    "rust": {"impl_item"},
    "go": {"type_declaration"},
}


def find_enclosing_scope(node, src, lang):
    """Walk up the AST to find the enclosing function/class and return its text."""
    current = node
    func_node = None
    class_node = None
    while current is not None:
        if current.type in FUNCTION_NODE_TYPES.get(lang, set()):
            func_node = current
        if current.type in CLASS_NODE_TYPES.get(lang, set()):
            class_node = current
        current = current.parent

    parts = []
    if class_node:
        parts.append(f"// --- Enclosing Class/Impl ---\n{text(class_node, src)}")
    if func_node:
        parts.append(f"// --- Enclosing Function ---\n{text(func_node, src)}")
    return "\n\n".join(parts)


def extract_call_arguments(node, src, lang, alias_map):
    """Extract and analyze arguments passed to a dangerous call."""
    args_node = node.child_by_field_name("arguments")
    if not args_node:
        return ""

    args = []
    for child in args_node.children:
        if child.type in ("(", ")", ","):
            continue
        arg_text = text(child, src)
        arg_type = child.type

        # Analyze if argument is user-controlled
        risk_note = ""
        if arg_type in ("string", "string_literal"):
            risk_note = " [STATIC_STRING]"
        elif arg_type == "identifier":
            risk_note = " [VARIABLE]"
        elif arg_type in ("call_expression", "call"):
            inner = resolve_name(child.child_by_field_name("function"), src, lang, alias_map)
            risk_note = f" [CALL_RESULT: {inner}]"
        elif arg_type in ("binary_expression", "concatenation"):
            risk_note = " [CONCATENATION - possible injection]"
        elif arg_type == "format_expression":
            risk_note = " [FORMATTED_STRING - possible injection]"
        elif "template" in arg_type:
            risk_note = " [TEMPLATE_LITERAL - possible injection]"

        args.append(f"  - [{arg_type}]{risk_note}: {arg_text}")

    return "Arguments passed to dangerous call:\n" + "\n".join(args) if args else ""


def find_relevant_imports(root_node, src, lang, resolved_name):
    """Find imports that are relevant to the dangerous call."""
    imports = []
    target_module = resolved_name.split(".")[0] if "." in resolved_name else resolved_name

    def walk(node):
        t = node.type
        if lang == "python" and t in ("import_statement", "import_from_statement", "aliased_import"):
            imp_text = text(node, src).strip()
            if target_module in imp_text:
                imports.append(imp_text)
        elif lang in ("javascript", "typescript") and t in ("import_statement", "call_expression"):
            imp_text = text(node, src).strip()
            if target_module in imp_text or (t == "call_expression" and "require" in imp_text):
                imports.append(imp_text)
        elif lang == "rust" and t == "use_declaration":
            imp_text = text(node, src).strip()
            if target_module in imp_text:
                imports.append(imp_text)
        elif lang == "go" and t == "import_spec":
            imp_text = text(node, src).strip()
            if target_module in imp_text:
                imports.append(imp_text)

        for c in node.children:
            walk(c)

    walk(root_node)
    # Deduplicate and limit
    seen = set()
    result = []
    for imp in imports:
        if imp not in seen:
            seen.add(imp)
            result.append(imp)
            if len(result) >= 5:
                break
    return result


def build_alias_map(root_node, src, lang):
    """Build a map of local aliases to their original module names.

    Also returns the set of imported modules.
    """
    aliases = {}
    imported_modules = set()
    

    def walk(node):
        t = node.type
        if lang == "python" and t == "aliased_import":
            name_node = node.child_by_field_name("name")
            alias_node = node.child_by_field_name("alias")
            if name_node and alias_node:
                real = text(name_node, src)
                aliases[text(alias_node, src)] = real
                imported_modules.add(real.split(".")[0])
        elif lang == "python" and t in ("import_statement", "import_from_statement"):
            for child in node.children:
                if child.type == "dotted_name":
                    imported_modules.add(text(child, src).split(".")[0])
        elif lang in ("javascript", "typescript") and t == "call_expression":
            fn = node.child_by_field_name("function")
            if fn and text(fn, src) == "require":
                args = node.child_by_field_name("arguments")
                if args and args.children:
                    for a in args.children:
                        if a.type == "string":
                            mod = string_literal_value(a, src)
                            imported_modules.add(mod)
                            parent = node.parent
                            if parent and parent.type == "variable_declarator":
                                local = parent.child_by_field_name("name")
                                if local:
                                    aliases[text(local, src)] = normalize_module(mod)
        elif lang in ("javascript", "typescript") and t == "import_statement":
            src_node = node.child_by_field_name("source")
            if src_node:
                mod = normalize_module(string_literal_value(src_node, src))
                imported_modules.add(mod)
                for c in node.children:
                    if c.type == "import_clause":
                        for cc in c.children:
                            if cc.type == "identifier":
                                aliases[text(cc, src)] = mod
                            elif cc.type == "named_imports":
                                for spec in cc.children:
                                    if spec.type == "import_specifier":
                                        name_node = spec.child_by_field_name("name")
                                        if name_node:
                                            aliases[text(name_node, src)] = f"{mod}.{text(name_node, src)}"
        elif lang == "rust" and t == "use_declaration":
            arg = node.child_by_field_name("argument")
            if arg:
                full = resolve_name(arg, src, lang, {})
                imported_modules.add(full.split(".")[0])
                aliases[full.split(".")[-1]] = full
        elif lang == "go" and t == "import_spec":
            path_node = node.child_by_field_name("path")
            if path_node:
                mod = string_literal_value(path_node, src)
                imported_modules.add(mod)
                aliases[mod.split("/")[-1]] = mod

        for c in node.children:
            walk(c)

    walk(root_node)
    return aliases, imported_modules


def scan_source_file(path: Path, lang: str, report: ScanReport):
    """Scan a single source file for dangerous patterns using AST analysis.

    Extracts rich context: enclosing function, arguments analysis, and relevant imports.
    """
    src = path.read_bytes()
    try:
        parser = get_parser("typescript" if lang == "typescript" else lang)
    except Exception:
        return
    tree = parser.parse(src)
    root = tree.root_node
    report.files_scanned += 1

    alias_map, imported = build_alias_map(root, src, lang)
    rules = RULES.get(lang, {})
    net_modules = NETWORK_MODULES.get(lang, set())
    seen_lines = set()

    def walk(node):
        t = node.type
        is_call = t in ("call", "call_expression")
        is_new = t == "new_expression"

        if is_call or is_new:
            fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
            if fn:
                resolved = resolve_name(fn, src, lang, alias_map)
                bare = resolved.split(".")[-1]
                rule = rules.get(resolved) or rules.get(bare)
                if rule:
                    cat, sev, detail = rule
                    key = (path, node.start_point[0])
                    if key not in seen_lines:
                        seen_lines.add(key)

                        # Extract rich context
                        func_ctx = find_enclosing_scope(node, src, lang)
                        args_ctx = extract_call_arguments(node, src, lang, alias_map)
                        rel_imports = find_relevant_imports(root, src, lang, resolved)

                        report.add(
                            sev, cat, str(path), node.start_point[0] + 1,
                            detail,
                            context=line_text(node, src),
                            function_context=func_ctx,
                            arguments_context=args_ctx,
                            relevant_imports=rel_imports,
                        )

                # Special case: Python open(path, "w")
                if lang == "python" and resolved == "open":
                    args = node.child_by_field_name("arguments")
                    str_children = [
                        c for c in (args.children if args else [])
                        if c.type == "string"
                    ]
                    if len(str_children) >= 2:
                        mode = string_literal_value(str_children[1], src)
                        if "w" in mode or "a" in mode:
                            key = (path, node.start_point[0])
                            if key not in seen_lines:
                                seen_lines.add(key)
                                func_ctx = find_enclosing_scope(node, src, lang)
                                args_ctx = extract_call_arguments(node, src, lang, alias_map)
                                report.add(
                                    "warning", "file_write", str(path),
                                    node.start_point[0] + 1,
                                    f"Opening file in mode '{mode}'",
                                    context=line_text(node, src),
                                    function_context=func_ctx,
                                    arguments_context=args_ctx,
                                    relevant_imports=[],
                                )

        if t == "unsafe_block":
            func_ctx = find_enclosing_scope(node, src, lang)
            report.add(
                "warning", "memory_safety", str(path),
                node.start_point[0] + 1,
                "unsafe block -- bypassed borrow checker validation",
                context=line_text(node, src),
                function_context=func_ctx,
                arguments_context="",
                relevant_imports=[],
            )

        for c in node.children:
            walk(c)

    walk(root)

    net_hit = imported & net_modules
    if net_hit:
        report.add(
            "info", "network_access", str(path), 0,
            f"Imports network libraries: {', '.join(sorted(net_hit))}"
        )
