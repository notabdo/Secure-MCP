"""Configuration, constants, and severity rules."""

from pathlib import Path

# File extensions to language mapping
EXT_TO_LANG = {
    ".py": "python",
    ".ts": "typescript", ".tsx": "typescript",
    ".js": "javascript", ".jsx": "javascript",
    ".rs": "rust",
    ".go": "go",
}

TS_LANG_NAME = {
    "typescript": "typescript",
    "javascript": "javascript",
    "python": "python",
    "rust": "rust",
    "go": "go",
}

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules", "target", "dist", "build", ".git", 
    "__pycache__", "venv", ".venv"
}

# Dependency file parsers mapping
DEP_FILES = {
    "pyproject.toml": "python",
    "package.json": "javascript",
    "Cargo.toml": "rust",
    "go.mod": "go",
}

# Severity rules for each language -- using full resolved names
RULES = {
    "python": {
        # ---- code execution ----
        "eval": ("code_execution", "critical", "Direct execution of a string as Python code"),
        "exec": ("code_execution", "critical", "Dynamic execution of Python code"),
        "compile": ("code_execution", "warning", "Compiling and potentially executing untrusted code"),
        "__import__": ("dynamic_import", "warning", "Dynamic import at runtime"),

        # ---- shell execution ----
        "os.system": ("shell_exec", "critical", "Direct execution of a shell command"),
        "os.popen": ("shell_exec", "critical", "Opening a pipe to/from a shell command"),
        "subprocess.Popen": ("shell_exec", "warning", "Running a subprocess"),
        "subprocess.run": ("shell_exec", "warning", "Running a subprocess"),
        "subprocess.call": ("shell_exec", "warning", "Running a subprocess"),
        "subprocess.check_output": ("shell_exec", "warning", "Running a subprocess"),
        "subprocess.getoutput": ("shell_exec", "warning", "Capturing shell command output"),
        "subprocess.getstatusoutput": ("shell_exec", "warning", "Capturing shell command status and output"),
        "shell=True": ("shell_exec", "warning", "Using shell=True may enable shell injection"),

        # ---- deserialization ----
        "pickle.loads": ("deserialization", "critical", "Deserialization of untrusted data -- potentially executing code"),
        "pickle.load": ("deserialization", "critical", "Deserialization of untrusted data -- potentially executing code"),
        "yaml.load": ("deserialization", "critical", "Without SafeLoader, this poses a code execution risk"),
        "marshal.loads": ("deserialization", "warning", "Unsafe deserialization, can execute code"),
        "jsonpickle.decode": ("deserialization", "warning", "Deserialization with jsonpickle, may execute code"),

        # ---- file operations ----
        "open('w": ("file_write", "info", "File opened in write mode"),
        "open('a": ("file_write", "info", "File opened in append mode"),

        # ---- insecure temp files ----
        "tempfile.mktemp": ("insecure_temp", "warning", "Insecure temp file creation (use mkstemp)"),
        "tempfile.NamedTemporaryFile": ("file_write", "info", "Temporary file creation"),

        # ---- weak cryptography ----
        "hashlib.md5": ("weak_crypto", "warning", "MD5 is cryptographically broken"),
        "hashlib.sha1": ("weak_crypto", "warning", "SHA1 is considered weak"),
        "cryptography.hazmat": ("weak_crypto", "warning", "Using low-level primitives directly"),
        # process replacement / arbitrary execution
        "os.execl": ("shell_exec", "critical", "Replaces current process with a new program (execl)"),
        "os.execle": ("shell_exec", "critical", "Replaces current process with a new program (execle)"),
        "os.execlp": ("shell_exec", "critical", "Replaces current process using PATH search"),
        "os.execv": ("shell_exec", "critical", "Replaces current process with argument vector"),
        "os.execve": ("shell_exec", "critical", "Replaces current process with argument vector and environment"),
        "os.execvp": ("shell_exec", "critical", "Replaces current process with PATH search (execvp)"),

        # dynamic code via compile + exec
        "exec(compile": ("code_execution", "critical", "Compile and immediately execute dynamic code"),

        # CTypes / FFI – arbitrary native code
        "ctypes.CDLL": ("code_execution", "warning", "Loading a native library from a path – possible code execution"),
        "ctypes.cdll.LoadLibrary": ("code_execution", "warning", "Loading a dynamic library dynamically"),

        # file operations beyond basic write
        "open('w+": ("file_write", "info", "File opened in read-write mode (truncating)"),
        "open('a+": ("file_write", "info", "File opened in read-append mode"),
        "shutil.copy": ("file_write", "info", "Copying files – may overwrite sensitive files"),
        "shutil.move": ("file_write", "info", "Moving files – may overwrite or relocate sensitive files"),
        "os.remove": ("file_write", "warning", "Deleting a file"),
        "os.unlink": ("file_write", "warning", "Deleting a file (unlink)"),
        "os.rmdir": ("file_write", "warning", "Removing a directory"),

        # network / data exfiltration
        "socket.socket": ("network_request", "info", "Creating a network socket – possible data leak"),
        "requests.post": ("network_request", "info", "Sending HTTP POST – potential data exfiltration"),
        "urllib.request.urlopen": ("network_request", "info", "Making a URL request"),

        # SQL injection patterns
        "execute(": ("sql_injection", "warning", "Raw SQL execution – ensure parameterized queries"),
        "cursor.execute": ("sql_injection", "warning", "Raw database query – use parameterization"),
    },

    "javascript": {
        # ---- code execution ----
        "eval": ("code_execution", "critical", "Dynamic code execution"),
        "Function(" : ("code_execution", "critical", "Creating function from string is equivalent to eval"),
        "setTimeout(" : ("code_execution", "warning", "String argument in setTimeout gets evaluated"),
        "setInterval(" : ("code_execution", "warning", "String argument in setInterval gets evaluated"),
        "vm.runInNewContext": ("code_execution", "critical", "Executing code in an isolated but dynamic context"),
        "vm.runInThisContext": ("code_execution", "critical", "Dynamic code execution"),

        # ---- shell execution ----
        "child_process.exec": ("shell_exec", "critical", "Executing shell command"),
        "child_process.execSync": ("shell_exec", "critical", "Executing shell command (synchronous)"),
        "child_process.spawn": ("shell_exec", "warning", "Running a subprocess"),
        "child_process.fork": ("shell_exec", "warning", "Forking a new Node.js process"),

        # ---- file operations ----
        "fs.writeFile": ("file_write", "warning", "Writing file (async)"),
        "fs.writeFileSync": ("file_write", "warning", "Writing file (synchronous)"),
        "fs.appendFile": ("file_write", "warning", "Appending to file"),
        "fs.appendFileSync": ("file_write", "warning", "Appending to file (synchronous)"),

        # ---- XSS (client-side) ----
        "document.write": ("xss", "warning", "Dynamically writing HTML content"),
        ".innerHTML": ("xss", "warning", "Setting innerHTML may lead to XSS"),
        "dangerouslySetInnerHTML": ("xss", "warning", "React prop bypassing XSS protection"),

        # ---- information leakage ----
        "localStorage.setItem": ("info_leak", "info", "Storing data in localStorage"),
        "sessionStorage.setItem": ("info_leak", "info", "Storing data in sessionStorage"),

        "global.eval": ("code_execution", "critical", "Direct eval call via global object"),
        "new Function(": ("code_execution", "critical", "Creating function from string (alternative phrasing)"),
        "Reflect.construct": ("code_execution", "warning", "Dynamic constructor invocation from string"),

        "child_process.execFile": ("shell_exec", "critical", "Executing a file without shell (still dangerous)"),
        "child_process.execFileSync": ("shell_exec", "critical", "Synchronous file execution"),
        "child_process.spawnSync": ("shell_exec", "warning", "Synchronous subprocess spawn"),

        "fs.readFile": ("file_read", "info", "Reading file contents – potential data exposure"),
        "fs.readFileSync": ("file_read", "info", "Synchronous file read"),
        "fs.createWriteStream": ("file_write", "warning", "Creating a writable stream"),
        "fs.createReadStream": ("file_read", "info", "Creating a readable stream"),
        "fs.unlink": ("file_write", "warning", "Deleting a file"),
        "fs.rmdir": ("file_write", "warning", "Removing a directory"),

        "net.connect": ("network_request", "info", "Initiating a TCP connection"),
        "net.createConnection": ("network_request", "info", "Creating a network connection"),
        "dgram.createSocket": ("network_request", "info", "Creating a UDP socket"),
        "fetch(": ("network_request", "info", "Making an HTTP request (Fetch API)"),
        "XMLHttpRequest": ("network_request", "info", "Creating an XHR request"),
        "new WebSocket": ("network_request", "info", "Opening a WebSocket connection"),

        ".outerHTML": ("xss", "warning", "Setting outerHTML – can lead to DOM-based XSS"),
        "insertAdjacentHTML": ("xss", "warning", "Inserting HTML strings dynamically"),

        "crypto.createHash('md5'": ("weak_crypto", "warning", "Using MD5 hashing in Node.js"),
        "crypto.createHash('sha1'": ("weak_crypto", "warning", "Using SHA1 hashing in Node.js"),
    },

    "typescript": {},  # set to match javascript below

    "rust": {
        # ---- shell execution ----
        "Command::new": ("shell_exec", "critical", "Running a process/shell command"),
        "std::process::Command": ("shell_exec", "critical", "Running a process/shell command"),

        # ---- file operations ----
        "fs::write": ("file_write", "warning", "Writing file directly"),
        "std::fs::write": ("file_write", "warning", "Writing file directly"),

        # ---- memory safety ----
        "mem::transmute": ("memory_safety", "warning", "Unsafe raw memory conversion (transmute)"),
        "unsafe {": ("memory_safety", "info", "Unsafe block, manual safety checks required"),

        "std::mem::transmute_copy": ("memory_safety", "warning", "Unsafe transmute without ownership checks"),
        "std::ptr::read": ("memory_safety", "warning", "Unsafe raw pointer read"),
        "std::ptr::write": ("memory_safety", "warning", "Unsafe raw pointer write"),
        "unsafe fn": ("memory_safety", "info", "Function declared as unsafe – manual review needed"),
        "unsafe impl": ("memory_safety", "info", "Trait impl marked unsafe – manual review needed"),

        "include_str!": ("file_inclusion", "info", "Including a file at compile time"),
        "include_bytes!": ("file_inclusion", "info", "Including binary data at compile time"),

        "std::env::var": ("info_leak", "info", "Reading environment variable – may leak secrets"),
        "std::env::vars": ("info_leak", "info", "Iterating over all environment variables"),

        "std::net::TcpStream": ("network_request", "info", "Creating a TCP stream"),
        "std::net::UdpSocket": ("network_request", "info", "Creating a UDP socket"),
    },


    "go": {
        # ---- shell execution ----
        "exec.Command": ("shell_exec", "critical", "Running a process/shell command"),
        "os/exec": ("shell_exec", "warning", "Imported os/exec for command execution"),

        # ---- file operations ----
        "os.WriteFile": ("file_write", "warning", "Writing file directly"),
        "ioutil.WriteFile": ("file_write", "warning", "Writing file directly (deprecated)"),

        # ---- weak cryptography ----
        "crypto/md5": ("weak_crypto", "warning", "MD5 is cryptographically broken"),
        "crypto/sha1": ("weak_crypto", "warning", "SHA1 is considered weak"),

        "exec.CommandContext": ("shell_exec", "critical", "Running a process with context support"),
        "os.StartProcess": ("shell_exec", "critical", "Starting a new process directly"),

        "os.OpenFile": ("file_write", "warning", "Opening a file with mode – check flags for write"),
        "os.Create": ("file_write", "warning", "Creating a file for writing"),
        "os.Remove": ("file_write", "warning", "Deleting a file"),
        "os.RemoveAll": ("file_write", "warning", "Recursively removing a path"),
        "os.Chmod": ("file_write", "info", "Changing file permissions"),
        "os.Chown": ("file_write", "info", "Changing file ownership"),

        "net.Dial": ("network_request", "info", "Initiating a network connection"),
        "net.Listen": ("network_request", "info", "Starting a network listener"),
        "net/http.Get": ("network_request", "info", "Making an HTTP GET request"),
        "net/http.Post": ("network_request", "info", "Making an HTTP POST request"),

        "crypto/des": ("weak_crypto", "warning", "DES is obsolete and insecure"),
        "crypto/rc4": ("weak_crypto", "warning", "RC4 is insecure and should not be used"),
        "math/rand": ("weak_crypto", "warning", "Use crypto/rand for cryptographic randomness"),
    },
}
RULES["typescript"] = RULES["javascript"]

# Network-related modules per language
NETWORK_MODULES = {
    "python": {"httpx", "requests", "urllib", "urllib3", "socket", "aiohttp"},
    "javascript": {"http", "https", "axios", "node-fetch", "undici", "child_process"},
    "typescript": {"http", "https", "axios", "node-fetch", "undici"},
    "rust": {"reqwest", "hyper", "tokio"},
    "go": {"net/http"},
}

# Text labels (no emoji)
SEVERITY_LABELS = {
    "critical": "[CRIT]",
    "warning": "[WARN]",
    "info": "[INFO]",
}