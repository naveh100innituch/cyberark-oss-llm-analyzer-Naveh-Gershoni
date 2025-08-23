from __future__ import annotations
import re
from typing import List, Dict, Any, Tuple

RE_FIXED_BUF = re.compile(r"(?:char\s+\*?)(\w+)\s*=\s*new\s+char\[(\d+)\];|char\s+(\w+)\[(\d+)\];")
RE_MEMCPY = re.compile(r"\bmemcpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\)")
RE_ALLOC_MUL = re.compile(r"\b(\w+)\s*=\s*(\w+)\s*\*\s*(\w+)\s*;")
RE_UINT32_DECL = re.compile(r"\buint32_t\b\s+(\w+)")
RE_DELETE = re.compile(r"\bdelete(\[\])?\s+(\w+)\s*;")
RE_UNSAFE_FUNCS = re.compile(r"\b(gets|strcpy|strcat|sprintf|vsprintf|scanf)\s*\(")
RE_FORMAT_STRING = re.compile(r"\b(printf|fprintf|syslog)\s*\(\s*[a-zA-Z0-9_]+\s*\)")
RE_DANGEROUS_CALLS = re.compile(r"\b(system|popen|exec\w*|fork)\s*\(")
RE_INSECURE_RANDOM = re.compile(r"\b(rand|srand)\s*\(")
RE_HARDCODED_SECRET = re.compile(r"(password\s*=|secret\s*=|api[_-]?key\s*=)", re.IGNORECASE)
RE_FOPEN = re.compile(r"\bfopen\s*\(([^,]+),")
RE_LOOP = re.compile(r"\bwhile\s*\(\s*true\s*\)|for\s*\(\s*;\s*;\s*\)")
RE_CAST = re.compile(r"\((char\s*\*|void\s*\*)\)")
RE_UNINIT_VAR = re.compile(r"\b(int|char|float|double)\s+(\w+)\s*;")
RE_MEM_LEAK = re.compile(r"\bmalloc\s*\([^)]*\)")
RE_DEPRECATED_FUNCS = re.compile(r"\b(bzero|gets|strcpy|strcat)\s*\(")
RE_PTR_ARITH = re.compile(r"(\w+)\s*\+\s*\d+")
RE_HARDCODED_PATH = re.compile(r'".*\\.*"|"/.*/.*"')
RE_FILE_PERMS = re.compile(r"fopen\s*\([^,]+,\s*\"[wa]\".*\)")
RE_DIV_ZERO = re.compile(r"/\s*0")
RE_SIGNED_UNSIGNED = re.compile(r"\b(int|short|long)\s+.*\s*=\s*\d+U")
RE_RECURSION = re.compile(r"\b(\w+)\s*\(\s*.*\)\s*{[^}]*\1\s*\(")
RE_GLOBAL_VAR = re.compile(r"\bstatic\s+\w+\s+\w+\s*;")
RE_NULL_DEREF = re.compile(r"\*\s*\w+\s*;")
RE_BUF_UNDERFLOW = re.compile(r"\b\w+\s*\[\s*-\d+\s*\]")
RE_NO_CHECK = re.compile(r"\b(fopen|malloc|realloc|fread|fwrite)\s*\([^)]*\)\s*;")
RE_UNUSED_VAR = re.compile(r"\b(int|char|float|double)\s+(\w+)\s*;")
RE_STRNCPY_OVERFLOW = re.compile(r"\bstrncpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\)")
RE_STRCPY_NULL = re.compile(r"\bstrcpy\s*\(\s*[^,]+,\s*NULL\s*\)")
RE_DOUBLE_FREE = re.compile(r"\bfree\s*\(\s*(\w+)\s*\).*\bfree\s*\(\1\s*\)")
RE_STACK_OVERFLOW = re.compile(r"\bchar\s+\w+\[\d{5,}\];")
RE_USE_BEFORE_INIT = re.compile(r"\b(\w+)\s*=\s*\w+;\s*\1")
RE_PTR_SUBSCRIPT = re.compile(r"\*(\w+)\s*\+\s*\d+")
RE_PRINTF_USER_INPUT = re.compile(r"\bprintf\s*\(\s*[^\"].*?\)")
RE_SQL_INJECTION = re.compile(r'".*SELECT.*"')
RE_SIGNED_OVERFLOW = re.compile(r"\bint\s+\w+\s*=\s*\d+\s*\+\s*\d+;")
RE_SHIFT_OVERFLOW = re.compile(r"\b(\w+)\s*<<\s*\d+")
RE_RACE_CONDITION = re.compile(r"\b(lock|mutex|pthread_mutex_lock)\s*;")
RE_UNLOCK_WITHOUT_LOCK = re.compile(r"\b(pthread_mutex_unlock|unlock)\s*\(")
RE_FD_LEAK = re.compile(r"\b(open|fopen|socket)\s*\([^)]*\)")
RE_CLOSE_MISSING = re.compile(r"\bclose\s*\([^)]*\)")
RE_HARD_CODED_CREDENTIALS = re.compile(r"(username|password)\s*=\s*\"[^\"]+\"")
RE_WEAK_CRYPTO = re.compile(r"\bmd5|sha1\b")
RE_EXCESSIVE_MACRO = re.compile(r"#define\s+\w+\s+.+")
RE_SPRINTF_OVERFLOW = re.compile(r"\bsprintf\s*\(")
RE_ARRAY_OOB = re.compile(r"\w+\s*\[\s*\w+\s*\+\s*\d+\s*\]")
RE_DANGLING_PTR = re.compile(r"\*\s*\w+\s*;")
RE_FORMAT_STRING_VAR = re.compile(r"\bprintf\s*\(\s*\w+\s*\)")
RE_MUTEX_NO_LOCK = re.compile(r"\b(pthread_mutex_lock|lock)\s*;")
RE_FOPEN_NO_CLOSE = re.compile(r"\bfopen\s*\([^)]*\);(?!.*fclose)")
RE_HARDCODED_URL = re.compile(r'"https?://[^"]+"')
RE_UNCHECKED_RETURN = re.compile(r"\b(read|write|fread|fwrite|malloc|realloc)\s*\([^)]*\)\s*;")  

def _window(lines: List[str], idx: int, k: int = 3) -> str:
    start = max(0, idx - k)
    end = min(len(lines), idx + k + 1)
    return "".join(lines[start:end])

def analyze(source: str, enabled_rules: List[str] | None = None) -> List[Dict[str, Any]]:
    if enabled_rules is not None:
        enabled = set(enabled_rules)
    else:
        enabled = {
            "HEAP_OVERFLOW", "INT_OVERFLOW", "LOGIC_BUG", "UAF",
            "UNSAFE_FUNCS", "FORMAT_STRING", "DANG_CALL",
            "INSECURE_RANDOM", "HARDCODED_SECRET",
            "FILE_INJECTION", "UNBOUNDED_LOOP", "DANG_CAST",
            "UNINIT_VAR", "MEM_LEAK", "DEPRECATED_FUNCS", "PTR_ARITH",
            "HARDCODED_PATH", "FILE_PERMS", "DIV_ZERO", "SIGNED_UNSIGNED",
            "RECURSION", "GLOBAL_VAR", "NULL_DEREF", "BUF_UNDERFLOW",
            "NO_CHECK", "UNUSED_VAR", "STRNCPY_OVERFLOW", "STRCPY_NULL", "DOUBLE_FREE", "STACK_OVERFLOW",
            "USE_BEFORE_INIT", "PTR_SUBSCRIPT", "PRINTF_USER_INPUT", "SQL_INJECTION",
            "SIGNED_OVERFLOW", "SHIFT_OVERFLOW", "RACE_CONDITION", "UNLOCK_WITHOUT_LOCK",
            "FD_LEAK", "CLOSE_MISSING", "HARD_CODED_CREDENTIALS", "WEAK_CRYPTO", "EXCESSIVE_MACRO", "SPRINTF_OVERFLOW", "ARRAY_OOB", "DANGLING_PTR", "FORMAT_STRING_VAR",
            "MUTEX_NO_LOCK", "FOPEN_NO_CLOSE", "HARDCODED_URL", "UNCHECKED_RETURN"
        }

    findings: List[Dict[str, Any]] = []
    lines = source.splitlines(True)

    fixed_buffers: Dict[str, Tuple[int, int]] = {}
    uint32_vars: set[str] = set()
    deleted_vars: set[str] = set()

    for i, line in enumerate(lines, start=1):
        # Track uint32_t
        for m in RE_UINT32_DECL.finditer(line):
            uint32_vars.add(m.group(1))

        # Track fixed buffer allocations
        m = RE_FIXED_BUF.search(line)
        if m:
            if m.group(1) and m.group(2):
                fixed_buffers[m.group(1)] = (int(m.group(2)), i)
            elif m.group(3) and m.group(4):
                fixed_buffers[m.group(3)] = (int(m.group(4)), i)

        dm = RE_DELETE.search(line)
        if dm:
            deleted_vars.add(dm.group(2))

        if "HEAP_OVERFLOW" in enabled:
            for mcp in RE_MEMCPY.finditer(line):
                dst = mcp.group(1).strip()
                size_expr = mcp.group(3).strip()
                for name, (sz, decl_line) in fixed_buffers.items():
                    if name in dst:
                        findings.append({
                            "rule": "HEAP_OVERFLOW",
                            "line": i,
                            "message": f"Possible heap-based buffer overflow: memcpy into {name} (size {sz}) with size '{size_expr}' not checked.",
                            "snippet": _window(lines, i-1),
                        })
                        break

        if "INT_OVERFLOW" in enabled:
            am = RE_ALLOC_MUL.search(line)
            if am:
                left, a, b = am.group(1), am.group(2), am.group(3)
                if a in uint32_vars or b in uint32_vars or left in uint32_vars:
                    findings.append({
                        "rule": "INT_OVERFLOW",
                        "line": i,
                        "message": f"Potential integer overflow in allocation: '{line.strip()}'",
                        "snippet": _window(lines, i-1),
                    })

        if "UAF" in enabled and deleted_vars:
            for var in list(deleted_vars):
                if var in line and "delete" not in line:
                    findings.append({
                        "rule": "UAF",
                        "line": i,
                        "message": f"Possible use-after-free: variable '{var}' referenced after delete.",
                        "snippet": _window(lines, i-1),
                    })
                    break

        if "LOGIC_BUG" in enabled:
            if "total_freed" in line and "+=" in line:
                findings.append({
                    "rule": "LOGIC_BUG",
                    "line": i,
                    "message": "Stats bug: 'total_freed' increments count instead of freed bytes.",
                    "snippet": _window(lines, i-1),
                })

        generic_rules = [
            ("UNSAFE_FUNCS", RE_UNSAFE_FUNCS, "Use of unsafe function: '{line}'"),
            ("FORMAT_STRING", RE_FORMAT_STRING, "Potential format string vulnerability: '{line}'"),
            ("DANG_CALL", RE_DANGEROUS_CALLS, "Dangerous system call: '{line}'"),
            ("INSECURE_RANDOM", RE_INSECURE_RANDOM, "Insecure randomness: '{line}' not cryptographically safe."),
            ("HARDCODED_SECRET", RE_HARDCODED_SECRET, "Hardcoded secret detected: '{line}'"),
            ("FILE_INJECTION", RE_FOPEN, "Potential file injection/path traversal: '{line}'"),
            ("UNBOUNDED_LOOP", RE_LOOP, "Unbounded loop detected: '{line}' may cause DoS."),
            ("DANG_CAST", RE_CAST, "Dangerous cast detected: '{line}' may cause type confusion."),
            ("UNINIT_VAR", RE_UNINIT_VAR, "Variable declared but possibly uninitialized: '{line}'"),
            ("MEM_LEAK", RE_MEM_LEAK, "Memory allocated without free (possible leak): '{line}'"),
            ("DEPRECATED_FUNCS", RE_DEPRECATED_FUNCS, "Use of deprecated/unsafe function: '{line}'"),
            ("PTR_ARITH", RE_PTR_ARITH, "Pointer arithmetic detected: '{line}'"),
            ("HARDCODED_PATH", RE_HARDCODED_PATH, "Hardcoded file path detected: '{line}'"),
            ("FILE_PERMS", RE_FILE_PERMS, "Insecure file permissions in fopen: '{line}'"),
            ("DIV_ZERO", RE_DIV_ZERO, "Possible division by zero: '{line}'"),
            ("SIGNED_UNSIGNED", RE_SIGNED_UNSIGNED, "Signed/unsigned mismatch: '{line}'"),
            ("RECURSION", RE_RECURSION, "Possible infinite recursion: '{line}'"),
            ("GLOBAL_VAR", RE_GLOBAL_VAR, "Global/static variable may be unsafe: '{line}'"),
            ("NULL_DEREF", RE_NULL_DEREF, "Potential null pointer dereference: '{line}'"),
            ("BUF_UNDERFLOW", RE_BUF_UNDERFLOW, "Buffer underflow detected: '{line}'"),
            ("NO_CHECK", RE_NO_CHECK, "Missing error check: '{line}'"),
            ("UNUSED_VAR", RE_UNUSED_VAR, "Possibly unused variable: '{line}'"),
            ("STRNCPY_OVERFLOW", RE_STRNCPY_OVERFLOW, "Potential strncpy overflow: '{line}'"),
            ("STRCPY_NULL", RE_STRCPY_NULL, "Strcpy NULL destination detected: '{line}'"),
            ("DOUBLE_FREE", RE_DOUBLE_FREE, "Double free detected: '{line}'"),
            ("STACK_OVERFLOW", RE_STACK_OVERFLOW, "Potential stack overflow: '{line}'"),
            ("USE_BEFORE_INIT", RE_USE_BEFORE_INIT, "Use of variable before init: '{line}'"),
            ("PTR_SUBSCRIPT", RE_PTR_SUBSCRIPT, "Pointer subscript detected: '{line}'"),
            ("PRINTF_USER_INPUT", RE_PRINTF_USER_INPUT, "User input in printf: '{line}'"),
            ("SQL_INJECTION", RE_SQL_INJECTION, "Potential SQL injection: '{line}'"),
            ("SIGNED_OVERFLOW", RE_SIGNED_OVERFLOW, "Signed integer overflow possible: '{line}'"),
            ("SHIFT_OVERFLOW", RE_SHIFT_OVERFLOW, "Shift overflow possible: '{line}'"),
            ("RACE_CONDITION", RE_RACE_CONDITION, "Possible race condition detected: '{line}'"),
            ("UNLOCK_WITHOUT_LOCK", RE_UNLOCK_WITHOUT_LOCK, "Unlock without lock detected: '{line}'"),
            ("FD_LEAK", RE_FD_LEAK, "File descriptor/socket leak possible: '{line}'"),
            ("CLOSE_MISSING", RE_CLOSE_MISSING, "Resource opened without close: '{line}'"),
            ("HARD_CODED_CREDENTIALS", RE_HARD_CODED_CREDENTIALS, "Hardcoded credentials: '{line}'"),
            ("WEAK_CRYPTO", RE_WEAK_CRYPTO, "Weak crypto algorithm used: '{line}'"),
            ("EXCESSIVE_MACRO", RE_EXCESSIVE_MACRO, "Excessive macro definition: '{line}'"),
            ("SPRINTF_OVERFLOW", RE_SPRINTF_OVERFLOW, "Possible buffer overflow via sprintf: '{line}'"),
            ("ARRAY_OOB", RE_ARRAY_OOB, "Array index may go out of bounds: '{line}'"),
            ("DANGLING_PTR", RE_DANGLING_PTR, "Dangling pointer detected: '{line}'"),
            ("FORMAT_STRING_VAR", RE_FORMAT_STRING_VAR, "Format string with variable input: '{line}'"),
            ("MUTEX_NO_LOCK", RE_MUTEX_NO_LOCK, "Mutex used without proper lock: '{line}'"),
            ("FOPEN_NO_CLOSE", RE_FOPEN_NO_CLOSE, "File opened but not closed: '{line}'"),
            ("HARDCODED_URL", RE_HARDCODED_URL, "Hardcoded URL detected: '{line}'"),
            ("UNCHECKED_RETURN", RE_UNCHECKED_RETURN, "Return value not checked: '{line}'")
        ]

        for rule_name, regex, msg_template in generic_rules:
            if rule_name in enabled and regex.search(line):
                if rule_name == "FILE_INJECTION":
                    m = regex.search(line)
                    if m and '"' not in m.group(1):
                        findings.append({
                            "rule": rule_name,
                            "line": i,
                            "message": msg_template.format(line=line.strip()),
                            "snippet": _window(lines, i-1),
                        })
                else:
                    findings.append({
                        "rule": rule_name,
                        "line": i,
                        "message": msg_template.format(line=line.strip()),
                        "snippet": _window(lines, i-1),
                    })

    return findings
