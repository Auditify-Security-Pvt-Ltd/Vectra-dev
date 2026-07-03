"""
SAST Scanner — Static Application Security Testing engine.

Pipeline (sequential):
  1. Language detection    — marker files + extension heuristics
  2. Secret detection      — 15 regex patterns across all text files
  3. Dependency analysis   — 6 dependency file formats
  4. OWASP static analysis — language-specific patterns (JS/TS/Python/Java)
  5. CWE mapping           — auto-applied to all findings
  6. CVE correlation       — NVD lookup per vulnerable dependency
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

# ── Skip lists ────────────────────────────────────────────────────────

_SKIP_DIRS = frozenset({
    'node_modules', '.git', '__pycache__', 'dist', 'build',
    'target', 'vendor', '.gradle', '.idea', '.vscode',
    'venv', '.venv', 'env', 'coverage', '.nyc_output',
    'out', 'bin', '.terraform', '.next', '.nuxt', 'storybook-static',
})

_SKIP_EXTS = frozenset({
    '.pyc', '.class', '.jar', '.war', '.zip', '.tar', '.gz',
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.pdf',
    '.doc', '.docx', '.xls', '.xlsx', '.bin', '.exe', '.dll',
    '.so', '.o', '.woff', '.woff2', '.ttf', '.eot', '.mp4',
    '.mp3', '.webm', '.lock',
})

_SKIP_FILENAMES = frozenset({
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'poetry.lock', 'Gemfile.lock', 'Cargo.lock',
})

_MAX_FILE_BYTES = 5 * 1024 * 1024  # 5 MB

# ── CWE map ───────────────────────────────────────────────────────────

_CWE_MAP: Dict[str, Tuple[str, str, str]] = {
    'SQL Injection': (
        'CWE-89',
        'Improper Neutralization of Special Elements used in an SQL Command',
        'The software constructs all or part of an SQL command using externally-influenced '
        'input, but does not neutralize special elements that could modify the intended SQL command.',
    ),
    'Command Injection': (
        'CWE-78',
        'Improper Neutralization of Special Elements used in an OS Command',
        'The software constructs all or part of an OS command using externally-influenced '
        'input, but does not neutralize special elements that could modify the intended OS command.',
    ),
    'Path Traversal': (
        'CWE-22',
        'Improper Limitation of a Pathname to a Restricted Directory',
        'The software uses external input to construct a pathname intended to identify a file '
        'or directory, but does not properly neutralize path traversal sequences.',
    ),
    'XSS': (
        'CWE-79',
        'Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)',
        'The software does not neutralize user-controllable input before it is placed in '
        'output used as a web page served to other users.',
    ),
    'SSRF': (
        'CWE-918',
        'Server-Side Request Forgery (SSRF)',
        'The web server receives a URL from an upstream component and retrieves its contents, '
        'but does not sufficiently ensure the request targets the expected destination.',
    ),
    'Insecure Deserialization': (
        'CWE-502',
        'Deserialization of Untrusted Data',
        'The application deserializes untrusted data without sufficiently verifying '
        'that the resulting data will be valid.',
    ),
    'Insecure File Upload': (
        'CWE-434',
        'Unrestricted Upload of File with Dangerous Type',
        'The software allows the attacker to upload files of dangerous types that can be '
        'automatically processed within the product\'s environment.',
    ),
    'Weak Cryptography': (
        'CWE-327',
        'Use of a Broken or Risky Cryptographic Algorithm',
        'The use of a broken or risky cryptographic algorithm may result in the '
        'exposure of sensitive information.',
    ),
    'Code Injection': (
        'CWE-94',
        'Improper Control of Generation of Code (Code Injection)',
        'The software constructs code using externally-influenced input but does not '
        'neutralize special elements that could modify the intended code segment.',
    ),
    'Hardcoded Credentials': (
        'CWE-798',
        'Use of Hard-coded Credentials',
        'The software contains hard-coded credentials such as passwords or cryptographic keys '
        'used for authentication or encryption of internal data.',
    ),
    'Broken Authentication': (
        'CWE-287',
        'Improper Authentication',
        'When an actor claims to have a given identity, the software does not prove '
        'or insufficiently proves that the claim is correct.',
    ),
    'Security Misconfiguration': (
        'CWE-16',
        'Configuration',
        'Weaknesses in this category are introduced during the configuration of the software.',
    ),
    'Dependency Vulnerability': (
        'CWE-1395',
        'Dependency on Vulnerable Third-Party Component',
        'The product has a dependency on a third-party component that contains '
        'one or more known vulnerabilities.',
    ),
    # Secret subtypes (all CWE-798)
    'AWS Access Key':   ('CWE-798', 'Use of Hard-coded Credentials', 'An AWS Access Key ID was found hard-coded in source code.'),
    'AWS Secret Key':   ('CWE-798', 'Use of Hard-coded Credentials', 'An AWS Secret Access Key was found hard-coded in source code.'),
    'GCP API Key':      ('CWE-798', 'Use of Hard-coded Credentials', 'A Google Cloud Platform API Key was found hard-coded in source code.'),
    'GitHub Token':     ('CWE-798', 'Use of Hard-coded Credentials', 'A GitHub personal access or OAuth token was found hard-coded in source code.'),
    'JWT Token':        ('CWE-798', 'Use of Hard-coded Credentials', 'A JSON Web Token was found hard-coded in source code.'),
    'Private Key':      ('CWE-321', 'Use of Hard-coded Cryptographic Key', 'A private cryptographic key was found hard-coded in source code.'),
    'Bearer Token':     ('CWE-798', 'Use of Hard-coded Credentials', 'A Bearer token was found hard-coded in source code.'),
    'Database URL':     ('CWE-798', 'Use of Hard-coded Credentials', 'A database connection string with embedded credentials was found in source code.'),
    'Password':         ('CWE-798', 'Use of Hard-coded Credentials', 'A password was found hard-coded in source code.'),
    'API Key':          ('CWE-798', 'Use of Hard-coded Credentials', 'An API key was found hard-coded in source code.'),
    'Secret':           ('CWE-798', 'Use of Hard-coded Credentials', 'A secret or token was found hard-coded in source code.'),
    'SMTP Credentials': ('CWE-798', 'Use of Hard-coded Credentials', 'SMTP credentials were found hard-coded in source code.'),
    'Azure Key':        ('CWE-798', 'Use of Hard-coded Credentials', 'An Azure storage or service key was found hard-coded in source code.'),
    'Slack Token':      ('CWE-798', 'Use of Hard-coded Credentials', 'A Slack API token was found hard-coded in source code.'),
    'Stripe Key':       ('CWE-798', 'Use of Hard-coded Credentials', 'A Stripe payment API key was found hard-coded in source code.'),
}

# ── OWASP 2021 map ────────────────────────────────────────────────────

_OWASP_MAP: Dict[str, str] = {
    'SQL Injection':             'A03:2021 – Injection',
    'Command Injection':         'A03:2021 – Injection',
    'XSS':                       'A03:2021 – Injection',
    'Code Injection':            'A03:2021 – Injection',
    'Path Traversal':            'A01:2021 – Broken Access Control',
    'Insecure File Upload':      'A01:2021 – Broken Access Control',
    'SSRF':                      'A10:2021 – Server-Side Request Forgery',
    'Insecure Deserialization':  'A08:2021 – Software and Data Integrity Failures',
    'Weak Cryptography':         'A02:2021 – Cryptographic Failures',
    'Hardcoded Credentials':     'A07:2021 – Identification and Authentication Failures',
    'Broken Authentication':     'A07:2021 – Identification and Authentication Failures',
    'Security Misconfiguration': 'A05:2021 – Security Misconfiguration',
    'Dependency Vulnerability':  'A06:2021 – Vulnerable and Outdated Components',
}

_SECRET_TYPES = [
    'AWS Access Key', 'AWS Secret Key', 'GCP API Key', 'GitHub Token', 'JWT Token',
    'Private Key', 'Bearer Token', 'Database URL', 'Password', 'API Key', 'Secret',
    'SMTP Credentials', 'Azure Key', 'Slack Token', 'Stripe Key',
]
for _s in _SECRET_TYPES:
    _OWASP_MAP[_s] = 'A07:2021 – Identification and Authentication Failures'

# ── Secret patterns ───────────────────────────────────────────────────

_SECRET_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ('AWS Access Key',   re.compile(r'\bAKIA[0-9A-Z]{16}\b')),
    ('AWS Secret Key',   re.compile(r'(?i)aws.{0,20}(?:secret|access)[_-]?key\s*[=:]\s*[\'"]?([A-Za-z0-9/+=]{40})[\'"]?')),
    ('GCP API Key',      re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')),
    ('GitHub Token',     re.compile(r'\bgh[pousr]_[A-Za-z0-9_]{36,255}\b')),
    ('JWT Token',        re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b')),
    ('Private Key',      re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----')),
    ('Bearer Token',     re.compile(r'(?i)["\']?bearer["\']?\s*[:=]\s*[\'"]([A-Za-z0-9\-._~+/]{20,})[\'"]')),
    ('Database URL',     re.compile(r'(?i)(?:mysql|postgresql|postgres|mongodb|redis|mssql|sqlite)://[^/\s\'"]{3,}:[^@\s\'"]{3,}@')),
    ('Password',         re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*[\'"]([^\'"#\s]{6,})[\'"]')),
    ('API Key',          re.compile(r'(?i)api[_-]?key\s*[=:]\s*[\'"]([A-Za-z0-9\-_]{16,})[\'"]')),
    ('Secret',           re.compile(r'(?i)(?:secret_?key|client_?secret|app_?secret|webhook_?secret)\s*[=:]\s*[\'"]([A-Za-z0-9\-_+/=]{16,})[\'"]')),
    ('SMTP Credentials', re.compile(r'(?i)smtp.{0,30}(?:user(?:name)?|pass(?:word)?)\s*[=:]\s*[\'"]([^\'"]{4,})[\'"]')),
    ('Azure Key',        re.compile(r'(?i)(?:account_?key|azure.{0,10}(?:key|secret))\s*[=:]\s*[\'"]([A-Za-z0-9+/=]{20,})[\'"]')),
    ('Slack Token',      re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b')),
    ('Stripe Key',       re.compile(r'\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}\b')),
]

# ── OWASP analysis patterns ───────────────────────────────────────────

# Tuples of (vuln_type, severity, compiled_pattern, recommendation)
_JS_TS_PATTERNS: List[Tuple[str, str, re.Pattern, str]] = [
    (
        'SQL Injection', 'high',
        re.compile(r'(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:req\.|request\.|params\.|query\.|body\.|input|data|args|user)'),
        'Use parameterized queries or an ORM. Never concatenate user input into SQL strings.',
    ),
    (
        'SQL Injection', 'high',
        re.compile(r'(?i)\.(?:query|execute|raw)\s*\(\s*`[^`]*\$\{'),
        'Avoid template literals in SQL queries. Use parameterized placeholders (?, $1) instead.',
    ),
    (
        'XSS', 'high',
        re.compile(r'\.innerHTML\s*[+]?=\s*(?![\s\n]*[\'"`]?\s*<[a-z])'),
        'Sanitize user input before setting innerHTML. Use textContent or DOMPurify.',
    ),
    (
        'XSS', 'critical',
        re.compile(r'dangerouslySetInnerHTML\s*=\s*\{'),
        'Avoid dangerouslySetInnerHTML. If required, sanitize with DOMPurify before rendering.',
    ),
    (
        'XSS', 'medium',
        re.compile(r'document\.write\s*\('),
        'Avoid document.write() with user-controlled input. Use safe DOM APIs instead.',
    ),
    (
        'Code Injection', 'critical',
        re.compile(r'\beval\s*\('),
        'Avoid eval(). It executes arbitrary code and is a critical security risk.',
    ),
    (
        'Code Injection', 'high',
        re.compile(r'\bnew\s+Function\s*\('),
        'Avoid new Function() with user input. It is equivalent to eval().',
    ),
    (
        'Command Injection', 'critical',
        re.compile(r'(?i)(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:[^,)]*\+|`[^`]*\$\{)'),
        'Never pass user-controlled input to child_process methods. Use an argument array with spawn().',
    ),
    (
        'Path Traversal', 'high',
        re.compile(r'(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)'),
        'Validate file paths with path.resolve(). Verify the resolved path stays within an allowed base directory.',
    ),
    (
        'SSRF', 'high',
        re.compile(r'(?:fetch|axios(?:\.[a-z]+)?|request|got|http\.(?:get|post)|https\.(?:get|post))\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.)'),
        'Validate URLs before outbound requests. Use an allowlist of permitted domains and block internal IP ranges.',
    ),
    (
        'Security Misconfiguration', 'medium',
        re.compile(r'(?i)cors\s*\(\s*\{[^}]*origin\s*:\s*[\'"]?\*[\'"]?'),
        'Restrict CORS to specific origins instead of wildcard (*) in production.',
    ),
]

_PYTHON_PATTERNS: List[Tuple[str, str, re.Pattern, str]] = [
    (
        'Command Injection', 'critical',
        re.compile(r'\bos\.system\s*\('),
        'Avoid os.system(). Use subprocess.run() with a list argument and shell=False.',
    ),
    (
        'Command Injection', 'critical',
        re.compile(r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True'),
        'Avoid shell=True in subprocess calls with user input. Use shell=False and pass args as a list.',
    ),
    (
        'Code Injection', 'critical',
        re.compile(r'\beval\s*\('),
        'Avoid eval() with user-controlled input. It can execute arbitrary Python code.',
    ),
    (
        'Code Injection', 'critical',
        re.compile(r'\bexec\s*\((?!\s*[\'"](?:SELECT|INSERT|UPDATE|DELETE))'),
        'Avoid exec() with user-controlled input. It can execute arbitrary Python code.',
    ),
    (
        'Insecure Deserialization', 'critical',
        re.compile(r'\bpickle\.loads?\s*\('),
        'Never deserialize pickle data from untrusted sources. Use JSON or a safe serialization format.',
    ),
    (
        'Insecure Deserialization', 'high',
        re.compile(r'\byaml\.load\s*\([^,)]+\)(?!\s*#.*safe)'),
        'Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader) to prevent code execution.',
    ),
    (
        'SQL Injection', 'high',
        re.compile(r'(?i)cursor\.execute\s*\(\s*f[\'"]'),
        'Avoid f-strings in SQL queries. Use parameterized queries: cursor.execute("... WHERE id = %s", (id,)).',
    ),
    (
        'SQL Injection', 'high',
        re.compile(r'(?i)cursor\.execute\s*\(\s*[\'"].+[\'"\s]*%\s*(?:\(|request|params|input)'),
        'Use parameterized queries with %s placeholders, not % string formatting.',
    ),
    (
        'Path Traversal', 'high',
        re.compile(r'\bopen\s*\(\s*(?:request\.|req\.|params\.|os\.path\.join\s*\([^,)]*(?:request|req|params|input|args))'),
        'Validate file paths with os.path.realpath() and verify they stay within an allowed base directory.',
    ),
    (
        'Weak Cryptography', 'high',
        re.compile(r'\bhashlib\.(?:md5|sha1)\s*\('),
        'MD5 and SHA-1 are cryptographically broken. Use hashlib.sha256() or hashlib.sha3_256() instead.',
    ),
    (
        'Security Misconfiguration', 'medium',
        re.compile(r'(?m)^DEBUG\s*=\s*True'),
        'DEBUG=True must never be enabled in production. Set DEBUG=False before deployment.',
    ),
    (
        'Hardcoded Credentials', 'high',
        re.compile(r'(?i)SECRET_KEY\s*=\s*[\'"](?:django-insecure-|your-secret|change-me|example|test|dev|local)'),
        'Replace the default SECRET_KEY with a cryptographically random value. Store it in an environment variable.',
    ),
]

_JAVA_PATTERNS: List[Tuple[str, str, re.Pattern, str]] = [
    (
        'Command Injection', 'critical',
        re.compile(r'Runtime\.getRuntime\(\)\.exec\s*\('),
        'Avoid Runtime.exec() with user input. Use ProcessBuilder with a string array and validate all arguments.',
    ),
    (
        'SQL Injection', 'high',
        re.compile(r'(?:Statement|PreparedStatement)\s*\.\s*execute(?:Query|Update)?\s*\(\s*[\'"].*\+'),
        'Use PreparedStatement with parameterized queries (?) instead of string concatenation.',
    ),
    (
        'Path Traversal', 'high',
        re.compile(r'new\s+File\s*\(\s*(?:request\.getParameter|req\.getParameter)'),
        'Validate file paths from request parameters. Use Paths.get().normalize() and verify within allowed base directory.',
    ),
    (
        'Insecure Deserialization', 'critical',
        re.compile(r'new\s+ObjectInputStream\s*\('),
        'ObjectInputStream deserialization of untrusted data can lead to RCE. Use JSON/XML with schema validation.',
    ),
    (
        'Weak Cryptography', 'high',
        re.compile(r'MessageDigest\.getInstance\s*\(\s*[\'"](?:MD5|SHA-1|SHA1)[\'"]'),
        'MD5 and SHA-1 are cryptographically broken. Use SHA-256: MessageDigest.getInstance("SHA-256").',
    ),
    (
        'Weak Cryptography', 'high',
        re.compile(r'\b(?:DESKeySpec|DESedeKeySpec)\b'),
        'DES and 3DES are deprecated. Use AES-256 with GCM mode instead.',
    ),
    (
        'XSS', 'high',
        re.compile(r'(?:response\.getWriter|out)\s*\.(?:print|println|write)\s*\(\s*(?:request\.getParameter|req\.getParameter)'),
        'Never write unencoded user input directly to HTTP response. Apply HTML encoding before output.',
    ),
    (
        'Security Misconfiguration', 'medium',
        re.compile(r'setAllowedOrigins\s*\(\s*(?:Arrays\.asList\s*\(\s*)?[\'"]?\*[\'"]?\s*\)'),
        'Restrict CORS to specific origins. Avoid wildcard (*) in production.',
    ),
]

# ── Language extension map ────────────────────────────────────────────

_LANG_EXTS: Dict[str, str] = {
    '.ts': 'TypeScript', '.tsx': 'TypeScript',
    '.js': 'JavaScript', '.jsx': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript',
    '.py': 'Python',
    '.java': 'Java',
}

_LANG_PATTERNS: Dict[str, List] = {
    'TypeScript': _JS_TS_PATTERNS,
    'JavaScript': _JS_TS_PATTERNS,
    'Python':     _PYTHON_PATTERNS,
    'Java':       _JAVA_PATTERNS,
}

# ── Helpers ───────────────────────────────────────────────────────────

def _new_finding(
    scan_id: str,
    project_name: str,
    category: str,
    vuln_type: str,
    severity: str,
    title: str,
    description: str,
    file_path: str,
    line: int,
    code: str,
    recommendation: str,
    **extra: Any,
) -> dict:
    cwe = _CWE_MAP.get(vuln_type, ('CWE-0', 'Unknown', 'No description available.'))
    owasp = _OWASP_MAP.get(vuln_type, '')
    return {
        'findingId':       str(uuid.uuid4()),
        'scanId':          scan_id,
        'projectName':     project_name,
        'category':        category,
        'type':            vuln_type,
        'severity':        severity,
        'title':           title,
        'description':     description,
        'file':            file_path,
        'line':            line,
        'code':            code,
        'cweId':           cwe[0],
        'cweName':         cwe[1],
        'cweDescription':  cwe[2],
        'owaspCategory':   owasp,
        'recommendation':  recommendation,
        **extra,
    }


def _rel(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root)).replace('\\', '/')
    except ValueError:
        return str(path).replace('\\', '/')


def _read_safe(path: Path) -> Optional[str]:
    if path.stat().st_size > _MAX_FILE_BYTES:
        return None
    try:
        return path.read_text(encoding='utf-8', errors='replace')
    except Exception:
        return None


def _redact(line: str) -> str:
    return re.sub(
        r'([A-Za-z0-9+/=_\-]{4})[A-Za-z0-9+/=_\-]{6,}',
        r'\1***',
        line,
    )


def _is_skipped(path: Path) -> bool:
    parts = set(path.parts)
    if parts & _SKIP_DIRS:
        return True
    if path.name in _SKIP_FILENAMES:
        return True
    ext = path.suffix.lower()
    if ext in _SKIP_EXTS:
        return True
    # Skip minified JS
    name = path.name.lower()
    if name.endswith('.min.js') or name.endswith('.bundle.js') or name.endswith('.min.css'):
        return True
    return False


def _iter_source_files(root: Path, language: str) -> List[Path]:
    if language == 'TypeScript':
        target_exts = {'.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs'}
    elif language == 'JavaScript':
        target_exts = {'.js', '.jsx', '.mjs', '.cjs'}
    elif language == 'Python':
        target_exts = {'.py'}
    elif language == 'Java':
        target_exts = {'.java'}
    else:
        target_exts = set(_LANG_EXTS.keys())

    results: List[Path] = []
    for p in root.rglob('*'):
        if not p.is_file():
            continue
        if _is_skipped(p):
            continue
        if p.suffix.lower() in target_exts:
            results.append(p)
    return results


def _vuln_impact(vuln_type: str) -> str:
    impacts = {
        'SQL Injection':            'read, modify, or delete database records',
        'Command Injection':        'execute arbitrary OS commands on the server',
        'XSS':                      'inject malicious scripts into pages viewed by other users',
        'Code Injection':           'execute arbitrary code in the application context',
        'Path Traversal':           'read or write files outside the intended directory',
        'SSRF':                     'make the server perform requests to internal services',
        'Insecure Deserialization': 'achieve remote code execution via crafted payloads',
        'Weak Cryptography':        'break encryption and access protected data',
        'Security Misconfiguration':'exploit insecure default settings',
    }
    return impacts.get(vuln_type, 'exploit the application')


# ── 1. Language detection ─────────────────────────────────────────────

def detect_language(root: Path) -> str:
    """Detect primary programming language from marker files and extensions."""
    _MARKERS: Dict[str, str] = {
        'package.json':      'JavaScript',
        'requirements.txt':  'Python',
        'setup.py':          'Python',
        'Pipfile':           'Python',
        'pyproject.toml':    'Python',
        'pom.xml':           'Java',
        'build.gradle':      'Java',
        'build.gradle.kts':  'Java',
    }

    detected: set = set()
    for marker, lang in _MARKERS.items():
        if (root / marker).exists():
            detected.add(lang)

    # Check for TypeScript indicators inside a JavaScript project
    if 'JavaScript' in detected:
        ts_files = sum(
            1 for p in root.rglob('*.ts')
            if not _is_skipped(p)
        ) + sum(
            1 for p in root.rglob('*.tsx')
            if not _is_skipped(p)
        )
        if ts_files > 0 or (root / 'tsconfig.json').exists():
            detected.discard('JavaScript')
            detected.add('TypeScript')

    if len(detected) == 1:
        return next(iter(detected))

    if len(detected) > 1:
        # Most source files wins
        counts: Dict[str, int] = {}
        for lang in detected:
            exts = {ext for ext, l in _LANG_EXTS.items() if l == lang}
            c = sum(1 for p in root.rglob('*') if p.is_file() and p.suffix.lower() in exts and not _is_skipped(p))
            counts[lang] = c
        if counts:
            return max(counts, key=lambda k: counts[k])

    # Fallback: extension heuristics
    ext_counts: Dict[str, int] = {}
    for p in root.rglob('*'):
        if not p.is_file() or _is_skipped(p):
            continue
        lang = _LANG_EXTS.get(p.suffix.lower())
        if lang:
            ext_counts[lang] = ext_counts.get(lang, 0) + 1

    if ext_counts:
        best = max(ext_counts, key=lambda k: ext_counts[k])
        if best == 'JavaScript' and ext_counts.get('TypeScript', 0) > 0:
            return 'TypeScript'
        return best

    return 'Unknown'


# ── 2. Secret detection ───────────────────────────────────────────────

_TEXT_EXTS = frozenset({
    '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
    '.py', '.java', '.go', '.rb', '.php', '.rs',
    '.env', '.yml', '.yaml', '.toml', '.json', '.xml',
    '.conf', '.config', '.ini', '.properties',
    '.sh', '.bash', '.zsh', '.tf', '.hcl',
    '.html', '.htm', '.vue', '.svelte',
})

_MAX_SECRET_FINDINGS = 100


def scan_secrets(root: Path, scan_id: str, project_name: str) -> List[dict]:
    """Scan all text files for hardcoded secrets and credentials."""
    findings: List[dict] = []

    for p in root.rglob('*'):
        if not p.is_file() or _is_skipped(p):
            continue
        ext = p.suffix.lower()
        # Allow dotfiles like .env, .env.local
        is_env = p.name.startswith('.env') or p.name.endswith('.env')
        if ext not in _TEXT_EXTS and not is_env:
            continue
        if p.stat().st_size > _MAX_FILE_BYTES:
            continue

        try:
            text = p.read_text(encoding='utf-8', errors='replace')
        except Exception:
            continue

        rel = _rel(root, p)
        seen: set = set()

        for lineno, line in enumerate(text.splitlines(), start=1):
            for secret_type, pattern in _SECRET_PATTERNS:
                key = (lineno, secret_type)
                if key in seen:
                    continue
                if pattern.search(line):
                    seen.add(key)
                    findings.append(_new_finding(
                        scan_id=scan_id,
                        project_name=project_name,
                        category='secret',
                        vuln_type=secret_type,
                        severity='critical',
                        title=f'Hardcoded {secret_type} Detected',
                        description=(
                            f'A {secret_type} was found hard-coded in {rel} at line {lineno}. '
                            'Hard-coded credentials can be extracted from source code repositories '
                            'and used to compromise systems or access sensitive data.'
                        ),
                        file_path=rel,
                        line=lineno,
                        code=_redact(line.strip()[:300]),
                        recommendation=(
                            f'Remove the {secret_type} from source code immediately. '
                            'Store secrets in environment variables or a secrets manager '
                            '(AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). '
                            'Revoke and rotate the exposed credential.'
                        ),
                    ))
                    if len(findings) >= _MAX_SECRET_FINDINGS:
                        return findings
    return findings


# ── 3. Dependency analysis ────────────────────────────────────────────

def collect_dependencies(root: Path) -> List[Dict[str, str]]:
    """Parse dependency files and return {name, version, file} dicts."""
    deps: List[Dict[str, str]] = []

    # package.json
    pkg_json = root / 'package.json'
    if pkg_json.exists():
        try:
            data = json.loads(pkg_json.read_text(encoding='utf-8'))
            for section in ('dependencies', 'devDependencies', 'peerDependencies'):
                for name, ver in (data.get(section) or {}).items():
                    ver_clean = re.sub(r'^[^0-9]*', '', ver).split(' ')[0].split(',')[0]
                    if ver_clean:
                        deps.append({'name': name, 'version': ver_clean, 'file': 'package.json'})
        except Exception as e:
            logger.debug(f'[SAST] package.json parse error: {e}')

    # requirements.txt
    req_txt = root / 'requirements.txt'
    if req_txt.exists():
        try:
            for line in req_txt.read_text(encoding='utf-8').splitlines():
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                m = re.match(r'^([A-Za-z0-9\-_.]+)(?:\[.*?\])?(?:[=<>!~]+([A-Za-z0-9._]+))?', line)
                if m:
                    deps.append({
                        'name': m.group(1),
                        'version': m.group(2) or '',
                        'file': 'requirements.txt',
                    })
        except Exception as e:
            logger.debug(f'[SAST] requirements.txt parse error: {e}')

    # pom.xml (Maven)
    pom = root / 'pom.xml'
    if pom.exists():
        try:
            text = pom.read_text(encoding='utf-8')
            deps_block = re.search(r'<dependencies>(.*?)</dependencies>', text, re.DOTALL)
            if deps_block:
                for dep in re.finditer(r'<dependency>(.*?)</dependency>', deps_block.group(1), re.DOTALL):
                    g = re.search(r'<groupId>([^<]+)</groupId>', dep.group(1))
                    a = re.search(r'<artifactId>([^<]+)</artifactId>', dep.group(1))
                    v = re.search(r'<version>([^<$]+)</version>', dep.group(1))
                    if a:
                        name = f'{g.group(1).strip()}:{a.group(1).strip()}' if g else a.group(1).strip()
                        deps.append({
                            'name': name,
                            'version': v.group(1).strip() if v else '',
                            'file': 'pom.xml',
                        })
        except Exception as e:
            logger.debug(f'[SAST] pom.xml parse error: {e}')

    # build.gradle / build.gradle.kts
    for gradle_name in ('build.gradle', 'build.gradle.kts'):
        gradle = root / gradle_name
        if not gradle.exists():
            found = next(root.rglob(gradle_name), None)
            if found:
                gradle = found
        if gradle.exists():
            try:
                text = gradle.read_text(encoding='utf-8')
                for m in re.finditer(
                    r'(?:implementation|compile|testImplementation|api|runtimeOnly|testRuntimeOnly)\s*[\("]([^:]+):([^:]+):([^\'")\s]+)',
                    text,
                ):
                    deps.append({
                        'name': f'{m.group(1)}:{m.group(2)}',
                        'version': m.group(3),
                        'file': gradle.name,
                    })
            except Exception as e:
                logger.debug(f'[SAST] build.gradle parse error: {e}')

    # composer.json (PHP)
    composer = root / 'composer.json'
    if composer.exists():
        try:
            data = json.loads(composer.read_text(encoding='utf-8'))
            for section in ('require', 'require-dev'):
                for name, ver in (data.get(section) or {}).items():
                    if name in ('php', 'ext-json', 'ext-mbstring'):
                        continue
                    ver_clean = re.sub(r'^[^0-9]*', '', ver).split(' ')[0]
                    deps.append({'name': name, 'version': ver_clean, 'file': 'composer.json'})
        except Exception as e:
            logger.debug(f'[SAST] composer.json parse error: {e}')

    # *.csproj (C#/.NET)
    for csproj in root.rglob('*.csproj'):
        try:
            text = csproj.read_text(encoding='utf-8')
            for m in re.finditer(
                r'<PackageReference\s+Include=[\'"]([^\'"]+)[\'"]\s+Version=[\'"]([^\'"]+)[\'"]',
                text,
            ):
                deps.append({'name': m.group(1), 'version': m.group(2), 'file': csproj.name})
        except Exception as e:
            logger.debug(f'[SAST] csproj parse error: {e}')

    # Deduplicate by name (keep first occurrence)
    seen: set = set()
    unique: List[Dict[str, str]] = []
    for d in deps:
        if d['name'] not in seen:
            seen.add(d['name'])
            unique.append(d)
    return unique


# ── 4. OWASP static analysis ──────────────────────────────────────────

_MAX_OWASP_FINDINGS = 150


def analyze_owasp(root: Path, language: str, scan_id: str, project_name: str) -> List[dict]:
    """Run OWASP pattern matching on source files for the detected language."""
    if language == 'Unknown':
        return []

    patterns = _LANG_PATTERNS.get(language, [])
    if not patterns:
        return []

    src_files = _iter_source_files(root, language)
    findings: List[dict] = []

    for file_path in src_files:
        content = _read_safe(file_path)
        if content is None:
            continue

        rel = _rel(root, file_path)
        seen: set = set()

        for lineno, line in enumerate(content.splitlines(), start=1):
            for vuln_type, severity, pattern, recommendation in patterns:
                key = (lineno, vuln_type)
                if key in seen:
                    continue
                if pattern.search(line):
                    seen.add(key)
                    findings.append(_new_finding(
                        scan_id=scan_id,
                        project_name=project_name,
                        category='owasp',
                        vuln_type=vuln_type,
                        severity=severity,
                        title=f'{vuln_type} — {Path(rel).name}',
                        description=(
                            f'{vuln_type} vulnerability pattern detected in {rel} at line {lineno}. '
                            f'This may allow an attacker to {_vuln_impact(vuln_type)}.'
                        ),
                        file_path=rel,
                        line=lineno,
                        code=line.strip()[:300],
                        recommendation=recommendation,
                    ))
                    if len(findings) >= _MAX_OWASP_FINDINGS:
                        return findings

    return findings


# ── 5. CVE correlation ────────────────────────────────────────────────

_MAX_CVES_PER_DEP = 3


async def correlate_dependency_cves(
    deps: List[Dict[str, str]],
    scan_id: str,
    project_name: str,
) -> List[dict]:
    """Look up CVEs for each dependency via NVD and return findings."""
    from intelligence.nvd_client import get_cves_for_technology

    findings: List[dict] = []

    for dep in deps:
        name = dep['name']
        version = dep.get('version', '')
        if not version or version.startswith('*'):
            continue
        try:
            cves = await get_cves_for_technology(name, version)
        except Exception as exc:
            logger.debug(f'[SAST] CVE lookup failed for {name}@{version}: {exc}')
            cves = []

        for cve in cves[:_MAX_CVES_PER_DEP]:
            cvss = float(cve.get('cvss', 0) or 0)
            severity = _cvss_to_severity(cvss)
            cve_id = cve.get('id', 'CVE-UNKNOWN')
            desc = cve.get('description', 'No description available.')
            findings.append(_new_finding(
                scan_id=scan_id,
                project_name=project_name,
                category='dependency',
                vuln_type='Dependency Vulnerability',
                severity=severity,
                title=f'{cve_id} in {name}@{version}',
                description=(
                    f'{name} version {version} is affected by {cve_id} (CVSS {cvss:.1f}). '
                    f'{desc}'
                ),
                file_path=dep.get('file', 'dependency'),
                line=0,
                code=f'{name}@{version}',
                recommendation=(
                    f'Upgrade {name} to a patched version. '
                    'Review the package changelog and security advisories for the minimum safe version.'
                ),
                dependencyName=name,
                dependencyVersion=version,
                cveId=cve_id,
                cvssScore=cvss,
            ))

    return findings


def _cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return 'critical'
    if cvss >= 7.0:
        return 'high'
    if cvss >= 4.0:
        return 'medium'
    if cvss > 0:
        return 'low'
    return 'info'
