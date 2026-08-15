#!/usr/bin/env python3
"""
commit-guard: local, offline, rule-based security scanner for git repos.
No network calls — everything is local regex/heuristics.

Modes:
  python3 scan.py            -> incremental scan of the LAST commit's diff
                                 (used automatically by the post-commit hook)
  python3 scan.py --full     -> deep scan of the ENTIRE working tree:
                                 source code, .env files, Dockerfiles,
                                 docker-compose files, dependency manifests,
                                 CI workflow files, and git-tracked secrets.
"""

import subprocess
import re
import sys
import os
import json
from datetime import datetime

# =========================================================================
# 1. LINE-LEVEL RISK PATTERNS  (name, regex, severity, fix suggestion)
# =========================================================================
PATTERNS = [
    ("Hardcoded API key / secret",
     r'(?i)(api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*[\'"][A-Za-z0-9_\-]{10,}[\'"]',
     "HIGH",
     "Move the value to an environment variable or a secrets manager (e.g. os.environ / .env + python-dotenv), never hardcode it in source."),

    ("AWS Access Key",
     r'\bAKIA[0-9A-Z]{16}\b',
     "HIGH",
     "Revoke this key immediately in the AWS console (it's likely compromised once committed), then use IAM roles or environment-based credentials instead."),

    ("Private key block",
     r'-----BEGIN (RSA|EC|OPENSSH|PGP|DSA) PRIVATE KEY-----',
     "HIGH",
     "Remove the key from the repo and rotate it — a committed private key must be treated as fully compromised. Store keys outside version control."),

    ("eval() usage",
     r'(?<![.\w])eval\s*\(',
     "HIGH",
     "Avoid eval() on any input that could be influenced by a user. Use ast.literal_eval() for data, or a proper parser/dispatch table for logic."),

    ("exec() usage",
     r'(?<![.\w])exec\s*\(',
     "HIGH",
     "Avoid exec() on dynamic/user-influenced strings. Refactor to explicit function calls or a safe dispatch dictionary."),

    ("os.system usage",
     r'os\.system\s*\(',
     "MEDIUM",
     "Use subprocess.run([...], shell=False) with a list of arguments instead of os.system(), to avoid shell injection."),

    ("subprocess shell=True",
     r'subprocess\.\w+\([^)]*shell\s*=\s*True',
     "MEDIUM",
     "Pass command arguments as a list with shell=False instead of a shell string, to prevent shell/command injection."),

    ("pickle.loads (unsafe deserialization)",
     r'pickle\.loads?\s*\(',
     "MEDIUM",
     "Never unpickle data from an untrusted source. Use JSON or another safe serialization format for anything crossing a trust boundary."),

    ("yaml.load without SafeLoader",
     r'yaml\.load\s*\((?!.*SafeLoader)',
     "MEDIUM",
     "Use yaml.safe_load() instead of yaml.load(), or explicitly pass Loader=yaml.SafeLoader."),

    ("SQL string concatenation",
     r'(?i)(SELECT|INSERT|UPDATE|DELETE)\s+.{0,80}[\'"]\s*\+\s*\w+',
     "MEDIUM",
     "Use parameterized queries / prepared statements (e.g. cursor.execute(query, params)) instead of string concatenation, to prevent SQL injection."),

    ("Debug flag left on",
     r'(?i)^\s*debug\s*=\s*true\s*$',
     "LOW",
     "Ensure DEBUG is False in any production/staging configuration — verbose debug output can leak stack traces and secrets."),

    ("TODO/FIXME security note",
     r'(?i)#\s*(TODO|FIXME).*(security|vuln|unsafe|insecure)',
     "LOW",
     "Resolve the flagged issue before merging, or open a tracked ticket so it isn't forgotten."),
]

# =========================================================================
# 2. FALSE-POSITIVE SUPPRESSION
# =========================================================================
PLACEHOLDER_HINTS = [
    "changeme", "change_me", "your_key", "your-key", "yourkey",
    "example", "dummy", "placeholder", "xxxxxxxx", "<your", "insert_",
    "test_key", "test_secret", "fake_", "sample_", "redacted", "***",
    "getenv", "environ", "os.env", "process.env", "config.get",
    "input(", "prompt(",
]

# Files excluded from the generic line-pattern scan (still may be covered
# by dedicated structural checks below, e.g. .env / Dockerfile / deps).
EXCLUDED_FILE_PATTERNS = [
    r'\.commit-guard/scan\.py$',
    r'(^|/)tests?/',
    r'(^|/)test_.*\.py$',
    r'.*_test\.py$',
    r'(^|/)\.env\.example$',
    r'(^|/)(mock|fixture)s?/',
    r'\.md$', r'\.rst$',
    r'\.lock$', r'package-lock\.json$',
]

# Directories never worth walking during a full-repo scan.
IGNORED_DIRS = {
    '.git', '.commit-guard', 'node_modules', 'venv', '.venv', 'env',
    '__pycache__', 'dist', 'build', '.next', 'target', 'vendor',
    '.mypy_cache', '.pytest_cache', 'site-packages', '.tox', '.idea', '.vscode',
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # skip files bigger than 2MB (binaries, dumps, etc.)

def is_excluded_file(filename):
    if not filename:
        return False
    return any(re.search(p, filename, re.IGNORECASE) for p in EXCLUDED_FILE_PATTERNS)

def looks_like_placeholder(content):
    lowered = content.lower()
    # Match placeholder hints as separate tokens (not as substrings inside
    # longer alphanumeric strings). This avoids flagging values like
    # 'AKIAEXAMPLEKEY...' where 'example' appears inside a real key.
    for hint in PLACEHOLDER_HINTS:
        h = hint.lower()
        # require non-alphanumeric boundary around the hint
        pattern = r'(?<![a-z0-9_])' + re.escape(h) + r'(?![a-z0-9_])'
        if re.search(pattern, lowered):
            return True
    return False

def is_probably_binary(path):
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
        return b'\x00' in chunk
    except OSError:
        return True

def read_text(path):
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except OSError:
        return None

def run(cmd, cwd=None):
    return subprocess.run(cmd, capture_output=True, text=True, shell=False, cwd=cwd).stdout

def make_finding(file, line, issue, severity, snippet, fix):
    return {"file": file, "line": line, "issue": issue, "severity": severity,
            "snippet": snippet.strip()[:120], "fix": fix}

# =========================================================================
# 3. STRUCTURAL / FILE-SPECIFIC CHECKS
#    (.env, Dockerfile, docker-compose, dependency manifests, CI workflows)
# =========================================================================

def check_env_file(relpath, content, tracked_files):
    findings = []
    lines = content.splitlines()
    if relpath in tracked_files:
        findings.append(make_finding(
            relpath, 0, "'.env' file is committed to git history", "HIGH", relpath,
            "Remove it from tracking: git rm --cached " + relpath +
            " — then add it to .gitignore and rotate every secret it contained. "
            "Note the file still exists in old commits; use git filter-repo or BFG to purge history if it held real secrets."))
    else:
        findings.append(make_finding(
            relpath, 0, "'.env' file present in working directory", "LOW", relpath,
            "Confirm it's listed in .gitignore so it never gets committed by accident."))

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith('#') or '=' not in stripped:
            continue
        key, _, value = stripped.partition('=')
        key = key.strip()
        value = value.strip().strip('"\'')
        if not value or looks_like_placeholder(line):
            continue
        if re.search(r'(?i)(key|secret|token|password|pwd|credential)', key) and len(value) >= 6:
            findings.append(make_finding(
                relpath, i, f"Possible live secret in .env: '{key}'", "MEDIUM", line,
                "Ensure this file is gitignored. If it was ever committed, rotate this credential immediately."))
    return findings


def check_dockerfile(relpath, content):
    findings = []
    lines = content.splitlines()
    has_user = bool(re.search(r'(?im)^\s*USER\s+\S+', content))

    for i, line in enumerate(lines, 1):
        if re.match(r'^\s*FROM\s+\S+:latest\b', line, re.I):
            findings.append(make_finding(relpath, i, "Base image pinned to ':latest' tag", "MEDIUM", line,
                "Pin to a specific version tag (e.g. python:3.12.4-slim) for reproducible, auditable builds."))
        if re.search(r'(curl|wget)[^\n]*\|\s*(bash|sh)\b', line, re.I):
            findings.append(make_finding(relpath, i, "Piping a remote script directly into a shell", "HIGH", line,
                "Download the script, verify its checksum/signature, then run it — never pipe untrusted remote content straight into a shell."))
        if re.match(r'^\s*ADD\s+https?://', line, re.I):
            findings.append(make_finding(relpath, i, "ADD used to fetch a remote URL", "MEDIUM", line,
                "Prefer COPY for local files, or curl + explicit checksum verification for remote artifacts — ADD with a URL skips integrity checks."))
        if re.search(r'(?i)^\s*(ENV|ARG)\s+\w*(SECRET|PASSWORD|TOKEN|API_?KEY)\w*\s*=', line):
            findings.append(make_finding(relpath, i, "Secret baked into image via ENV/ARG", "HIGH", line,
                "Inject secrets at runtime (--env-file, orchestrator secrets) or use BuildKit --mount=type=secret; never bake them into image layers."))

    if not has_user:
        findings.append(make_finding(relpath, 0, "No USER directive — container runs as root by default", "MEDIUM", "(whole file)",
            "Add 'USER <non-root-user>' near the end of the Dockerfile to drop root privileges at runtime."))
    return findings


def check_compose(relpath, content):
    findings = []
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(r'(?i)privileged:\s*true', line):
            findings.append(make_finding(relpath, i, "Container runs in privileged mode", "HIGH", line,
                "Remove 'privileged: true'; grant only the specific Linux capabilities needed via 'cap_add' instead."))
        if '/var/run/docker.sock' in line:
            findings.append(make_finding(relpath, i, "Docker socket mounted into container", "HIGH", line,
                "Mounting docker.sock grants root-equivalent host access. Avoid it, or front it with a scoped docker-socket-proxy."))
        if re.search(r'(?i)network_mode:\s*[\'"]?host', line):
            findings.append(make_finding(relpath, i, "Container uses host networking", "MEDIUM", line,
                "Host networking bypasses container network isolation — use a defined bridge network and explicit port mappings instead."))
    return findings


def check_dependency_file(relpath, content):
    findings = []
    basename = os.path.basename(relpath)

    if basename in ('requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt'):
        for i, line in enumerate(content.splitlines(), 1):
            l = line.strip()
            if not l or l.startswith('#') or l.startswith('-'):
                continue
            if l.startswith('http://'):
                findings.append(make_finding(relpath, i, "Dependency fetched over plain HTTP", "MEDIUM", l,
                    "Use an https:// index/package URL to prevent man-in-the-middle tampering during install."))
            elif not re.search(r'(==|>=|<=|~=|!=)', l):
                findings.append(make_finding(relpath, i, "Dependency has no pinned version", "LOW", l,
                    "Pin an exact version (package==x.y.z) so installs are reproducible and a compromised future release can't slip in silently."))

    elif basename == 'package.json':
        try:
            data = json.loads(content)
            for dep_type in ('dependencies', 'devDependencies'):
                for name, ver in data.get(dep_type, {}).items():
                    v = str(ver).strip()
                    if v in ('*', 'latest') or v.startswith('>') and '=' not in v:
                        findings.append(make_finding(relpath, 0, f"'{name}' uses floating version '{v}'", "MEDIUM", f'"{name}": "{v}"',
                            "Pin to an exact or caret-range version and commit package-lock.json so installs are reproducible and auditable."))
        except (json.JSONDecodeError, AttributeError):
            pass

    elif basename == 'Pipfile':
        for i, line in enumerate(content.splitlines(), 1):
            if re.match(r'^\s*\w[\w\-]*\s*=\s*"\*"', line):
                findings.append(make_finding(relpath, i, "Dependency pinned to '*' (any version)", "LOW", line,
                    "Pin an exact version in Pipfile to avoid unpredictable upgrades."))
    return findings


def check_github_workflow(relpath, content):
    findings = []
    lines = content.splitlines()
    if re.search(r'(?im)^\s*on:\s*.*pull_request_target', content) or 'pull_request_target' in content:
        findings.append(make_finding(relpath, 0, "Workflow triggers on 'pull_request_target'", "HIGH", "(whole file)",
            "pull_request_target runs with access to repo secrets even for forked PRs. Avoid checking out and executing the PR's own code under this trigger, or switch to 'pull_request'."))
    for i, line in enumerate(lines, 1):
        if re.search(r'\$\{\{\s*github\.event\.(issue|pull_request)\.(title|body)', line):
            findings.append(make_finding(relpath, i, "Untrusted PR/issue text interpolated directly into workflow", "HIGH", line,
                "Pass the value through an env: variable instead of inline ${{ }} interpolation in a run: step, to prevent script injection."))
    return findings


# --- language detection, used to tailor .gitignore recommendations ---

LANG_MARKER_FILES = {
    "Python":          ["requirements.txt", "requirements-dev.txt", "Pipfile", "pyproject.toml", "setup.py", "manage.py"],
    "Node/JavaScript": ["package.json"],
    "Go":              ["go.mod"],
    "Rust":            ["Cargo.toml"],
    "Java":            ["pom.xml", "build.gradle", "build.gradle.kts"],
    "PHP":             ["composer.json"],
    "Ruby":            ["Gemfile"],
}

EXT_LANG_FALLBACK = {
    ".py": "Python",
    ".js": "Node/JavaScript", ".jsx": "Node/JavaScript", ".ts": "Node/JavaScript", ".tsx": "Node/JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".php": "PHP",
    ".rb": "Ruby",
}

# Language-specific entries a .gitignore should have. .env / key files are
# handled once, generically, in UNIVERSAL_GITIGNORE_RULES below instead of
# being repeated per language.
LANGUAGE_GITIGNORE_RULES = {
    "Python": [
        ("__pycache__", "MEDIUM", "Add '__pycache__/' to .gitignore — compiled bytecode caches shouldn't be tracked."),
        ("pyc",         "LOW",    "Add '*.pyc' to .gitignore — compiled Python files shouldn't be tracked."),
        ("venv",        "MEDIUM", "Add 'venv/' and '.venv/' to .gitignore — virtual environments are large and machine-specific, don't commit them."),
        ("egg-info",    "LOW",    "Add '*.egg-info/' to .gitignore — build metadata shouldn't be tracked."),
    ],
    "Node/JavaScript": [
        ("node_modules", "MEDIUM", "Add 'node_modules/' to .gitignore — install dependencies via npm/yarn instead of committing them."),
        ("dist",         "LOW",    "Add 'dist/' (or your actual build output folder) to .gitignore — build artifacts shouldn't be tracked."),
        ("npm-debug",    "LOW",    "Add 'npm-debug.log*' to .gitignore — npm's own debug logs shouldn't be tracked."),
    ],
    "Go": [
        ("vendor", "LOW", "Consider adding 'vendor/' to .gitignore if you're not intentionally vendoring dependencies."),
    ],
    "Rust": [
        ("target", "MEDIUM", "Add '/target' to .gitignore — Cargo build artifacts shouldn't be tracked."),
    ],
    "Java": [
        ("class",  "LOW", "Add '*.class' to .gitignore — compiled bytecode shouldn't be tracked."),
        ("target", "LOW", "Add 'target/' (Maven) or 'build/' (Gradle) to .gitignore — build output shouldn't be tracked."),
    ],
    "PHP": [
        ("vendor", "MEDIUM", "Add 'vendor/' to .gitignore — Composer dependencies should be installed, not committed."),
    ],
    "Ruby": [
        ("vendor/bundle", "LOW", "Add 'vendor/bundle' to .gitignore if using Bundler's local install path."),
    ],
}

# Checked regardless of detected language.
UNIVERSAL_GITIGNORE_RULES = [
    (".env", "HIGH",   "Add '.env' (and ideally '.env.*' with a negated '!.env.example') to .gitignore to stop environment secrets from being committed."),
    ("pem",  "MEDIUM", "Add '*.pem' to .gitignore to avoid accidentally committing certificate/key files."),
    ("key",  "MEDIUM", "Add '*.key' to .gitignore to avoid accidentally committing private key files."),
]

def detect_languages(basenames_seen, ext_seen):
    detected = set()
    for lang, markers in LANG_MARKER_FILES.items():
        if any(m in basenames_seen for m in markers):
            detected.add(lang)
    for ext, lang in EXT_LANG_FALLBACK.items():
        if ext in ext_seen:
            detected.add(lang)
    return detected

def check_gitignore(repo_root, detected_languages):
    findings = []
    gitignore_path = os.path.join(repo_root, '.gitignore')

    if not os.path.isfile(gitignore_path):
        lang_note = f" tailored for {', '.join(sorted(detected_languages))}" if detected_languages else ""
        findings.append(make_finding(".gitignore", 0, "No .gitignore file found in repo", "MEDIUM", "(missing file)",
            f"Create a .gitignore{lang_note} — without one it's easy to accidentally commit secrets, virtual environments, or build artifacts."))
        return findings

    content = read_text(gitignore_path) or ""
    joined_lower = "\n".join(
        l.strip().lower() for l in content.splitlines() if l.strip() and not l.strip().startswith('#')
    )

    def covered(token):
        return token.lower() in joined_lower

    seen_fixes = set()
    for lang in detected_languages:
        for token, sev, fix in LANGUAGE_GITIGNORE_RULES.get(lang, []):
            if not covered(token) and fix not in seen_fixes:
                findings.append(make_finding(".gitignore", 0, f"Missing recommended {lang} entry: '{token}'", sev,
                    "(not found in .gitignore)", fix))
                seen_fixes.add(fix)

    for token, sev, fix in UNIVERSAL_GITIGNORE_RULES:
        if not covered(token) and fix not in seen_fixes:
            findings.append(make_finding(".gitignore", 0, f"Missing recommended entry: '{token}'", sev,
                "(not found in .gitignore)", fix))
            seen_fixes.add(fix)

    return findings


# =========================================================================
# 4. FULL-REPO SCAN
# =========================================================================

def get_tracked_files(repo_root):
    out = run(["git", "ls-files"], cwd=repo_root)
    return set(out.splitlines())

def scan_full_repo(repo_root):
    findings = []
    tracked_files = get_tracked_files(repo_root)
    basenames_seen = set()
    ext_seen = set()

    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]

        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            relpath = os.path.relpath(fpath, repo_root)

            basenames_seen.add(fname)
            ext_seen.add(os.path.splitext(fname)[1].lower())

            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            if is_probably_binary(fpath):
                continue

            content = read_text(fpath)
            if content is None:
                continue

            base = fname
            # --- dedicated structural checks ---
            if base == '.env' or (base.startswith('.env.') and 'example' not in base and 'sample' not in base):
                findings.extend(check_env_file(relpath, content, tracked_files))
                continue  # don't also run generic line patterns on raw secret values
            if base in ('Dockerfile',) or base.startswith('Dockerfile.'):
                findings.extend(check_dockerfile(relpath, content))
            if re.match(r'docker-compose.*\.ya?ml$', base, re.I):
                findings.extend(check_compose(relpath, content))
            if base in ('requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt', 'package.json', 'Pipfile'):
                findings.extend(check_dependency_file(relpath, content))
            if relpath.replace('\\', '/').startswith('.github/workflows/') and base.endswith(('.yml', '.yaml')):
                findings.extend(check_github_workflow(relpath, content))

            # --- generic line-pattern scan ---
            if is_excluded_file(relpath):
                continue
            for i, line in enumerate(content.splitlines(), 1):
                if looks_like_placeholder(line):
                    continue
                for name, pattern, sev, fix in PATTERNS:
                    if re.search(pattern, line):
                        findings.append(make_finding(relpath, i, name, sev, line, fix))

    detected_languages = detect_languages(basenames_seen, ext_seen)
    findings.extend(check_gitignore(repo_root, detected_languages))

    return findings, detected_languages

# =========================================================================
# 5. INCREMENTAL (POST-COMMIT) SCAN — fast, last commit only
# =========================================================================

def get_last_commit_diff():
    return run(["git", "diff", "HEAD~1", "HEAD"])

def get_last_commit_summary():
    return run(["git", "log", "-1", "--stat", "--pretty=format:%h | %an | %s"])

def scan_diff(diff_text):
    findings = []
    seen = set()
    current_file = None
    line_no = 0

    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            current_file = line[6:]
            line_no = 0
            # For incremental scans, also inspect the current file content
            # for any patterns (covers secrets that existed before the commit
            # but the file was touched in this commit). Avoid scanning the
            # scanner itself and excluded files.
            if current_file and current_file != ".commit-guard/scan.py" and not is_excluded_file(current_file):
                content = read_text(current_file)
                if content:
                    for i, l in enumerate(content.splitlines(), 1):
                        if looks_like_placeholder(l):
                            continue
                        for name, pattern, sev, fix in PATTERNS:
                            if re.search(pattern, l):
                                key = (current_file, i, name)
                                if key not in seen:
                                    findings.append(make_finding(current_file, i, name, sev, l, fix))
                                    seen.add(key)
            continue
        if current_file == ".commit-guard/scan.py":
            continue
        if line.startswith("@@"):
            m = re.search(r'\+(\d+)', line)
            if m:
                line_no = int(m.group(1)) - 1
            continue
        if line.startswith("+") and not line.startswith("+++"):
            line_no += 1
            content = line[1:]
            if looks_like_placeholder(content) or is_excluded_file(current_file):
                continue
            for name, pattern, sev, fix in PATTERNS:
                if re.search(pattern, content):
                    key = (current_file, line_no, name)
                    if key not in seen:
                        findings.append(make_finding(current_file, line_no, name, sev, content, fix))
                        seen.add(key)
        elif not line.startswith("-"):
            line_no += 1

    return findings

# =========================================================================
# 6. REPORTING
# =========================================================================

def print_report(title, subtitle, findings):
    print("=" * 64)
    print(f"commit-guard — {title} — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print("=" * 64)
    if subtitle:
        print(f"\n{subtitle}")

    if not findings:
        print("\n✅ No security issues flagged.")
        print("=" * 64)
        return

    sev_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (sev_order[f["severity"]], f["file"] or ""))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] += 1

    print(f"\n[Findings] {len(findings)} total  "
          f"(🔴 {counts['HIGH']} HIGH · 🟠 {counts['MEDIUM']} MEDIUM · 🟡 {counts['LOW']} LOW)\n")

    for f in findings:
        icon = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}[f["severity"]]
        print(f"{icon} [{f['severity']}] {f['issue']}")
        print(f"   File: {f['file']}:{f['line']}")
        print(f"   Code: {f['snippet']}")
        print(f"   Fix:  {f['fix']}")
        print()

    if counts["HIGH"]:
        print(f"⚠️  {counts['HIGH']} HIGH severity issue(s) — review before pushing/deploying.")
    print("=" * 64)

# =========================================================================
# 7. ENTRY POINT
# =========================================================================

def main():
    full_mode = "--full" in sys.argv

    if full_mode:
        repo_root = run(["git", "rev-parse", "--show-toplevel"]).strip() or os.getcwd()
        findings, detected_languages = scan_full_repo(repo_root)
        lang_line = f"Detected languages: {', '.join(sorted(detected_languages))}" if detected_languages else "Detected languages: none recognized"
        print_report("full repository scan", f"Repo: {repo_root}\n{lang_line}", findings)
    else:
        summary = get_last_commit_summary()
        diff = get_last_commit_diff()
        if not diff.strip():
            print("commit-guard: no diff found (first commit or empty diff).")
            return
        findings = scan_diff(diff)
        print_report("commit scan", "[Commit Summary]\n" + summary, findings)

if __name__ == "__main__":
    main()
