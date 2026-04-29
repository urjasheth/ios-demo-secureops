#!/usr/bin/env python3
"""
SecurOps Hybrid — AI Code Review (Phase 2)
==========================================
AI-powered code review for Pull Requests.
Matches SonarQube + CodeRabbit capabilities using free AI APIs.

Features:
  - PR diff analysis with inline review comments
  - Security vulnerability detection (OWASP Top 10)
  - Bug detection (null checks, error handling, edge cases)
  - Code quality (complexity, naming, duplication, dead code)
  - Performance issues (N+1, memory leaks, inefficient patterns)
  - Best practices enforcement per language
  - PR summary with severity categorization
  - Quality Gate (pass/fail based on findings)

AI Providers (free, no credit card):
  - Primary:   Google AI Studio (Gemini 2.0 Flash)
  - Fallback:  Groq (Llama 3.3 70B)

Usage:
  Set env vars: GOOGLE_AI_API_KEY (or GROQ_API_KEY), GITHUB_TOKEN
  python3 scripts/ai-code-review.py

Author: SecurOps Team
"""

import os
import sys
import json
import re
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime

# ─────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────
GOOGLE_AI_API_KEY = os.environ.get("GOOGLE_AI_API_KEY", "")
GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# GitHub context (set by GitHub Actions)
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "")
GITHUB_EVENT_PATH = os.environ.get("GITHUB_EVENT_PATH", "")
GITHUB_SHA = os.environ.get("GITHUB_SHA", "")

# Review settings
MAX_FILES_TO_REVIEW = 15          # Skip giant PRs
MAX_DIFF_LINES_PER_FILE = 500     # Truncate huge diffs
MAX_INLINE_COMMENTS = 25          # Don't spam the PR
SEVERITY_BLOCK_THRESHOLD = "critical"  # Block PR on critical findings

# File patterns to skip
SKIP_PATTERNS = [
    r"\.lock$", r"package-lock\.json$", r"yarn\.lock$",
    r"\.min\.(js|css)$", r"\.map$", r"\.svg$", r"\.png$",
    r"\.jpg$", r"\.gif$", r"\.ico$", r"\.woff",
    r"\.gitleaks\.toml$", r"\.DS_Store$",
    r"node_modules/", r"vendor/", r"dist/",
    r"__pycache__/", r"\.pyc$",
    r"generated/", r"build/", r"\.gradle/",
    r"Pods/", r"\.dart_tool/",
]

# ─────────────────────────────────────────────────────────
# AI PROVIDER ABSTRACTION (with retry + fallback)
# ─────────────────────────────────────────────────────────
import time

MAX_RETRIES = 2
RETRY_DELAY = 3  # seconds

def call_ai(prompt, system_prompt="", max_tokens=4096):
    """Call AI provider with retry + automatic fallback: Gemini → Groq → None"""

    # Try Gemini first (with retries)
    if GOOGLE_AI_API_KEY:
        for attempt in range(MAX_RETRIES + 1):
            result = _call_gemini(prompt, system_prompt, max_tokens)
            if result:
                return result
            if attempt < MAX_RETRIES:
                wait = RETRY_DELAY * (attempt + 1)
                print(f"  ⚠️  Gemini attempt {attempt+1} failed, retrying in {wait}s...")
                time.sleep(wait)
        print("  ⚠️  Gemini exhausted retries, trying Groq fallback...")

    # Try Groq fallback (with retries)
    if GROQ_API_KEY:
        for attempt in range(MAX_RETRIES + 1):
            result = _call_groq(prompt, system_prompt, max_tokens)
            if result:
                return result
            if attempt < MAX_RETRIES:
                wait = RETRY_DELAY * (attempt + 1)
                print(f"  ⚠️  Groq attempt {attempt+1} failed, retrying in {wait}s...")
                time.sleep(wait)
        print("  ⚠️  Groq also exhausted retries")

    # No provider available
    if not GOOGLE_AI_API_KEY and not GROQ_API_KEY:
        print("  ℹ️  No AI API key configured (GOOGLE_AI_API_KEY or GROQ_API_KEY)")
        print("  ℹ️  Skipping AI code review — security scans still active")
    return None


def _call_gemini(prompt, system_prompt, max_tokens):
    """Call Google AI Studio (Gemini 2.0 Flash)"""
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GOOGLE_AI_API_KEY}"

        contents = []
        if system_prompt:
            contents.append({"role": "user", "parts": [{"text": system_prompt}]})
            contents.append({"role": "model", "parts": [{"text": "Understood. I will follow these instructions for the code review."}]})
        contents.append({"role": "user", "parts": [{"text": prompt}]})

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json"
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            text = data["candidates"][0]["content"]["parts"][0]["text"]
            return text
    except Exception as e:
        print(f"  ⚠️  Gemini API error: {e}")
        return None


def _call_groq(prompt, system_prompt, max_tokens):
    """Call Groq API (OpenAI-compatible)"""
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"}
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}"
            },
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  ⚠️  Groq API error: {e}")
        return None

# ─────────────────────────────────────────────────────────
# GITHUB API HELPERS
# ─────────────────────────────────────────────────────────
def github_api(endpoint, method="GET", data=None):
    """Make a GitHub API request"""
    url = f"https://api.github.com{endpoint}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  ⚠️  GitHub API error {e.code}: {e.read().decode()[:200]}")
        return None


def get_pr_info():
    """Extract PR number and details from GitHub Actions event"""
    if not GITHUB_EVENT_PATH or not os.path.exists(GITHUB_EVENT_PATH):
        print("  ℹ️  No PR event found — skipping code review")
        return None

    with open(GITHUB_EVENT_PATH) as f:
        event = json.load(f)

    pr = event.get("pull_request")
    if not pr:
        print("  ℹ️  Not a PR event — skipping code review")
        return None

    return {
        "number": pr["number"],
        "title": pr.get("title", ""),
        "body": pr.get("body", "") or "",
        "author": pr.get("user", {}).get("login", "unknown"),
        "base": pr.get("base", {}).get("sha", ""),
        "head": pr.get("head", {}).get("sha", ""),
        "base_ref": pr.get("base", {}).get("ref", "main"),
        "head_ref": pr.get("head", {}).get("ref", ""),
    }


def get_pr_diff(pr_number):
    """Get the PR diff from GitHub API"""
    url = f"https://api.github.com/repos/{GITHUB_REPOSITORY}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"  ⚠️  Failed to get PR diff: {e}")
        return None


def get_pr_files(pr_number):
    """Get list of changed files in PR"""
    result = github_api(f"/repos/{GITHUB_REPOSITORY}/pulls/{pr_number}/files?per_page=100")
    return result if result else []

# ─────────────────────────────────────────────────────────
# DIFF PARSING
# ─────────────────────────────────────────────────────────
def parse_diff(raw_diff):
    """Parse unified diff into per-file structures"""
    files = []
    current_file = None
    current_hunk = None
    diff_line_pos = 0

    for line in raw_diff.split("\n"):
        # New file header
        if line.startswith("diff --git"):
            if current_file:
                files.append(current_file)
            match = re.search(r"b/(.+)$", line)
            filename = match.group(1) if match else "unknown"
            current_file = {
                "filename": filename,
                "hunks": [],
                "additions": 0,
                "deletions": 0,
                "diff_lines": [],
            }
            diff_line_pos = 0
            continue

        if not current_file:
            continue

        # Skip file metadata lines
        if line.startswith("index ") or line.startswith("---") or line.startswith("+++"):
            continue

        # Hunk header
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            start_line = int(match.group(1)) if match else 1
            current_hunk = {"start": start_line, "current_line": start_line}
            current_file["hunks"].append(current_hunk)
            diff_line_pos += 1
            continue

        if current_hunk is None:
            continue

        diff_line_pos += 1

        if line.startswith("+"):
            current_file["additions"] += 1
            current_file["diff_lines"].append({
                "type": "add",
                "content": line[1:],
                "line": current_hunk["current_line"],
                "position": diff_line_pos
            })
            current_hunk["current_line"] += 1
        elif line.startswith("-"):
            current_file["deletions"] += 1
            current_file["diff_lines"].append({
                "type": "del",
                "content": line[1:],
                "line": current_hunk["current_line"],
                "position": diff_line_pos
            })
        else:
            current_file["diff_lines"].append({
                "type": "ctx",
                "content": line[1:] if line.startswith(" ") else line,
                "line": current_hunk["current_line"],
                "position": diff_line_pos
            })
            current_hunk["current_line"] += 1

    if current_file:
        files.append(current_file)

    return files


def should_skip_file(filename):
    """Check if file should be skipped from review"""
    for pattern in SKIP_PATTERNS:
        if re.search(pattern, filename):
            return True
    return False


def get_language(filename):
    """Detect language from file extension"""
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".jsx": "React JSX", ".tsx": "React TSX",
        ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
        ".swift": "Swift", ".m": "Objective-C",
        ".dart": "Dart/Flutter", ".go": "Go",
        ".cs": "C#/.NET", ".rb": "Ruby", ".php": "PHP",
        ".rs": "Rust", ".c": "C", ".cpp": "C++", ".h": "C/C++ Header",
        ".yaml": "YAML", ".yml": "YAML", ".json": "JSON",
        ".xml": "XML", ".html": "HTML", ".css": "CSS",
        ".sql": "SQL", ".sh": "Shell", ".ps1": "PowerShell",
        ".tf": "Terraform", ".hcl": "HCL",
        ".dockerfile": "Dockerfile", ".gradle": "Gradle",
    }
    name = filename.lower()
    if "dockerfile" in name:
        return "Dockerfile"
    for ext, lang in ext_map.items():
        if name.endswith(ext):
            return lang
    return "Unknown"

# ─────────────────────────────────────────────────────────
# AI CODE REVIEW — THE CORE
# ─────────────────────────────────────────────────────────
SYSTEM_PROMPT = """You are SecurOps AI Reviewer — an expert code reviewer equivalent to SonarQube, CodeRabbit, and CodeClimate combined.
You analyze code changes in Pull Requests and provide actionable, specific, line-level feedback.

═══════════════════════════════════════════════════
YOUR REVIEW COVERS 8 CATEGORIES WITH 80+ RULE CHECKS
═══════════════════════════════════════════════════

━━━ 1. 🔒 SECURITY (OWASP Top 10 + CWE Top 25) ━━━
Check for:
- SQL/NoSQL Injection: string concatenation in queries, unsanitized user input in DB calls
- XSS: unescaped output in HTML/templates, innerHTML usage, dangerouslySetInnerHTML
- SSRF: user-controlled URLs in HTTP requests, unvalidated redirects
- Broken Authentication: hardcoded credentials, weak password validation, missing rate limiting
- Sensitive Data Exposure: logging PII/tokens, secrets in code, missing encryption at rest
- Insecure Deserialization: pickle.loads, yaml.load without SafeLoader, JSON.parse of user input
- Broken Access Control: missing authorization checks, IDOR vulnerabilities
- Security Misconfiguration: debug mode in production, permissive CORS, missing security headers
- Cryptographic Failures: MD5/SHA1 for passwords, ECB mode, hardcoded keys/IVs, weak random
- Path Traversal: user input in file paths without sanitization

━━━ 2. 🐛 BUGS & RELIABILITY ━━━
Check for:
- Null/Undefined: accessing properties on nullable without null-check, Optional.get() without isPresent()
- Off-by-One: loop boundary errors, array index out of bounds, fence-post errors
- Race Conditions: shared mutable state without synchronization, async issues, double-checked locking
- Error Handling: empty catch blocks, swallowed exceptions, catch(Exception) too broad
- Resource Leaks: unclosed streams/connections/cursors, missing finally/using/try-with-resources
- Type Errors: incorrect type casting, parseInt without validation, type coercion bugs
- Logic Errors: inverted conditions, unreachable code, always-true/false conditions
- Concurrency: ConcurrentModificationError risk, non-thread-safe collections used across threads
- State Management: uninitialized variables, stale state in closures, missing state reset

━━━ 3. 🧹 CODE QUALITY & SMELLS (SonarQube-style) ━━━
Check for:
- Complexity: cyclomatic complexity > 10, deeply nested if/else/try (>3 levels), long method chains
- Naming: single-letter variables (except i/j/k in loops), misleading names, inconsistent naming conventions
- Dead Code: unreachable code, unused variables/imports/parameters, commented-out code blocks
- Duplication: copy-pasted logic that should be extracted, repeated magic numbers/strings
- Long Methods: functions > 50 lines, classes > 300 lines, parameter lists > 5 params
- Single Responsibility: classes/functions doing too many things, god classes, feature envy
- Magic Numbers: raw numbers without named constants (except 0, 1, -1, common values)
- Tight Coupling: direct instantiation vs dependency injection, hard-coded dependencies
- Code Comments: TODO/FIXME/HACK without issue reference, misleading comments, commented-out code

━━━ 4. ⚡ PERFORMANCE ━━━
Check for:
- N+1 Queries: database calls inside loops, lazy-loading in iteration, missing eager loading
- Memory Leaks: event listeners not removed, subscriptions not disposed, growing collections
- Inefficient Operations: O(n²) when O(n) is possible, nested loops on large data, repeated computation
- Unnecessary I/O: sync file/network calls in hot paths, blocking main thread, redundant API calls
- String Operations: string concatenation in loops (use StringBuilder/Buffer), excessive regex compilation
- Collection Misuse: ArrayList for frequent inserts, HashMap vs TreeMap choice, missing capacity hints
- React/UI: missing keys in lists, unnecessary re-renders, large component re-renders
- Database: missing indexes implied by query patterns, SELECT *, unbounded queries without LIMIT
- Caching: repeated computation that should be cached/memoized, cache without expiration

━━━ 5. 📏 BEST PRACTICES (Language-Specific) ━━━

Python:
- Use f-strings over .format() or % formatting
- Use pathlib over os.path, use context managers (with) for file/resource handling
- Type hints on public functions, dataclasses over raw dicts for structured data
- Avoid mutable default arguments, use enumerate() over range(len())

Java/Kotlin:
- Use Optional over null returns, prefer val over var (Kotlin), use sealed classes
- Use try-with-resources for AutoCloseable, avoid raw types in generics
- Prefer Stream API over manual loops, use immutable collections where possible
- Kotlin: use scope functions (let, apply, also), data classes, null safety operators

JavaScript/TypeScript:
- Use const over let, never use var, use === over ==
- Use Promise/async-await over callbacks, handle Promise rejections
- TypeScript: avoid 'any' type, use proper interface/type definitions, strict null checks
- Use optional chaining (?.), nullish coalescing (??), destructuring

C#/.NET:
- Use async/await properly (don't block on async), IDisposable pattern
- Use LINQ over manual loops, string interpolation over concatenation
- Prefer record types for DTOs, use nullable reference types (C# 8+)

Dart/Flutter:
- Use const constructors, final variables, late initialization
- Proper widget composition (small widgets), avoid building widgets in build()
- Use extension methods, null safety operators (!., ?., ??=), proper dispose()

Go:
- Handle all errors (don't use _), use defer for cleanup
- Use context for cancellation, avoid goroutine leaks, check channel closing
- Prefer interfaces over concrete types, use table-driven tests

━━━ 6. 🧪 TESTING ━━━
Check for:
- Missing Tests: new public methods/endpoints without corresponding tests
- Untested Edge Cases: boundary values, null/empty inputs, error paths not tested
- Test Quality: assertions too vague (assertTrue vs assertEquals), single assert per test
- Test Independence: tests depending on execution order, shared mutable test state
- Mock Overuse: mocking everything vs integration tests, mocking what you don't own

━━━ 7. 🏗️ ARCHITECTURE & DESIGN ━━━
Check for:
- SOLID Violations: classes with multiple responsibilities, Liskov substitution issues
- API Design: inconsistent naming, missing input validation, breaking changes
- Error Propagation: losing error context during re-throw, generic error messages
- Dependency Direction: inner layers depending on outer layers, circular dependencies
- Configuration: hardcoded values that should be configurable, environment-specific logic

━━━ 8. 📝 DOCUMENTATION ━━━
Check for:
- Missing Docs: public API without documentation, complex algorithms without explanation
- Outdated Docs: parameter changes not reflected in docstring, misleading comments
- API Contracts: missing request/response schemas, undocumented error responses

═══════════════════════════════════════════════════
SEVERITY LEVELS
═══════════════════════════════════════════════════
- critical: Security vulnerabilities, data loss risks, crashes in production → MUST fix before merge
- high: Bugs, resource leaks, significant quality issues → SHOULD fix before merge
- medium: Code smells, performance concerns, best practice violations → NICE to fix
- low: Style improvements, minor suggestions, documentation → Optional/informational

═══════════════════════════════════════════════════
RULES FOR YOUR REVIEW
═══════════════════════════════════════════════════
1. Only comment on NEW/CHANGED lines (lines with +), NEVER on deleted or unchanged code
2. Be specific: reference exact line numbers, variable names, and method names
3. Provide a concrete fix suggestion for EVERY finding (show corrected code when possible)
4. Use the language/framework-appropriate conventions and idioms
5. Don't be overly nitpicky — focus on issues that genuinely matter for production quality
6. If the code looks good, say so! Not every PR needs findings. Give clean code a score of 9-10
7. Prioritize: Security > Bugs > Performance > Quality > Best Practices > Documentation
8. For each finding, explain WHY it's a problem (impact) not just WHAT is wrong
9. Consider the context: a prototype script has different standards than a production API
10. Return valid JSON only, no markdown wrapping or extra text"""


def review_file(file_data, pr_context):
    """Review a single file using AI"""
    filename = file_data["filename"]
    language = get_language(filename)

    # Build the diff text (only additions and context)
    diff_text = ""
    for dl in file_data["diff_lines"][:MAX_DIFF_LINES_PER_FILE]:
        prefix = "+" if dl["type"] == "add" else "-" if dl["type"] == "del" else " "
        diff_text += f"L{dl['line']:4d} {prefix} {dl['content']}\n"

    if not diff_text.strip():
        return None

    prompt = f"""Review this code change in a Pull Request.

**PR Title:** {pr_context.get('title', 'N/A')}
**File:** {filename}
**Language:** {language}
**Changes:** +{file_data['additions']} / -{file_data['deletions']} lines

**Diff (L=line number, +=added, -=removed, space=context):**
```
{diff_text}
```

Analyze ONLY the added (+) lines. Return a JSON object with this exact structure:
{{
  "findings": [
    {{
      "line": <int, the line number from the diff>,
      "severity": "<critical|high|medium|low>",
      "category": "<security|bug|quality|performance|best_practice|testing|architecture|documentation>",
      "title": "<short title, max 80 chars>",
      "description": "<detailed explanation of the issue and WHY it matters>",
      "suggestion": "<specific code fix or recommendation (show corrected code when possible)>"
    }}
  ],
  "file_summary": "<1-2 sentence summary of code quality for this file>",
  "score": <int 1-10, where 10 is perfect code>
}}

If the code looks good with no issues, return: {{"findings": [], "file_summary": "Code looks clean and well-written.", "score": 9}}"""

    response = call_ai(prompt, SYSTEM_PROMPT)
    if not response:
        return None

    try:
        # Parse JSON response
        result = json.loads(response)
        # Attach filename to each finding
        for f in result.get("findings", []):
            f["filename"] = filename
            f["language"] = language
        return result
    except json.JSONDecodeError:
        # Try to extract JSON from response
        match = re.search(r'\{[\s\S]*\}', response)
        if match:
            try:
                result = json.loads(match.group())
                for f in result.get("findings", []):
                    f["filename"] = filename
                    f["language"] = language
                return result
            except json.JSONDecodeError:
                pass
        print(f"  ⚠️  Could not parse AI response for {filename}")
        return None


def generate_pr_summary(all_findings, files_reviewed, pr_context):
    """Generate an overall PR summary comment"""
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_counts = {}

    for f in all_findings:
        sev = f.get("severity", "low")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        cat = f.get("category", "other")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    total = len(all_findings)
    has_critical = severity_counts["critical"] > 0
    has_high = severity_counts["high"] > 0

    # Quality gate
    if has_critical:
        gate = "❌ FAILED"
        gate_reason = "Critical issues must be fixed before merge"
    elif has_high and severity_counts["high"] >= 3:
        gate = "⚠️ WARNING"
        gate_reason = "Multiple high-severity issues found"
    else:
        gate = "✅ PASSED"
        gate_reason = "No blocking issues found"

    # Category emoji map
    cat_emoji = {
        "security": "🔒", "bug": "🐛", "quality": "🧹",
        "performance": "⚡", "best_practice": "📏", "testing": "🧪",
        "architecture": "🏗️", "documentation": "📝"
    }

    # Build summary markdown
    summary = f"""## 🤖 SecurOps AI Code Review

### Quality Gate: {gate}
{gate_reason}

### 📊 Summary
| Metric | Value |
|--------|-------|
| Files reviewed | {files_reviewed} |
| Total findings | {total} |
| 🔴 Critical | {severity_counts['critical']} |
| 🟠 High | {severity_counts['high']} |
| 🟡 Medium | {severity_counts['medium']} |
| 🔵 Low | {severity_counts['low']} |

"""

    if category_counts:
        summary += "### 📋 Findings by Category\n"
        summary += "| Category | Count |\n|----------|-------|\n"
        for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
            emoji = cat_emoji.get(cat, "📌")
            label = cat.replace("_", " ").title()
            summary += f"| {emoji} {label} | {count} |\n"
        summary += "\n"

    if all_findings:
        summary += "### 🔍 Top Findings\n"
        # Show top 10 most severe findings
        sorted_findings = sorted(all_findings,
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity"), 4))

        for i, f in enumerate(sorted_findings[:10]):
            sev_badge = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(f.get("severity"), "⚪")
            summary += f"\n{sev_badge} **{f.get('title', 'Issue')}** (`{f.get('filename', '')}` L{f.get('line', '?')})\n"
            summary += f"> {f.get('description', '')}\n"
            if f.get("suggestion"):
                summary += f"> 💡 **Fix:** {f.get('suggestion')}\n"

    if not all_findings:
        summary += "\n### ✨ Great job!\nNo issues found. This PR looks clean and well-written.\n"

    summary += f"""
---
<sub>🤖 Powered by SecurOps AI (Gemini/Groq) • {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</sub>
<sub>📊 This review covers: Security • Bugs • Code Quality • Performance • Best Practices • Testing • Architecture • Documentation</sub>
"""

    return summary, gate


# ─────────────────────────────────────────────────────────
# GITHUB PR COMMENT POSTING
# ─────────────────────────────────────────────────────────
def post_pr_review(pr_number, findings, summary, head_sha, files_data):
    """Post inline review comments + summary on the PR"""

    # Build position map: filename+line → diff position
    position_map = {}
    for fd in files_data:
        for dl in fd.get("diff_lines", []):
            if dl["type"] == "add":
                key = f"{fd['filename']}:{dl['line']}"
                position_map[key] = dl["position"]

    # Build inline comments (limited to MAX_INLINE_COMMENTS)
    comments = []
    sorted_findings = sorted(findings,
        key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.get("severity"), 4))

    for f in sorted_findings[:MAX_INLINE_COMMENTS]:
        filename = f.get("filename", "")
        line = f.get("line", 0)
        key = f"{filename}:{line}"
        position = position_map.get(key)

        if not position:
            continue

        sev_badge = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🔵 Low"}.get(
            f.get("severity"), "⚪ Info")
        cat_emoji = {
            "security": "🔒", "bug": "🐛", "quality": "🧹",
            "performance": "⚡", "best_practice": "📏", "testing": "🧪",
            "architecture": "🏗️", "documentation": "📝"
        }.get(f.get("category"), "📌")

        body = f"**{sev_badge}** | {cat_emoji} {f.get('category', 'other').replace('_', ' ').title()}\n\n"
        body += f"**{f.get('title', 'Issue')}**\n\n"
        body += f"{f.get('description', '')}\n\n"
        if f.get("suggestion"):
            suggestion_text = f.get('suggestion', '')
            # Check if suggestion contains actual code (has newlines or looks like code)
            has_code = '\n' in suggestion_text or '=' in suggestion_text or '(' in suggestion_text
            if has_code:
                # Use GitHub's suggestion block for ONE-CLICK fix apply
                body += "💡 **Apply this fix** (click 'Apply suggestion' below):\n\n"
                body += f"```suggestion\n{suggestion_text}\n```\n"
            else:
                # Plain text suggestion
                body += f"💡 **Suggestion:** {suggestion_text}\n"

        comments.append({
            "path": filename,
            "position": position,
            "body": body
        })

    # Determine review event
    has_critical = any(f.get("severity") == "critical" for f in findings)
    event = "REQUEST_CHANGES" if has_critical else "COMMENT"

    # Post review with inline comments
    if comments:
        review_data = {
            "body": summary,
            "event": event,
            "commit_id": head_sha,
            "comments": comments
        }
        result = github_api(
            f"/repos/{GITHUB_REPOSITORY}/pulls/{pr_number}/reviews",
            method="POST",
            data=review_data
        )
        if result:
            print(f"  ✅ Posted review with {len(comments)} inline comments")
        else:
            # Fallback: post summary as regular comment
            _post_comment_fallback(pr_number, summary)
    else:
        # No inline comments, just post summary
        _post_comment_fallback(pr_number, summary)


def _post_comment_fallback(pr_number, summary):
    """Post summary as a regular PR comment (fallback)"""
    # First, check for existing bot comment to update
    comments = github_api(f"/repos/{GITHUB_REPOSITORY}/issues/{pr_number}/comments?per_page=100")
    existing_id = None
    if comments:
        for c in comments:
            if "SecurOps AI Code Review" in c.get("body", ""):
                existing_id = c["id"]
                break

    if existing_id:
        # Update existing comment
        github_api(
            f"/repos/{GITHUB_REPOSITORY}/issues/comments/{existing_id}",
            method="PATCH",
            data={"body": summary}
        )
        print(f"  ✅ Updated existing review comment #{existing_id}")
    else:
        # Post new comment
        github_api(
            f"/repos/{GITHUB_REPOSITORY}/issues/{pr_number}/comments",
            method="POST",
            data={"body": summary}
        )
        print(f"  ✅ Posted new review comment on PR #{pr_number}")

# ─────────────────────────────────────────────────────────
# MAIN EXECUTION
# ─────────────────────────────────────────────────────────
def main():
    print("═" * 50)
    print("  🤖 SecurOps AI Code Review — Phase 2")
    print("═" * 50)

    # Check prerequisites
    if not GITHUB_TOKEN:
        print("  ⚠️  GITHUB_TOKEN not set — skipping AI code review")
        sys.exit(0)

    if not GOOGLE_AI_API_KEY and not GROQ_API_KEY:
        print("  ⚠️  No AI API key configured")
        print("  ℹ️  Set GOOGLE_AI_API_KEY or GROQ_API_KEY in repo secrets")
        print("  ℹ️  Get free key: https://aistudio.google.com/apikey")
        sys.exit(0)

    provider = "Gemini" if GOOGLE_AI_API_KEY else "Groq"
    print(f"  ℹ️  AI Provider: {provider}")

    # Get PR info
    pr_info = get_pr_info()
    if not pr_info:
        sys.exit(0)

    pr_number = pr_info["number"]
    print(f"  ℹ️  Reviewing PR #{pr_number}: {pr_info['title']}")
    print(f"  ℹ️  Author: @{pr_info['author']}")

    # Get PR diff
    raw_diff = get_pr_diff(pr_number)
    if not raw_diff:
        print("  ⚠️  Could not get PR diff")
        sys.exit(0)

    # Parse diff into files
    files = parse_diff(raw_diff)
    print(f"  ℹ️  Total files changed: {len(files)}")

    # Filter files
    reviewable = []
    for f in files:
        if should_skip_file(f["filename"]):
            print(f"  ⏭️  Skipping: {f['filename']} (excluded pattern)")
            continue
        if f["additions"] == 0:
            print(f"  ⏭️  Skipping: {f['filename']} (no additions)")
            continue
        reviewable.append(f)

    if not reviewable:
        print("  ℹ️  No reviewable files — posting clean summary")
        summary, gate = generate_pr_summary([], 0, pr_info)
        _post_comment_fallback(pr_number, summary)
        sys.exit(0)

    # Limit files
    if len(reviewable) > MAX_FILES_TO_REVIEW:
        print(f"  ⚠️  Too many files ({len(reviewable)}), reviewing top {MAX_FILES_TO_REVIEW}")
        reviewable = sorted(reviewable, key=lambda x: x["additions"], reverse=True)[:MAX_FILES_TO_REVIEW]

    print(f"  ℹ️  Files to review: {len(reviewable)}")
    print()

    # Review each file
    all_findings = []
    file_summaries = []

    for i, file_data in enumerate(reviewable, 1):
        fname = file_data["filename"]
        lang = get_language(fname)
        print(f"  [{i}/{len(reviewable)}] Reviewing: {fname} ({lang}, +{file_data['additions']}/-{file_data['deletions']})")

        result = review_file(file_data, pr_info)
        if result:
            findings = result.get("findings", [])
            all_findings.extend(findings)
            score = result.get("score", "?")
            file_summary = result.get("file_summary", "")
            print(f"         → Score: {score}/10 | Findings: {len(findings)} | {file_summary}")
            file_summaries.append({"file": fname, "score": score, "summary": file_summary})
        else:
            print(f"         → Skipped (AI unavailable)")

    print()
    print(f"  📊 Total findings: {len(all_findings)}")

    # Generate summary
    summary, gate = generate_pr_summary(all_findings, len(reviewable), pr_info)
    print(f"  🚦 Quality Gate: {gate}")

    # Post to GitHub PR
    print(f"  📤 Posting review to PR #{pr_number}...")
    post_pr_review(pr_number, all_findings, summary, pr_info["head"], reviewable)

    # Set output for GitHub Actions
    has_critical = any(finding.get('severity') == 'critical' for finding in all_findings)
    output_file = os.environ.get("GITHUB_OUTPUT", "")
    if output_file:
        with open(output_file, "a") as out:
            out.write(f"findings_count={len(all_findings)}\n")
            out.write(f"gate={gate}\n")
            out.write(f"has_critical={'true' if has_critical else 'false'}\n")

    # Exit code based on gate
    if "FAILED" in gate:
        print(f"\n  ❌ AI Review: Quality Gate FAILED — critical issues found")
        sys.exit(1)
    else:
        print(f"\n  ✅ AI Review complete — {gate}")
        sys.exit(0)


if __name__ == "__main__":
    main()
