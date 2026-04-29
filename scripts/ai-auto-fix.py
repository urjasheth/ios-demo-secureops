#!/usr/bin/env python3
"""
SecurOps Hybrid AI Auto-Fix Script
File: scripts/ai-auto-fix.py

Uses Gemini (primary) / Groq (fallback) to:
1. Read all scan reports (Gitleaks, TruffleHog, Semgrep, Trivy, Nuclei, ZAP, Checkov)
2. Analyze each vulnerability
3. Generate specific code fixes
4. Create a GitHub Issue with fixes + PR-ready patches

AI Providers (free, no credit card):
  Primary:   Google AI Studio (Gemini 2.0 Flash)
  Fallback:  Groq (Llama 3.3 70B)

Requires: GOOGLE_AI_API_KEY or GROQ_API_KEY in GitHub repo secrets
"""

import os
import json
import glob
import urllib.request
import urllib.error
from datetime import datetime

# ─────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────
GOOGLE_AI_API_KEY = os.environ.get("GOOGLE_AI_API_KEY", "")
GROQ_API_KEY      = os.environ.get("GROQ_API_KEY", "")
GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN")
REPO              = os.environ.get("REPO", "")
SHA               = os.environ.get("SHA", "")
ACTOR             = os.environ.get("ACTOR", "unknown")
MAX_FIXES_PER_RUN = 10

# ─────────────────────────────────────────────────────────
# AI PROVIDER (Gemini → Groq fallback)
# ─────────────────────────────────────────────────────────
import time

MAX_RETRIES = 2
RETRY_DELAY = 3  # seconds

def call_ai(prompt, max_tokens=1024):
    """Call AI provider with retry + automatic fallback: Gemini → Groq → None"""

    if GOOGLE_AI_API_KEY:
        for attempt in range(MAX_RETRIES + 1):
            result = _call_gemini(prompt, max_tokens)
            if result:
                return result
            if attempt < MAX_RETRIES:
                wait = RETRY_DELAY * (attempt + 1)
                print(f"  ⚠️  Gemini attempt {attempt+1} failed, retrying in {wait}s...")
                time.sleep(wait)
        print("  ⚠️  Gemini exhausted retries, trying Groq...")

    if GROQ_API_KEY:
        for attempt in range(MAX_RETRIES + 1):
            result = _call_groq(prompt, max_tokens)
            if result:
                return result
            if attempt < MAX_RETRIES:
                wait = RETRY_DELAY * (attempt + 1)
                print(f"  ⚠️  Groq attempt {attempt+1} failed, retrying in {wait}s...")
                time.sleep(wait)

    return "AI fix generation unavailable — no API key or provider error."


def _call_gemini(prompt, max_tokens):
    """Call Google AI Studio (Gemini 2.0 Flash)"""
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GOOGLE_AI_API_KEY}"
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": max_tokens}
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["candidates"][0]["content"]["parts"][0]["text"]
    except Exception as e:
        print(f"  ⚠️  Gemini error: {e}")
        return None


def _call_groq(prompt, max_tokens):
    """Call Groq (OpenAI-compatible)"""
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2, "max_tokens": max_tokens
        }
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}"
            }, method="POST"
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"  ⚠️  Groq error: {e}")
        return None

# ─────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────

def load_report(path_pattern):
    """Load a JSON report file, return empty dict if not found."""
    files = glob.glob(path_pattern, recursive=True)
    if not files:
        return {}
    try:
        with open(files[0]) as f:
            return json.load(f)
    except Exception:
        return {}

def load_jsonl(path_pattern):
    """Load a JSONL (newline-delimited JSON) report file."""
    files = glob.glob(path_pattern, recursive=True)
    results = []
    if not files:
        return results
    try:
        with open(files[0]) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        pass
    return results

def read_file_snippet(filepath, line_num, context=5):
    """Read code around a specific line for context."""
    try:
        with open(filepath) as f:
            lines = f.readlines()
        start = max(0, line_num - context - 1)
        end   = min(len(lines), line_num + context)
        snippet = []
        for i, line in enumerate(lines[start:end], start=start+1):
            marker = ">>>" if i == line_num else "   "
            snippet.append(f"{marker} {i:4d} | {line.rstrip()}")
        return "\n".join(snippet)
    except Exception:
        return "(could not read file)"

# ─────────────────────────────────────────────────────────
# COLLECT ALL FINDINGS (7 tools)
# ─────────────────────────────────────────────────────────

def collect_findings():
    """Collect all findings from all scan reports."""
    findings = []

    # ── Semgrep (SAST) ───────────────────────────────────
    sast = load_report("reports/report-sast/semgrep.json")
    for r in sast.get("results", [])[:5]:
        if r.get("extra", {}).get("severity") == "ERROR":
            findings.append({
                "tool"     : "Semgrep SAST",
                "severity" : "HIGH",
                "type"     : r.get("check_id", "unknown"),
                "message"  : r.get("extra", {}).get("message", ""),
                "file"     : r.get("path", ""),
                "line"     : r.get("start", {}).get("line", 0),
                "snippet"  : read_file_snippet(r.get("path",""), r.get("start",{}).get("line",0)),
                "fix_hint" : r.get("extra", {}).get("metadata", {}).get("fix", ""),
            })

    # ── Trivy (SCA) ──────────────────────────────────────
    sca = load_report("reports/report-sca/trivy.json")
    for result in sca.get("Results", [])[:3]:
        for v in result.get("Vulnerabilities", [])[:3]:
            if v.get("Severity") in ["CRITICAL", "HIGH"]:
                findings.append({
                    "tool"     : "Trivy SCA",
                    "severity" : v.get("Severity", "HIGH"),
                    "type"     : v.get("VulnerabilityID", ""),
                    "message"  : v.get("Title", "") or v.get("Description", "")[:200],
                    "file"     : result.get("Target", ""),
                    "line"     : 0,
                    "snippet"  : f"Package: {v.get('PkgName')} {v.get('InstalledVersion')} → Fix: {v.get('FixedVersion','no fix yet')}",
                    "fix_hint" : f"Upgrade {v.get('PkgName')} to {v.get('FixedVersion','latest')}",
                })

    # ── Checkov (IaC) ────────────────────────────────────
    iac = load_report("reports/report-iac/checkov.json")
    for check in iac.get("results", {}).get("failed_checks", [])[:3]:
        if check.get("severity") == "CRITICAL":
            findings.append({
                "tool"     : "Checkov IaC",
                "severity" : "CRITICAL",
                "type"     : check.get("check_id", ""),
                "message"  : check.get("check", {}).get("name", ""),
                "file"     : check.get("repo_file_path", ""),
                "line"     : check.get("file_line_range", [0])[0],
                "snippet"  : read_file_snippet(check.get("repo_file_path",""), check.get("file_line_range",[0,0])[0]),
                "fix_hint" : check.get("check", {}).get("guideline", ""),
            })

    # ── Nuclei (DAST) ────────────────────────────────────
    nuclei = load_jsonl("reports/report-dast/nuclei.json")
    for r in nuclei[:3]:
        if r.get("info", {}).get("severity") in ["critical", "high"]:
            findings.append({
                "tool"     : "Nuclei DAST",
                "severity" : r.get("info", {}).get("severity", "high").upper(),
                "type"     : r.get("template-id", ""),
                "message"  : r.get("info", {}).get("name", ""),
                "file"     : r.get("matched-at", r.get("host", "")),
                "line"     : 0,
                "snippet"  : r.get("extracted-results", ["No extract"])[0] if r.get("extracted-results") else "",
                "fix_hint" : r.get("info", {}).get("remediation", ""),
            })

    # ── OWASP ZAP (Deep DAST) ───────────────────────────
    zap = load_report("reports/report-dast-zap/zap_report.json")
    for site in zap.get("site", [])[:2]:
        for alert in site.get("alerts", [])[:3]:
            risk = alert.get("riskcode", "0")
            if risk == "3":  # HIGH only
                findings.append({
                    "tool"     : "OWASP ZAP DAST",
                    "severity" : "HIGH",
                    "type"     : alert.get("alert", ""),
                    "message"  : f"{alert.get('name', '')} at {alert.get('url', site.get('@name', ''))}",
                    "file"     : alert.get("url", site.get("@name", "")),
                    "line"     : 0,
                    "snippet"  : f"Attack: {alert.get('attack', 'N/A')}\nEvidence: {alert.get('evidence', 'N/A')}\nParam: {alert.get('param', 'N/A')}",
                    "fix_hint" : alert.get("solution", ""),
                })

    return findings[:MAX_FIXES_PER_RUN]

# ─────────────────────────────────────────────────────────
# AI FIX GENERATION
# ─────────────────────────────────────────────────────────

def generate_fix(finding):
    """Ask AI to generate a specific fix for a finding."""
    prompt = f"""You are a security engineer. Analyze this security finding and provide a concrete fix.

TOOL: {finding['tool']}
SEVERITY: {finding['severity']}
TYPE: {finding['type']}
FILE: {finding['file']}
LINE: {finding['line']}
ISSUE: {finding['message']}

CODE CONTEXT:
{finding['snippet']}

FIX HINT FROM TOOL: {finding['fix_hint']}

Provide:
1. **Root Cause** (1 sentence)
2. **Exact Fix** (show the corrected code or command)
3. **Why This Fix Works** (1-2 sentences)
4. **Prevention** (1 sentence for future)

Be specific. Show actual code changes, not generic advice.
Format as markdown."""

    return call_ai(prompt, max_tokens=800)

# ─────────────────────────────────────────────────────────
# GITHUB ISSUE CREATION
# ─────────────────────────────────────────────────────────

def create_github_issue(findings_with_fixes):
    """Create a GitHub Issue with all AI-generated fixes."""
    if not GITHUB_TOKEN or not REPO:
        print("⚠️  No GITHUB_TOKEN or REPO — skipping issue creation")
        return

    try:
        provider = "Gemini" if GOOGLE_AI_API_KEY else "Groq"
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        sha_short = SHA[:7] if SHA else "unknown"

        body_lines = [
            f"## 🤖 SecurOps Hybrid AI Auto-Fix Report",
            f"",
            f"**Commit:** `{sha_short}` | **By:** @{ACTOR} | **Time:** {timestamp}",
            f"**Pipeline:** 7-tool hybrid scan (Gitleaks + TruffleHog + Semgrep + Trivy + Nuclei + ZAP + Checkov)",
            f"**AI Provider:** {provider}",
            f"",
            f"Found **{len(findings_with_fixes)}** issue(s) requiring attention.",
            f"AI has analyzed each finding and provided specific fixes below.",
            f"",
            f"---",
        ]

        for i, (finding, fix) in enumerate(findings_with_fixes, 1):
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(finding["severity"], "⚪")
            line_info = f' line {finding["line"]}' if finding['line'] else ''
            body_lines += [
                f"",
                f"## {severity_emoji} Issue {i}: {finding['type']}",
                f"**Tool:** {finding['tool']} | **Severity:** {finding['severity']}",
                f"**Location:** `{finding['file']}`{line_info}",
                f"",
                f"**Finding:** {finding['message']}",
                f"",
                f"### 🤖 AI Fix ({provider}):",
                f"",
                fix,
                f"",
                f"---",
            ]

        body_lines += [
            f"",
            f"*Generated by SecurOps Hybrid AI Auto-Fix using {provider} | [View pipeline run](https://github.com/{REPO}/actions)*",
        ]

        body = "\n".join(body_lines)

        issue_data = json.dumps({
            "title"  : f"🤖 SecurOps AI Fix: {len(findings_with_fixes)} issues found (commit {sha_short})",
            "body"   : body,
            "labels" : ["security", "ai-auto-fix", "automated"],
        }).encode()

        req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO}/issues",
            data=issue_data,
            headers={
                "Authorization": f"token {GITHUB_TOKEN}",
                "Content-Type" : "application/json",
                "Accept"       : "application/vnd.github.v3+json",
            },
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"✅ GitHub Issue created: {result.get('html_url')}")

    except Exception as e:
        print(f"⚠️  Could not create GitHub issue: {e}")
        with open("ai-fix-report.md", "w") as f:
            f.write(body)
        print("✅ Saved to ai-fix-report.md instead")

# ─────────────────────────────────────────────────────────
# SAVE FIX REPORT
# ─────────────────────────────────────────────────────────

def save_fix_report(findings_with_fixes):
    """Save the AI fix report as a markdown file (always)."""
    provider = "Gemini" if GOOGLE_AI_API_KEY else "Groq"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# 🤖 SecurOps Hybrid AI Auto-Fix Report",
        f"Generated: {timestamp} | Commit: {SHA[:7] if SHA else 'local'} | AI: {provider}",
        f"Pipeline: 7-tool hybrid scan",
        f"",
    ]
    for i, (finding, fix) in enumerate(findings_with_fixes, 1):
        lines += [
            f"## Issue {i}: [{finding['severity']}] {finding['type']} — {finding['tool']}",
            f"**File:** `{finding['file']}` | **Line:** {finding['line']}",
            f"**Issue:** {finding['message']}",
            f"",
            f"### AI Fix:",
            fix,
            f"",
            f"---",
            f"",
        ]
    with open("ai-fix-report.md", "w") as f:
        f.write("\n".join(lines))
    print(f"✅ Fix report saved: ai-fix-report.md")

# ─────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────

def main():
    print("🤖 SecurOps Hybrid AI Auto-Fix — Starting...")
    print(f"   Repo: {REPO} | Actor: {ACTOR} | SHA: {SHA[:7] if SHA else 'local'}")
    print(f"   Pipeline: 7-tool hybrid (Gitleaks+TruffleHog+Semgrep+Trivy+Nuclei+ZAP+Checkov)")
    print()

    if not GOOGLE_AI_API_KEY and not GROQ_API_KEY:
        print("⚠️  No AI API key configured (GOOGLE_AI_API_KEY or GROQ_API_KEY)")
        print("   Get free key: https://aistudio.google.com/apikey")
        return

    provider = "Gemini" if GOOGLE_AI_API_KEY else "Groq"
    print(f"   AI Provider: {provider}")

    print("📊 Collecting findings from all 7 scan reports...")
    findings = collect_findings()

    if not findings:
        print("✅ No findings to fix — all scans passed!")
        return

    print(f"   Found {len(findings)} issue(s) to analyze")
    print()

    findings_with_fixes = []
    for i, finding in enumerate(findings, 1):
        print(f"🔍 Analyzing issue {i}/{len(findings)}: [{finding['severity']}] {finding['type']} ({finding['tool']})")
        fix = generate_fix(finding)
        findings_with_fixes.append((finding, fix))
        print(f"   ✅ Fix generated")

    print()

    save_fix_report(findings_with_fixes)

    print("📝 Creating GitHub Issue with all fixes...")
    create_github_issue(findings_with_fixes)

    print()
    print(f"✅ AI Auto-Fix complete — {len(findings_with_fixes)} fixes generated using {provider}")

if __name__ == "__main__":
    main()
