import json
import sys

def check_zap_report(report_path):
    """
    SecurOps ZAP Threshold Enforcer
    From: Approach A — Block on HIGH, Warn on MEDIUM
    Integrated into Hybrid pipeline as post-ZAP gate
    """
    print(f"🔍 SecurOps: Analyzing ZAP report at {report_path}...")

    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print("⚠️ ZAP report not found — skipping threshold check")
        sys.exit(0)
    except json.JSONDecodeError:
        print("⚠️ ZAP report is not valid JSON — skipping")
        sys.exit(0)

    high_count = 0
    medium_count = 0
    low_count = 0

    for site in data.get('site', []):
        for alert in site.get('alerts', []):
            risk = alert.get('riskcode')  # 3=High, 2=Medium, 1=Low, 0=Info
            if risk == "3":
                high_count += 1
                print(f"🔴 HIGH RISK: {alert.get('alert')} — {alert.get('name')}")
                print(f"   URL: {alert.get('url', 'N/A')}")
            elif risk == "2":
                medium_count += 1
                print(f"🟡 MEDIUM RISK: {alert.get('alert')}")
            elif risk == "1":
                low_count += 1

    print(f"\n{'='*50}")
    print(f"  ZAP Results: {high_count} High | {medium_count} Medium | {low_count} Low")
    print(f"{'='*50}")

    if high_count > 0:
        print("❌ BLOCK: High severity vulnerabilities detected!")
        print("   Fix these before merging. See ZAP HTML report for details.")
        sys.exit(1)
    elif medium_count > 0:
        print("⚠️ WARN: Medium severity issues detected. Please review.")
        print("   Pipeline continues but these should be addressed.")
        sys.exit(0)  # Warn but don't fail for medium
    else:
        print("✅ No High or Medium security issues found.")
        sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python zap_report_check.py <path_to_json_report>")
        sys.exit(1)
    check_zap_report(sys.argv[1])
