"""
Full scan-to-report pipeline.

Steps:
  1. Check ZAP is reachable
  2. Check the target Flask app is reachable
  3. Run the ZAP spider + active scan
  4. Run AI analysis on the scan output
  5. Print a final summary with timing
"""

import os
import sys
import time
from pathlib import Path

import urllib.request
import urllib.error

from dotenv import load_dotenv
from zapv2 import ZAPv2

from scanner.config import ZAP_API_URL, TARGET_URL, REPORT_OUTPUT_PATH
from scanner.run_scan import (
    run_spider,
    run_active_scan,
    collect_alerts,
    save_report,
    print_summary,
)
from analysis.analyze import (
    load_alerts,
    deduplicate,
    load_prompt,
    call_claude,
    save_report as save_analysis,
    DEFAULT_OUTPUT,
)

REPO_ROOT = Path(__file__).resolve().parent

DOCKER_ZAP_CMD = (
    "docker run -u zap -p 8080:8080 "
    "ghcr.io/zaproxy/zaproxy:stable zap.sh "
    "-daemon -host 0.0.0.0 -port 8080 "
    '-config api.addrs.addr.name=.* -config api.addrs.addr.regex=true'
)


# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

def check_url(url: str, label: str) -> bool:
    """Return True if url responds, False otherwise."""
    try:
        with urllib.request.urlopen(url, timeout=5):
            return True
    except Exception:
        return False


def preflight() -> bool:
    """Check ZAP and Flask app reachability. Returns True if both are up."""
    ok = True

    print(f"[*] Checking ZAP at {ZAP_API_URL} ...")
    if check_url(ZAP_API_URL, "ZAP"):
        print("    ZAP is reachable.")
    else:
        print(
            f"\n[!] Cannot reach ZAP at {ZAP_API_URL}.\n"
            "    Start ZAP with:\n\n"
            f"      {DOCKER_ZAP_CMD}\n"
        )
        ok = False

    flask_health_url = "http://127.0.0.1:5000"
    print(f"[*] Checking target app at {flask_health_url} ...")
    if check_url(flask_health_url, "Flask app"):
        print("    Flask app is reachable.")
    else:
        print(
            f"\n[!] Cannot reach the Flask app at {flask_health_url}.\n"
            "    Start it with:\n\n"
            "      python vulnerable_app/app.py\n"
        )
        ok = False

    return ok


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_scan_phase() -> list[dict]:
    """Connect to ZAP, spider, active scan, collect and save alerts."""
    zap = ZAPv2(proxies={"http": ZAP_API_URL, "https": ZAP_API_URL})

    try:
        version = zap.core.version
        print(f"[*] ZAP version: {version}")
    except Exception as e:
        print(f"[!] ZAP connection failed during scan: {e}")
        raise

    run_spider(zap, TARGET_URL)
    run_active_scan(zap, TARGET_URL)

    print("\n[*] Collecting alerts...")
    alerts = collect_alerts(zap, TARGET_URL)
    print(f"    {len(alerts)} alert(s) retrieved.")

    report_path = REPO_ROOT / REPORT_OUTPUT_PATH
    save_report(alerts, str(report_path))
    print_summary(alerts)

    return alerts


def run_analysis_phase() -> None:
    """Deduplicate alerts, send to Claude, save Markdown report."""
    report_path = REPO_ROOT / REPORT_OUTPUT_PATH

    alerts = load_alerts(report_path)
    deduped = deduplicate(alerts)
    print(f"\n[*] {len(deduped)} unique vulnerability type(s) after deduplication.")

    prompt = load_prompt(deduped)
    analysis = call_claude(prompt)
    save_analysis(analysis, DEFAULT_OUTPUT)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv(REPO_ROOT / ".env")

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[!] ANTHROPIC_API_KEY not set. Add it to your .env file.")
        raise SystemExit(1)

    print("\n" + "=" * 50)
    print("  AI Vulnerability Scanner — Full Pipeline")
    print("=" * 50 + "\n")

    # Pre-flight
    if not preflight():
        print("\n[!] Pre-flight checks failed. Fix the issues above and re-run.")
        raise SystemExit(1)

    pipeline_start = time.time()

    # --- Phase 1: Scan ---
    print("\n[Phase 1/2] Running ZAP scan...\n")
    scan_start = time.time()
    try:
        alerts = run_scan_phase()
    except Exception as e:
        print(f"\n[!] Scan failed: {e}")
        print("    Aborting — no data to analyse.")
        raise SystemExit(1)
    scan_elapsed = time.time() - scan_start

    # --- Phase 2: Analysis ---
    print("\n[Phase 2/2] Running AI analysis...\n")
    analysis_start = time.time()
    try:
        run_analysis_phase()
    except Exception as e:
        print(f"\n[!] Analysis failed: {e}")
        raise SystemExit(1)
    analysis_elapsed = time.time() - analysis_start

    total_elapsed = time.time() - pipeline_start

    # --- Final summary ---
    print("\n" + "=" * 50)
    print("  Pipeline Complete")
    print("=" * 50)
    print(f"  Vulnerabilities found : {len(alerts)}")
    print(f"  Report saved to       : {DEFAULT_OUTPUT}")
    print(f"  Scan time             : {scan_elapsed:.1f}s")
    print(f"  Analysis time         : {analysis_elapsed:.1f}s")
    print(f"  Total time            : {total_elapsed:.1f}s")
    print("=" * 50 + "\n")


if __name__ == "__main__":
    main()
