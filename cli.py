"""
cli.py — Command-line interface for the AI-Powered Vulnerability Scanner.

Usage:
    python cli.py                                      # quick scan, no AI analysis
    python cli.py --scan-type full                     # spider + active scan
    python cli.py --ai-analyze                         # quick scan + single-model analysis
    python cli.py --compare                            # quick scan + multi-model comparison
    python cli.py --target http://192.168.1.10:8080    # custom target
    python cli.py --scan-type full --compare --verbose
"""

import argparse
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from zapv2 import ZAPv2

from scanner.config import ZAP_API_URL
from scanner.run_scan import (
    collect_alerts,
    print_summary,
    run_active_scan,
    run_spider,
    save_report,
)
from analysis.analyze import (
    call_claude,
    deduplicate,
    load_alerts,
    load_prompt,
    save_report as save_analysis,
)
from multi_model import compare_models, save_comparison, print_comparison_summary

REPO_ROOT = Path(__file__).resolve().parent

DOCKER_START_CMD = (
    "  docker run -u zap -p 8080:8080 \\\n"
    "    ghcr.io/zaproxy/zaproxy:stable zap.sh \\\n"
    "    -daemon -host 0.0.0.0 -port 8080 \\\n"
    "    -config api.addrs.addr.name=.* \\\n"
    "    -config api.addrs.addr.regex=true"
)


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description=(
            "AI-Powered Vulnerability Scanner\n"
            "Scan a web application with OWASP ZAP and optionally analyze\n"
            "findings with Claude AI to generate a remediation report."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python cli.py\n"
            "  python cli.py --scan-type full\n"
            "  python cli.py --ai-analyze\n"
            "  python cli.py --compare\n"
            "  python cli.py --target http://192.168.1.10:8080 --scan-type full\n"
            "  python cli.py --scan-type full --compare --verbose\n"
            "  python cli.py --output results/my_scan.json --compare"
        ),
    )

    parser.add_argument(
        "--target",
        default="http://127.0.0.1:5000",
        metavar="URL",
        help="URL of the target application to scan (default: http://127.0.0.1:5000)",
    )
    parser.add_argument(
        "--scan-type",
        choices=["quick", "full"],
        default="quick",
        dest="scan_type",
        help=(
            "Scan depth: 'quick' runs the spider only; "
            "'full' runs the spider then an active attack scan (default: quick)"
        ),
    )
    parser.add_argument(
        "--output",
        default="results/scan_output.json",
        metavar="FILE",
        help="File path for the raw JSON scan results (default: results/scan_output.json)",
    )
    parser.add_argument(
        "--ai-analyze",
        action="store_true",
        dest="ai_analyze",
        help=(
            "Send findings to Claude AI for analysis and generate a Markdown "
            "remediation report. Requires ANTHROPIC_API_KEY in .env (default: off)"
        ),
    )
    parser.add_argument(
        "--compare",
        action="store_true",
        help=(
            "Send findings to multiple Claude models (Sonnet and Haiku) and "
            "generate a side-by-side comparison report. "
            "Requires ANTHROPIC_API_KEY in .env (default: off)"
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print additional detail during the scan (ZAP version, target remapping, etc.)",
    )

    return parser


# ---------------------------------------------------------------------------
# Scan helpers
# ---------------------------------------------------------------------------

def connect_to_zap(verbose: bool) -> ZAPv2:
    """Connect to the ZAP API and verify it is responsive."""
    print(f"[*] Connecting to ZAP at {ZAP_API_URL} ...")
    zap = ZAPv2(proxies={"http": ZAP_API_URL, "https": ZAP_API_URL})

    try:
        version = zap.core.version
        print(f"    ZAP connected. {'Version: ' + version if verbose else 'OK'}")
    except Exception as e:
        print(f"\n[!] Cannot connect to ZAP: {e}")
        print(f"    Start ZAP with Docker:\n\n{DOCKER_START_CMD}\n")
        raise SystemExit(1)

    return zap


def remap_for_docker(target: str) -> str:
    """
    ZAP runs inside Docker and cannot reach the host via 127.0.0.1 or localhost.
    Remap those to host.docker.internal so ZAP can reach the Flask app.
    """
    return (
        target
        .replace("127.0.0.1", "host.docker.internal")
        .replace("localhost", "host.docker.internal")
    )


def run_scan(
    zap: ZAPv2,
    target: str,
    scan_type: str,
    output: str,
    verbose: bool,
) -> list[dict]:
    """Spider the target (and run an active scan if scan_type is 'full')."""
    zap_target = remap_for_docker(target)

    if verbose:
        print(f"    User-facing target : {target}")
        print(f"    ZAP target (Docker): {zap_target}")

    # Spider — always runs
    run_spider(zap, zap_target)

    # Active scan — full mode only
    if scan_type == "full":
        run_active_scan(zap, zap_target)
    else:
        print("\n[*] Scan type is 'quick' — skipping active attack scan.")

    print("\n[*] Collecting alerts ...")
    alerts = collect_alerts(zap, zap_target)
    print(f"    {len(alerts)} alert(s) retrieved.")

    save_report(alerts, output)
    print_summary(alerts)

    return alerts


# ---------------------------------------------------------------------------
# AI analysis helper
# ---------------------------------------------------------------------------

def run_ai_analysis(input_path: Path, verbose: bool) -> Path:
    """Deduplicate alerts, call Claude, and save the Markdown report."""
    if not os.getenv("ANTHROPIC_API_KEY"):
        print("\n[!] ANTHROPIC_API_KEY is not set. Add it to your .env file.")
        raise SystemExit(1)

    print("\n[*] Running AI analysis ...")

    alerts = load_alerts(input_path)
    deduped = deduplicate(alerts)

    if verbose:
        print(f"    {len(alerts)} raw alert(s) deduplicated to {len(deduped)} unique type(s).")
    else:
        print(f"    {len(deduped)} unique vulnerability type(s) identified.")

    prompt = load_prompt(deduped)
    analysis = call_claude(prompt)

    # Place the Markdown report alongside the JSON output
    report_path = input_path.with_name(input_path.stem + "_ai_analysis.md")
    save_analysis(analysis, report_path)

    return report_path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv(REPO_ROOT / ".env")

    parser = build_parser()
    args = parser.parse_args()

    output_path = Path(args.output)

    # Determine which AI mode is active for the config banner
    if args.compare:
        ai_mode = "multi-model comparison"
    elif args.ai_analyze:
        ai_mode = "single-model (Sonnet)"
    else:
        ai_mode = "disabled"

    # Print run configuration
    print("\n" + "=" * 52)
    print("  AI-Powered Vulnerability Scanner")
    print("=" * 52)
    print(f"  Target      : {args.target}")
    print(f"  Scan type   : {args.scan_type}")
    print(f"  Output      : {args.output}")
    print(f"  AI analysis : {ai_mode}")
    if args.verbose:
        print(f"  ZAP API     : {ZAP_API_URL}")
        print(f"  Verbose     : on")
    print("=" * 52 + "\n")

    start_time = time.time()

    # Phase 1: Scan
    zap = connect_to_zap(args.verbose)
    alerts = run_scan(zap, args.target, args.scan_type, str(output_path), args.verbose)

    # Phase 2: AI analysis — single-model (optional)
    report_path = None
    if args.ai_analyze:
        report_path = run_ai_analysis(output_path, args.verbose)

    # Phase 2 (alt): multi-model comparison (optional, mutually exclusive with --ai-analyze)
    comparison_path = None
    if args.compare:
        if not os.getenv("ANTHROPIC_API_KEY"):
            print("\n[!] ANTHROPIC_API_KEY is not set. Add it to your .env file.")
            raise SystemExit(1)

        print("\n[*] Running multi-model comparison ...")
        comparison = compare_models(output_path, verbose=args.verbose)
        comparison_path = output_path.with_name(output_path.stem + "_comparison.json")
        save_comparison(comparison, comparison_path)
        print_comparison_summary(comparison)

    # Final summary
    elapsed = time.time() - start_time
    print("\n" + "=" * 52)
    print("  Complete")
    print("=" * 52)
    print(f"  Alerts found : {len(alerts)}")
    print(f"  Raw output   : {output_path}")
    if report_path:
        print(f"  AI report    : {report_path}")
    if comparison_path:
        print(f"  Comparison   : {comparison_path}")
    print(f"  Time elapsed : {elapsed:.1f}s")
    print("=" * 52 + "\n")


if __name__ == "__main__":
    main()
