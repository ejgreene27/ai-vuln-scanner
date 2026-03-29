"""
ZAP automated scanner — spiders and actively scans the target Flask app,
then saves all alerts as JSON and prints a risk-level summary.
"""

import json
import os
import time

from zapv2 import ZAPv2

from config import ZAP_API_URL, REPORT_OUTPUT_PATH, TARGET_URL


def wait_for_progress(poll_fn, label: str, interval: float = 2.0) -> None:
    """Poll poll_fn() until it returns 100, printing progress along the way."""
    while True:
        progress = int(poll_fn())
        print(f"  {label}: {progress}%", end="\r", flush=True)
        if progress >= 100:
            print(f"  {label}: 100% — done.      ")
            break
        time.sleep(interval)


def run_spider(zap: ZAPv2, target: str) -> None:
    print(f"\n[*] Starting spider on {target}")
    scan_id = zap.spider.scan(target)
    wait_for_progress(
        lambda: zap.spider.status(scan_id),
        label="Spider progress",
    )
    print(f"    URLs found: {len(zap.spider.results(scan_id))}")


def run_active_scan(zap: ZAPv2, target: str) -> None:
    print(f"\n[*] Starting active scan on {target}")
    scan_id = zap.ascan.scan(target)
    wait_for_progress(
        lambda: zap.ascan.status(scan_id),
        label="Active scan progress",
        interval=3.0,
    )


def collect_alerts(zap: ZAPv2, target: str) -> list[dict]:
    return zap.core.alerts(baseurl=target)


def save_report(alerts: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(alerts, f, indent=2)
    print(f"\n[*] Raw JSON report saved to: {path}")


def print_summary(alerts: list[dict]) -> None:
    risk_order = ["High", "Medium", "Low", "Informational"]
    counts: dict[str, int] = {r: 0 for r in risk_order}

    for alert in alerts:
        risk = alert.get("risk", "Informational")
        counts[risk] = counts.get(risk, 0) + 1

    print("\n" + "=" * 40)
    print(f"  SCAN COMPLETE — {len(alerts)} alert(s) found")
    print("=" * 40)
    for risk in risk_order:
        print(f"  {risk:<15} {counts[risk]}")
    print("=" * 40)


def main() -> None:
    print(f"[*] Connecting to ZAP at {ZAP_API_URL}")
    zap = ZAPv2(proxies={"http": ZAP_API_URL, "https": ZAP_API_URL})

    # Verify connection
    try:
        version = zap.core.version
        print(f"[*] ZAP version: {version}")
    except Exception as e:
        print(f"[!] Could not connect to ZAP: {e}")
        print("    Make sure ZAP is running and listening on", ZAP_API_URL)
        raise SystemExit(1)

    run_spider(zap, TARGET_URL)
    run_active_scan(zap, TARGET_URL)

    print("\n[*] Collecting alerts...")
    alerts = collect_alerts(zap, TARGET_URL)
    print(f"    {len(alerts)} alert(s) retrieved.")

    save_report(alerts, REPORT_OUTPUT_PATH)
    print_summary(alerts)


if __name__ == "__main__":
    main()
