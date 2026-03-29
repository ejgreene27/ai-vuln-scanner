"""
Loads raw ZAP scan output, deduplicates findings, sends them to the Claude API
for analysis, and saves the resulting report to reports/ai_analysis.md.
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import anthropic
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = REPO_ROOT / "reports" / "raw_scan_output.json"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "ai_analysis.md"
PROMPT_TEMPLATE = Path(__file__).resolve().parent / "prompts" / "vuln_analysis.txt"

MODEL = "claude-sonnet-4-0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_alerts(path: Path) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def deduplicate(alerts: list[dict]) -> list[dict]:
    """
    Group alerts by name. Each entry in the result has:
      - alert, risk, description, solution, reference
      - urls: sorted list of unique affected URLs
    """
    grouped: dict[str, dict] = {}

    for alert in alerts:
        name = alert.get("alert", "Unknown")
        url = alert.get("url", "")

        if name not in grouped:
            grouped[name] = {
                "alert": name,
                "risk": alert.get("risk", ""),
                "description": alert.get("description", ""),
                "solution": alert.get("solution", ""),
                "reference": alert.get("reference", ""),
                "urls": set(),
            }

        if url:
            grouped[name]["urls"].add(url)

    # Convert url sets to sorted lists for JSON serialisation
    result = []
    for entry in grouped.values():
        entry["urls"] = sorted(entry["urls"])
        result.append(entry)

    # Sort by risk level (High first)
    risk_order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    result.sort(key=lambda x: risk_order.get(x["risk"], 99))

    return result


def load_prompt(findings: list[dict]) -> str:
    template = PROMPT_TEMPLATE.read_text()
    findings_json = json.dumps(findings, indent=2)
    return template.replace("{findings}", findings_json)


def call_claude(prompt: str) -> str:
    """Stream a request to Claude and return the complete response text."""
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    print(f"[*] Sending findings to Claude ({MODEL})...")

    with client.messages.stream(
        model=MODEL,
        max_tokens=8096,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        # Print a simple progress indicator while streaming
        for _ in stream.text_stream:
            print(".", end="", flush=True)

        final = stream.get_final_message()

    print()  # newline after dots
    return next(
        block.text for block in final.content if block.type == "text"
    )


def save_report(text: str, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    print(f"[*] AI analysis saved to: {path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv(REPO_ROOT / ".env")

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[!] ANTHROPIC_API_KEY not set. Add it to your .env file.")
        raise SystemExit(1)

    # Accept an optional path argument
    input_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_INPUT

    if not input_path.exists():
        print(f"[!] Input file not found: {input_path}")
        raise SystemExit(1)

    print(f"[*] Loading alerts from: {input_path}")
    alerts = load_alerts(input_path)
    print(f"    {len(alerts)} raw alert(s) loaded.")

    deduped = deduplicate(alerts)
    print(f"    {len(deduped)} unique vulnerability type(s) after deduplication.")

    prompt = load_prompt(deduped)
    analysis = call_claude(prompt)

    save_report(analysis, DEFAULT_OUTPUT)
    print("[*] Done.")


if __name__ == "__main__":
    main()
