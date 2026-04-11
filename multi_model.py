"""
multi_model.py — Multi-model AI comparison for the AI-Powered Vulnerability Scanner.

Sends the same deduplicated ZAP findings to multiple Claude models and captures
each model's analysis alongside performance metadata (response time, token usage)
so analysts can evaluate quality vs. cost tradeoffs.

Usage (standalone):
    python multi_model.py results/scan_output.json
    python multi_model.py results/scan_output.json --verbose

Typically invoked via cli.py with the --compare flag.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import anthropic
from dotenv import load_dotenv

from analysis.analyze import load_alerts, deduplicate, load_prompt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Models included in the comparison — add or remove entries here to change the set.
MODELS = [
    {
        "id": "claude-sonnet-4-0",
        "display_name": "Claude Sonnet",
    },
    {
        "id": "claude-haiku-4-5-20251001",
        "display_name": "Claude Haiku",
    },
]

# Max tokens to request from each model.
MAX_TOKENS = 8096

REPO_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Core: single-model call
# ---------------------------------------------------------------------------

def call_model(client: anthropic.Anthropic, prompt: str, model_id: str) -> dict:
    """
    Send prompt to a single model and return a result dict containing:
      - model       : model ID string
      - analysis    : full text response
      - response_time_s : wall-clock seconds for the API call
      - input_tokens  : tokens consumed by the prompt
      - output_tokens : tokens generated in the response
      - total_tokens  : sum of input + output
    """
    start = time.time()

    response = client.messages.create(
        model=model_id,
        max_tokens=MAX_TOKENS,
        messages=[{"role": "user", "content": prompt}],
    )

    elapsed = time.time() - start

    # Extract the text from the first content block.
    analysis = next(
        block.text for block in response.content if block.type == "text"
    )

    return {
        "model": model_id,
        "analysis": analysis,
        "response_time_s": round(elapsed, 2),
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
        "total_tokens": response.usage.input_tokens + response.usage.output_tokens,
    }


# ---------------------------------------------------------------------------
# Orchestration: run all models against the same findings
# ---------------------------------------------------------------------------

def compare_models(scan_path: Path, verbose: bool = False) -> dict:
    """
    Load findings from scan_path, deduplicate them, build the shared prompt,
    then send it to each model in MODELS. Returns a structured comparison dict.
    """
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from environment

    # Load and deduplicate findings
    alerts = load_alerts(scan_path)
    deduped = deduplicate(alerts)

    if verbose:
        print(f"    {len(alerts)} raw alert(s) deduplicated to {len(deduped)} unique type(s).")
    else:
        print(f"    {len(deduped)} unique vulnerability type(s) identified.")

    # Build the prompt once — all models receive identical input
    prompt = load_prompt(deduped)

    # Run each model sequentially
    results = []
    for model_cfg in MODELS:
        model_id = model_cfg["id"]
        display = model_cfg["display_name"]
        print(f"\n[*] Querying {display} ({model_id}) ...")

        result = call_model(client, prompt, model_id)
        result["display_name"] = display  # attach friendly label for reporting

        print(
            f"    Done — {result['response_time_s']}s | "
            f"{result['input_tokens']:,} in / {result['output_tokens']:,} out tokens"
        )

        results.append(result)

    # Build the comparison object
    comparison = {
        "scan_file": str(scan_path),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings_count": len(deduped),
        "models": results,
    }

    return comparison


# ---------------------------------------------------------------------------
# Output: save JSON and print terminal summary
# ---------------------------------------------------------------------------

def save_comparison(comparison: dict, output_path: Path) -> None:
    """Write the full comparison dict to a JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(comparison, indent=2))
    print(f"\n[*] Comparison saved to: {output_path}")


def print_comparison_summary(comparison: dict) -> None:
    """Print a formatted terminal summary of the multi-model comparison."""
    models = comparison["models"]

    # Column widths
    col_model = 28
    col_time = 14
    col_in = 12
    col_out = 13
    col_total = 12

    divider = "=" * 62
    row_sep = "-" * 62

    print("\n" + divider)
    print("  Multi-Model Comparison Summary")
    print(divider)
    print(f"  Findings analyzed : {comparison['findings_count']} unique vulnerability type(s)")
    print(f"  Timestamp         : {comparison['timestamp']}")
    print()

    # Header row
    print(
        f"  {'Model':<{col_model}} {'Time':>{col_time}} "
        f"{'In Tokens':>{col_in}} {'Out Tokens':>{col_out}} {'Total':>{col_total}}"
    )
    print("  " + row_sep)

    # Data rows
    for m in models:
        label = f"{m['display_name']} ({m['model']})"
        # Truncate long labels so the table stays readable
        if len(label) > col_model - 1:
            label = label[: col_model - 4] + "..."
        print(
            f"  {label:<{col_model}} "
            f"{m['response_time_s']:>{col_time - 1}.1f}s "
            f"{m['input_tokens']:>{col_in},} "
            f"{m['output_tokens']:>{col_out},} "
            f"{m['total_tokens']:>{col_total},}"
        )

    # Speed and token comparison (only when exactly two models are present)
    if len(models) == 2:
        m0, m1 = models[0], models[1]
        print()

        # Speed comparison
        if m0["response_time_s"] > 0 and m1["response_time_s"] > 0:
            faster, slower = (
                (m1, m0) if m1["response_time_s"] < m0["response_time_s"] else (m0, m1)
            )
            ratio = slower["response_time_s"] / faster["response_time_s"]
            print(
                f"  Speed advantage  : {faster['display_name']} was "
                f"{ratio:.1f}x faster ({faster['response_time_s']}s vs {slower['response_time_s']}s)"
            )

        # Output token comparison
        delta = m0["output_tokens"] - m1["output_tokens"]
        pct = abs(delta) / max(m0["output_tokens"], 1) * 100
        if delta > 0:
            print(
                f"  Output tokens    : {m1['display_name']} used "
                f"{abs(delta):,} fewer tokens (−{pct:.0f}%)"
            )
        elif delta < 0:
            print(
                f"  Output tokens    : {m0['display_name']} used "
                f"{abs(delta):,} fewer tokens (−{pct:.0f}%)"
            )
        else:
            print("  Output tokens    : Both models used identical token counts")

    print(divider + "\n")


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main() -> None:
    load_dotenv(REPO_ROOT / ".env")

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("[!] ANTHROPIC_API_KEY not set. Add it to your .env file.")
        raise SystemExit(1)

    if len(sys.argv) < 2:
        print("Usage: python multi_model.py <scan_results.json> [--verbose]")
        raise SystemExit(1)

    scan_path = Path(sys.argv[1])
    verbose = "--verbose" in sys.argv

    if not scan_path.exists():
        print(f"[!] Scan file not found: {scan_path}")
        raise SystemExit(1)

    print(f"\n[*] Loading scan results from: {scan_path}")

    comparison = compare_models(scan_path, verbose=verbose)

    # Save alongside the input file
    output_path = scan_path.with_name(scan_path.stem + "_comparison.json")
    save_comparison(comparison, output_path)

    print_comparison_summary(comparison)


if __name__ == "__main__":
    main()
