# AI-Powered Vulnerability Scanner

A security research tool that automates web application vulnerability scanning using OWASP ZAP and leverages the Claude AI API to analyze findings, assess risk, and generate detailed remediation reports — all from a single command.

---

## Features

- **Automated scanning** — spiders and actively attacks a target application using OWASP ZAP
- **AI-powered analysis** — sends deduplicated findings to Claude for plain-language risk assessment
- **Smart deduplication** — groups repeated ZAP alerts by vulnerability type and severity
- **Actionable remediation** — generates a structured Markdown report with code-level fix examples
- **Single-command pipeline** — one script handles pre-flight checks, scanning, analysis, and reporting
- **Flexible CLI** — control scan depth, output path, and AI analysis via command-line flags

---

## Architecture

```
┌─────────────────────┐
│  Vulnerable Flask   │
│       App           │  ← intentional target running on localhost:5000
└────────┬────────────┘
         │ HTTP
         ▼
┌─────────────────────┐
│    OWASP ZAP        │  ← runs in Docker, spiders + actively scans
│  (Docker container) │
└────────┬────────────┘
         │ ZAP API
         ▼
┌─────────────────────┐
│  Python Orchestrator│  ← run_pipeline.py coordinates all phases
│  (run_pipeline.py)  │
└────────┬────────────┘
         │ Anthropic API
         ▼
┌─────────────────────┐
│    Claude AI        │  ← analyzes findings, writes remediation report
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Markdown Report    │  ← reports/ai_analysis.md
│  (ai_analysis.md)   │
└─────────────────────┘
```

---

## Prerequisites

- Python 3.10+
- Docker
- An [Anthropic API key](https://console.anthropic.com/)

---

## Setup & Usage

**1. Clone the repository**

```bash
git clone https://github.com/your-username/ai-vuln-scanner.git
cd ai-vuln-scanner
```

**2. Install dependencies**

```bash
pip install -r requirements.txt
```

**3. Configure your API key**

Create a `.env` file in the project root:

```bash
echo "ANTHROPIC_API_KEY=your-api-key-here" > .env
```

**4. Start the target Flask app**

```bash
python vulnerable_app/app.py
```

The app will be available at `http://localhost:5000`.

**5. Start OWASP ZAP via Docker**

```bash
docker run -u zap -p 8080:8080 \
  ghcr.io/zaproxy/zaproxy:stable zap.sh \
  -daemon -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* \
  -config api.addrs.addr.regex=true
```

**6. Run the full pipeline**

```bash
python run_pipeline.py
```

The script will verify ZAP and the Flask app are reachable, run the scan, send findings to Claude, and save the report to `reports/ai_analysis.md`.

---

## Project Structure

```
ai-vuln-scanner/
├── cli.py                   # CLI entry point (Phase 5) — use this for flexible scanning
├── run_pipeline.py          # Automated pipeline entry point — runs the full workflow
│
├── vulnerable_app/          # Intentionally vulnerable Flask app (scan target)
│   ├── app.py               # Routes with SQLi, XSS, and command injection
│   └── templates/           # HTML templates with warning banners
│
├── scanner/                 # ZAP scanning module
│   ├── config.py            # ZAP URL, target URL, report output path
│   └── run_scan.py          # Spider, active scan, alert collection
│
├── analysis/                # AI analysis module
│   ├── analyze.py           # Deduplication, Claude API call, report saving
│   └── prompts/
│       └── vuln_analysis.txt  # Prompt template (edit to tune AI output)
│
└── reports/                 # Scan output and generated reports
    ├── sample_scan_output.json   # Example raw ZAP output (tracked in git)
    └── sample_ai_analysis.md     # Example Claude-generated report (tracked in git)
```

---

## Sample Output

Example files are included in the `reports/` directory so you can see what the tool produces without running a full scan:

- `reports/sample_scan_output.json` — raw ZAP alert data
- `reports/sample_ai_analysis.md` — the AI-generated security report

Live scan output is written to `reports/raw_scan_output.json` and `reports/ai_analysis.md`, which are excluded from version control.

---

## Built With

| Tool | Purpose |
|---|---|
| Python | Core scripting and orchestration |
| Flask | Vulnerable target application |
| OWASP ZAP | Automated web vulnerability scanner |
| Claude API (Anthropic) | AI-powered findings analysis |
| Docker | ZAP runtime environment |

---

## Phase 5: CLI Interface

`cli.py` exposes a flexible command-line interface for running scans with different options — without touching any config files.

### Arguments

| Flag | Default | Description |
|---|---|---|
| `--target URL` | `http://127.0.0.1:5000` | Target application URL |
| `--scan-type` | `quick` | `quick` (spider only) or `full` (spider + active scan) |
| `--output FILE` | `results/scan_output.json` | Path to save raw JSON results |
| `--ai-analyze` | off | Send findings to Claude AI for analysis |
| `--verbose` | off | Print extra detail during the scan |

### Usage Examples

```bash
# Quick scan of the local Flask app (default behavior)
python cli.py

# Full spider + active scan
python cli.py --scan-type full

# Quick scan with AI analysis
python cli.py --ai-analyze

# Full scan with AI analysis and verbose output
python cli.py --scan-type full --ai-analyze --verbose

# Scan a custom target and save output to a specific path
python cli.py --target http://192.168.1.10:8080 --output results/custom_scan.json

# Save to a custom path and generate an AI report alongside it
python cli.py --output results/my_scan.json --ai-analyze
```

### Help Output

```
$ python cli.py --help

usage: cli.py [-h] [--target URL] [--scan-type {quick,full}] [--output FILE]
              [--ai-analyze] [--verbose]

AI-Powered Vulnerability Scanner
Scan a web application with OWASP ZAP and optionally analyze
findings with Claude AI to generate a remediation report.

options:
  -h, --help            show this help message and exit
  --target URL          URL of the target application to scan
                        (default: http://127.0.0.1:5000)
  --scan-type {quick,full}
                        Scan depth: 'quick' runs the spider only;
                        'full' runs the spider then an active attack scan
                        (default: quick)
  --output FILE         File path for the raw JSON scan results
                        (default: results/scan_output.json)
  --ai-analyze          Send findings to Claude AI for analysis and generate
                        a Markdown remediation report. Requires
                        ANTHROPIC_API_KEY in .env (default: off)
  --verbose             Print additional detail during the scan

examples:
  python cli.py
  python cli.py --scan-type full
  python cli.py --ai-analyze
  python cli.py --target http://192.168.1.10:8080 --scan-type full
  python cli.py --scan-type full --ai-analyze --verbose
  python cli.py --output results/my_scan.json --ai-analyze
```

> **Note:** The AI report is saved alongside the JSON output with an `_ai_analysis.md` suffix.
> For example, `--output results/my_scan.json` generates `results/my_scan_ai_analysis.md`.

---

## Disclaimer

The `vulnerable_app/` included in this repository is **intentionally insecure** — it contains SQL injection, cross-site scripting, and OS command injection vulnerabilities by design. It exists solely as a controlled scan target for demonstrating this tool.

**Do not deploy it to any real network or internet-accessible environment.**
