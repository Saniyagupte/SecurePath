# SecurePath — Security Intelligence, Not Just Alerts

> Turns vulnerabilities into auditor-accepted SOC2 compliance evidence.

SecurePath is built for engineering teams approaching SOC2 Type II who need more than scanner output. It converts vulnerability discovery, triage context, remediation guidance, and human approval evidence into a report format an auditor can review directly.

## Setup in 3 commands

```bash
git clone https://github.com/yourusername/securepath
cd securepath
cp .env.example .env  # add your GROQ_API_KEY
pip install -r requirements.txt && python app.py
```

Open `http://localhost:5000` and scan:

```text
https://github.com/juice-shop/juice-shop
```

## Or with Docker

```bash
docker build -t securepath .
docker run -e GROQ_API_KEY=your_key -e EXAI_PROVIDER=groq -p 5000:5000 securepath
```

Then open:

```text
http://localhost:5000
```

## What it does

SecurePath executes a 5-pass security analysis tailored for Node.js / Express / Angular repositories:

1. SAST with Semgrep (`p/nodejs`, `p/owasp-top-ten`, `p/secrets`, `p/javascript`)
2. Dependency risk detection via `npm audit --json` + manual vulnerable-version checks
3. Secret and credential pattern detection across repo files
4. Structural/logic analysis for injection, auth, redirect, CORS, and execution risks
5. Config and hygiene audit (`.env`, `.gitignore`, weak secret defaults, risky scripts)

Each finding is enriched with EXAI:

- Plain-English impact
- Business risk
- Exploit scenario
- Three ranked remediation options with tradeoffs
- SOC2 control mapping, confidence score, and false-positive risk reasoning

## Output

SecurePath generates:

- Progressive live dashboard of enriched findings
- Repository commit traceability
- SHA-256 integrity hash over findings payload
- Auditor-ready PDF evidence report in `reports/`

## Requirements

- Python 3.11+
- Git
- Node.js + npm (required for dependency audit pass)
- Public GitHub repository URL to scan
- Groq API key (`GROQ_API_KEY`) for high/critical enrichment

## Environment

Create `.env` from `.env.example` and set:

```env
GROQ_API_KEY=your_groq_key_here
EXAI_PROVIDER=groq
EXAI_MODEL=llama-3.3-70b-versatile
```

## Notes

- Semgrep is included in `requirements.txt`, and scanner runtime includes an install check fallback.
- The scanner clones repositories to a temporary path and removes them after scan completion.
- Findings are persisted in SQLite (`securepath.db`) for scan history and report reproducibility.

