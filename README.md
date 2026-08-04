# Sleuth

**High-performance Python-native secrets & API key scanner**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)

Sleuth finds hardcoded secrets, API keys, tokens, private keys and high-entropy strings in your codebase fast, accurately, and with beautiful output.

Inspired by Gitleaks and TruffleHog, but written in pure Python with a focus on developer experience, entropy analysis, and first-class SARIF support for GitHub Code Scanning.

---

## Features

- **30+ high-quality built-in rules** covering:
  - AWS (Access Key ID, Secret Key, MWS)
  - GitHub (PAT, OAuth, App, Fine-grained, Refresh)
  - Slack, Stripe, Google, Twilio, Telegram
  - Private keys (RSA, SSH, EC, PGP)
  - JWT, npm, PyPI, Heroku, Mailchimp, Square, PayPal, etc.
- **Shannon entropy detection** for unknown / generic secrets
- **Blazing fast** multi-threaded scanning
- **Beautiful terminal UI** with severity coloring and context
- **JSON + SARIF 2.1.0** reports (ready for GitHub Advanced Security)
- **CI-friendly** — proper exit codes (`1` when CRITICAL/HIGH findings exist)
- Skips binaries, large files, and common junk directories (`.git`, `node_modules`, `venv`, etc.)
- Configurable entropy threshold, threads, max file size

---

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sleuth.git
cd sleuth

# Install dependencies
pip install -r requirements.txt

# Optional: install as a package
pip install -e .
```

Or run directly:

```bash
python -m sleuth --help
```

---

## Quick Start

```bash
# Scan current directory
python -m sleuth scan .

# Scan a specific path
python -m sleuth scan ./src

# Verbose mode (show context)
python -m sleuth scan . -v

# Generate JSON report
python -m sleuth scan . -o report.json

# Generate SARIF for GitHub Code Scanning
python -m sleuth scan . --sarif results.sarif

# Quiet mode (CI)
python -m sleuth scan . --quiet
echo $?   # 1 if CRITICAL/HIGH secrets found

# List all rules
python -m sleuth rules
```

---

## Example Output

```
Sleuth v1.0.0 — scanning ./example-project ...

╭───────────────────────── Sleuth Results ─────────────────────────╮
│ Found 3 potential secret(s)                                      │
│   CRITICAL : 2                                                   │
│   HIGH     : 1                                                   │
│                                                                  │
│ Scanned: ./example-project                                       │
╰──────────────────────────────────────────────────────────────────╯

┌──────────┬─────────────────────┬──────────────────────────────┬────────────────────────────┐
│ Severity │ Rule                │ File:Line                    │ Match / Entropy            │
├──────────┼─────────────────────┼──────────────────────────────┼────────────────────────────┤
│ CRITICAL │ aws-access-key-id   │ config.py:12                 │ AKIA...  (entropy=4.82)    │
│ CRITICAL │ github-pat          │ .env:3                       │ ghp_xxxxxxxxxxxx...        │
│ HIGH     │ generic-api-key     │ settings.py:45               │ sk_live_... (entropy=4.91) │
└──────────┴─────────────────────┴──────────────────────────────┴────────────────────────────┘
```

---

## SARIF + GitHub Code Scanning

Sleuth produces valid **SARIF 2.1.0**. You can upload it directly:

```yaml
# .github/workflows/secrets.yml
name: Secret Scan
on: [push, pull_request]

jobs:
  sleuth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt
      - run: python -m sleuth scan . --sarif results.sarif --quiet || true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Configuration Options

| Flag | Description | Default |
|------|-------------|---------|
| `--entropy / --no-entropy` | Enable/disable high-entropy detection | `True` |
| `--entropy-threshold` | Minimum Shannon entropy | `4.5` |
| `-t, --threads` | Concurrent workers | `8` |
| `--max-size` | Max file size in MB | `2` |
| `-v, --verbose` | Show context lines | `False` |
| `-q, --quiet` | Minimal output (CI) | `False` |
| `-o, --output` | JSON report path | — |
| `--sarif` | SARIF report path | — |

---

## Why Sleuth?

| Feature | Sleuth | Gitleaks | TruffleHog |
|---------|--------|----------|------------|
| Language | Pure Python | Go | Go |
| Entropy detection | Yes | Yes | Yes |
| SARIF output | Yes | Yes | Limited |
| Beautiful CLI | Yes (rich) | Basic | Basic |
| Easy to extend | Very | Medium | Medium |
| Install size | Tiny | Medium | Large |

---

## Extending Rules

You can add custom rules via YAML (coming in next release) or by editing `sleuth/rules.py`.

Example rule structure:

```python
Rule(
    id="my-custom-token",
    description="My Service Token",
    regex=r"my_[A-Za-z0-9]{32}",
    severity="HIGH",
    tags=["custom"],
)
```

---

## Performance

Sleuth is designed for speed:

- Concurrent file scanning
- Keyword pre-filtering before expensive regex
- Smart binary / large file skipping
- Efficient entropy calculation

Typical scan of a medium codebase (10k files) finishes in a few seconds on modern hardware.

---

## License

MIT License — free for personal and commercial use.

---

## Roadmap

- [ ] Custom rules via YAML config
- [ ] Git history scanning (`git log -p`)
- [ ] Allowlist / baseline support
- [ ] HTML report
- [ ] Pre-commit hook integration
- [ ] Docker image

---

Made with care for the security community.
```
