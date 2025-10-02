

## Malware Sandbox

This repository contains a small, rule-based phishing email detector implemented in `phishing_detector.py`.

Usage
-----

1. Create a virtualenv and install dependencies from `requirements.txt`.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run the CLI against a text file containing the email body:

```bash
python phishing_detector.py email.txt --threshold 0.5
```

3. Run tests:

```bash
pytest -q
```

Notes
-----
- This is intentionally simple and rule-based for educational/demo purposes. For production use, prefer ML models or more comprehensive heuristics, and ensure privacy and legal compliance when analyzing email content.
