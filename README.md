# Week 8: Vulnerable Bookstore, scanned and fixed

Starter: intentionally vulnerable FastAPI bookstore (see the planted-issue list in `main.py`). This repo contains the fixes, scans and evidence; the story is in [`writeup.md`](writeup.md).

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
pytest                                               # 9 tests
semgrep scan --metrics=off --config p/default --config semgrep-local/rules.yml .   # 0 findings
pip-audit -r requirements.txt                        # no known vulnerabilities
python docs/injection_demo.py                        # needs Ollama + llama3.1:8b
```
Configuration (environment, never committed): see `.env.example`.
