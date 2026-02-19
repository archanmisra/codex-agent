# Sample Secure MCP Server (Python)

This repository contains a starter MCP server implemented in Python, exposed over **Streamable HTTP** for agent integration.

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python server.py
```

## Running tests

```bash
pytest -q
```

## Bootstrap on Mac

If your GitHub clone is empty, run this from repo root:

```bash
bash scripts/bootstrap_mac.sh
```

Then push:

```bash
git add .
git commit -m "Bootstrap secure sample MCP server"
git push -u origin main
```
