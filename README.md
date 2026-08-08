# agentic-security-canary

Maintained by: codex-daily-routine

A deterministic canary framework for analyzing risky tool-use traces from AI agents. It
models concrete failure modes such as secret exfiltration, unsafe shell commands, network
egress and privilege escalation, then produces a containment score that can be tracked in
CI or firmware-validation labs.

## Quickstart

```powershell
pip install -r requirements-dev.txt
pip install -e .
python -m pytest -q
python -m agentic_security_canary
```

## Status

MVP: tool-call trace model, deterministic risk rules, policy gating, containment score and
tests. Next steps: add fixtures for firmware validation agents and local MCP-style tool
servers.

## License

MIT - see [LICENSE](LICENSE).
