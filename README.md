# agentic-security-canary

Maintained by: codex-daily-routine

A deterministic canary framework for analyzing risky tool-use traces from AI agents. It
models concrete failure modes such as secret exfiltration, unsafe shell commands, network
egress and privilege escalation, then produces a containment score that can be tracked in
CI or firmware-validation labs.

## Research + Money Thesis

As agentic systems become more capable, validation cost shifts from "does it answer?" to
"does it stay inside the operating envelope?" The money question is whether organizations
can cheaply catch tool-use risk before it reaches production infrastructure, private repos
or hardware labs. This project is a small, auditable test harness for that question.

## Quickstart

```powershell
pip install -r requirements-dev.txt
pip install -e .
python -m pytest -q
python -m agentic_security_canary
```

## Silicon Valley Interview Hook

The `evaluate_trace()` API turns raw canary findings into a policy decision with severity,
violations and residual risk. That maps directly onto the platform question companies ask
before giving agents shell, repository, network or lab-control tools: did the agent stay
inside the operating envelope?

## Status

MVP: tool-call trace model, deterministic risk rules, policy gating, containment score and
tests. Next steps: add fixtures for firmware validation agents and local MCP-style tool
servers.

## License

MIT - see [LICENSE](LICENSE).
