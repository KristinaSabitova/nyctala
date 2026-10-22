# nyctala

Lightweight SIEM focused on detection engineering:

- **Detection-as-code**: Sigma rules in git, each with positive and negative tests.
- **Measured coverage**: an ATT&CK technique counts only when it has a rule with passing tests.
- **Explainable alerts**: every alert shows the events that caused it, its ATT&CK technique and the accumulated entity risk.
- **Offline-first**: no external telemetry, secrets redacted by default.

> Status: early development (pre-MVP). Nothing usable yet.

## Deployment

See [deploy/README.md](deploy/README.md): a dedicated, hardened VPS; sensors push logs over WireGuard.

## License

MIT
