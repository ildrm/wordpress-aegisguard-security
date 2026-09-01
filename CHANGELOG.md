# Changelog

## 1.0.1 — 2026-09-01

- Fixed activation-time audit-chain key ordering and serialized writes, verification, and retention pruning.
- Prevented TOTP replay and concurrent recovery-code reuse.
- Preserved IP-wide abuse counters across successful logins.
- Hardened encoded-traversal detection, large-upload inspection, and quarantine path handling.
- Reduced verified WordPress core and development-dependency scanner false positives.
- Added integration regressions, reproducible tooling, packaging rules, and CI checks.

## 1.0.0 — 2026-08-31

- Initial release.
- Local application WAF and temporary blocking.
- Login rate limiting and bot honeypot.
- TOTP MFA with dedicated per-site secret encryption and one-use recovery codes.
- Core checksum, malware, database, persistence, and integrity scanning.
- Upload protection and WordPress hardening controls.
- Tamper-evident events and incident correlation.
- Emergency lockdown and authenticated-encryption quarantine with restore/delete management.
- Outbound HTTP observability.
- WooCommerce refund monitoring.
- REST and cron attack-surface inventory.
- WP-CLI security commands.
- Audit-chain continuity across retention cleanup.
- Integrity-baseline protection for resource-limited initial scans.
