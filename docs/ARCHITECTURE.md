# Architecture

```text
AegisGuard Security
├── Bootstrap
├── Core
│   ├── Activator / schema
│   ├── Plugin lifecycle
│   └── Tamper-evident logger
├── Security
│   ├── RuntimeFirewall
│   ├── LoginProtection
│   ├── Mfa
│   ├── UploadProtection
│   ├── Hardening
│   ├── Scanner + integrity baseline
│   ├── OutboundMonitor
│   ├── ActivityMonitor
│   ├── IncidentManager
│   └── WP-CLI command
├── Support
│   ├── Capabilities
│   ├── Request/IP trust
│   └── Settings
└── Admin
    ├── Command center
    ├── Scanner/findings
    ├── Identity
    ├── Incidents
    ├── Events
    ├── Attack surface
    └── Settings
```

## Trust boundaries

- Browser requests are untrusted.
- Forwarding headers are untrusted unless the immediate proxy IP is allowlisted.
- File and database contents are untrusted and are never executed by the scanner.
- Authenticated users are still capability-checked for each security action.
- Administrator POST actions are still nonce-protected.
- Cloud services are outside the local trust boundary and are not required for local operation.

## Recovery guarantees

- Strict firewall is opt-in.
- Quarantine is manual.
- Uninstall deletion is opt-in.
- Lockdown does not disable WP-CLI.
- MFA recovery codes remain usable if the encrypted TOTP secret is unavailable.
