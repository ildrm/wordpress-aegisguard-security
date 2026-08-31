# AegisGuard Security

AegisGuard Security is a modular WordPress security agent that combines request filtering, malware and integrity scanning, identity protection, hardening, security telemetry, incident correlation, and containment controls in one plugin.

## Compatibility

- WordPress: 6.5+
- Tested up to: WordPress 7.1
- PHP: 7.4+
- Multisite-aware activation
- WooCommerce-aware monitoring without a hard dependency

## Implemented security engines

### Request and authentication protection
- Local application WAF with learning, monitoring, balanced, and strict modes.
- High-confidence SQL injection, XSS, traversal, wrapper/RFI, shell-meta, and sensitive-file probes.
- Temporary IP blocks using hashed transient keys.
- Login rate limiting by username/email + client IP.
- Login honeypot for unsophisticated automation.
- Generic invalid-credential messaging without hiding AegisGuard MFA/rate-limit errors.

### Identity security
- RFC 6238 TOTP MFA.
- MFA secrets encrypted at rest with libsodium secretbox when available, otherwise AES-256-GCM via OpenSSL, using a dedicated per-site encryption key independent of WordPress authentication salts.
- Ten one-use recovery codes stored only as WordPress password hashes.
- One-use recovery codes provide a separate account-recovery path without exposing the MFA secret.
- Session count visibility and one-click termination of all other sessions for the current user.

### Scanner and integrity engine
- WordPress official core checksums.
- Read-only heuristic malware inspection.
- Web-shell marker detection.
- Obfuscated `eval` chain detection.
- Dangerous process-execution review findings.
- PHP-in-uploads detection.
- Large encoded-payload review findings.
- File-integrity baseline stored in a dedicated table, including changed/new/missing-file detection when a complete scan finishes.
- Database scanning of posts and options.
- Sensitive web-root/backup file checks, privileged-user MFA posture checks, and suspicious high-frequency cron review.
- Verification of the local audit-event hash chain using a dedicated per-site audit key.
- PHP persistence checks for `auto_prepend_file` and `auto_append_file`.
- WordPress/plugin/theme update posture.
- Resource ceilings for file count and bytes read per file.

### Hardening
- Public REST user enumeration reduction.
- Numeric author enumeration blocking for unauthenticated requests.
- Generic login credential errors.
- XML-RPC switch and pingback removal.
- Plugin/theme editor capability denial.
- WordPress generator removal.
- Baseline `nosniff`, referrer, frame, and HSTS headers.
- Upload preflight inspection.

### Observability and response
- Dedicated audit-events table.
- HMAC event-chain hashes for tamper evidence.
- Sensitive context redaction.
- Optional IP anonymization.
- Severity-based rate-limited email alerts.
- Incident correlation for high/critical security events.
- Emergency lockdown.
- Authenticated-encryption file quarantine with verified restore and permanent-delete workflows.
- Outbound WordPress HTTP API observation for private, reserved, or link-local destinations.
- REST route inventory and WP-Cron inventory.
- WP-CLI scan and lockdown commands.

### WooCommerce
- Refund creation monitoring through the current `woocommerce_order_refunded` hook.
- No hard dependency on WooCommerce.

## WordPress.org and cloud-service boundary

The local plugin is intentionally self-contained. Features that inherently require external infrastructure are not represented as if they are locally functional. A future hosted service can add:

- reverse-proxy/edge WAF,
- DDoS mitigation,
- global IP/ASN reputation,
- live vulnerability intelligence,
- distributed virtual patches,
- compromised-password intelligence,
- cross-site threat correlation,
- fleet management,
- remote log retention and SIEM pipelines.

Any future service integration should exchange data only and must not remotely deliver executable PHP/JavaScript code into a WordPress.org-distributed plugin.

## Security design principles

1. Capability checks and CSRF nonces for state-changing administrator operations.
2. Sanitization on input and escaping on output.
3. No `eval`, shell execution, or execution of scanned content.
4. No trust of forwarding headers unless the immediate proxy address is explicitly trusted; proxy chains are evaluated from the server backwards to resist spoofed left-most X-Forwarded-For values.
5. Passwords, secrets, authorization headers, cookies, and nonces are redacted from event context.
6. Manual quarantine is preferred over automatic deletion.
7. Destructive uninstall cleanup is opt-in.
8. WP-CLI remains a recovery channel during lockdown.
9. Public REST protection happens at dispatch time to preserve authenticated API workflows.
10. All remote/cloud functionality is opt-in by architecture.

## Author

Shahin Ilderemi  
Email: ildrm@hotmail.com  
Website: https://ildrm.com  
GitHub: https://github.com/ildrm  
LinkedIn: https://www.linkedin.com/in/ildrm

## License

GPL-2.0-or-later. See `LICENSE`.
