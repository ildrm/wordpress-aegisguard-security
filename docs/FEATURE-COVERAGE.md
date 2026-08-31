# Feature Coverage and Infrastructure Boundary

## Fully operational in the plugin ZIP

- Local application WAF.
- Login brute-force/rate-limit protection.
- Login honeypot.
- TOTP MFA with a dedicated per-site encryption key and one-use recovery codes.
- WordPress core checksum verification.
- Heuristic malware and web-shell scanning.
- File-integrity baseline with changed/new/missing-file detection on complete scans.
- Database suspicious-content scanning.
- PHP persistence-directive checks.
- Upload executable/polyglot protection.
- User-enumeration controls.
- XML-RPC and pingback controls.
- File-editor capability hardening.
- Security headers.
- Locally hash-chained audit events plus chain verification, using a dedicated per-site audit key.
- Security incident grouping.
- Email alert throttling.
- Authenticated-encryption manual file quarantine with verified restore and permanent-delete workflows.
- Emergency lockdown and WP-CLI recovery.
- Sensitive backup/config-file presence checks.
- Administrator MFA posture checks.
- High-frequency WordPress cron review.
- REST attack-surface inventory.
- WP-Cron inventory.
- Outbound WordPress HTTP API private/link-local destination observation.
- WooCommerce refund monitoring.
- Privacy IP anonymization.
- Configurable event retention.
- Multisite-aware activation.

## Requires a hosted/cloud service to become operational

These cannot be honestly implemented by a standalone plugin ZIP:

- Reverse-proxy/edge WAF.
- Volumetric DDoS mitigation.
- Anycast/global bot network.
- Global malicious-IP/ASN reputation.
- Cross-customer threat intelligence.
- Real-time CVE and exploit-intelligence feed.
- Vendor-independent virtual patch feed.
- Compromised-password breach corpus.
- Off-server malware execution/sandboxing.
- Immutable remote log storage.
- Fleet/agency SaaS console.
- Remote SIEM storage and multi-site correlation.
- Mobile push service.

## Deliberately not shipped as an unsafe approximation

- Automatic deletion of suspicious files.
- Automatic edits to `wp-config.php`.
- Automatic `.htaccess` rewrites for every server type.
- Automatic CSP enforcement without learning/testing.
- Blind trust of `X-Forwarded-For`.
- Aggressive REST disabling.
- Remote executable rule/code delivery.
- Claims that installing the plugin makes a site GDPR/PCI/SOC 2/ISO 27001 compliant.
