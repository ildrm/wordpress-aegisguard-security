=== AegisGuard Security ===
Tags: security, firewall, malware, waf, mfa
Requires at least: 6.5
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A security-focused WordPress agent with WAF, malware and integrity scanning, MFA, hardening, audit events, incidents, and recovery controls.

== Description ==

AegisGuard Security is a modular WordPress security plugin designed around conservative defaults, explainable detections, and safe incident response.

Core capabilities include:

* Application-level request firewall with learning, monitoring, balanced, and strict modes.
* Login rate limiting and a bot honeypot.
* TOTP multi-factor authentication with a dedicated per-site encryption key and one-use recovery codes.
* Official WordPress core checksum verification.
* Malware-oriented heuristic scanning without executing discovered code.
* File-integrity baseline tracking for changed, new, and missing scannable files when a complete scan finishes.
* Database content scanning for suspicious executable and redirect patterns.
* Sensitive backup/config-file presence checks, administrator MFA posture review, and high-frequency cron review.
* Persistence checks for PHP auto-prepend/append directives.
* Upload protection against executable extensions and code-bearing polyglot uploads.
* User-enumeration reduction for login, author queries, and REST user endpoints.
* XML-RPC and pingback controls.
* Runtime plugin/theme editor capability denial.
* Baseline security headers.
* Locally hash-chained audit logs using a dedicated per-site HMAC key, with chain verification during security scans.
* Security incident correlation.
* Emergency lockdown with WP-CLI recovery access.
* Outbound WordPress HTTP API monitoring for private/link-local destinations.
* WooCommerce refund security logging when WooCommerce is present.
* REST API attack-surface inventory.
* WP-Cron inventory.
* WP-CLI scan and lockdown commands.
* Privacy controls including optional IP anonymization and configurable log retention.

AegisGuard intentionally does not claim to provide edge DDoS protection, a global reputation network, live CVE intelligence, breach-password intelligence, or globally distributed virtual patches without an external security service. The local plugin remains operational without cloud infrastructure.

== Installation ==

1. Upload the `aegisguard-security` directory to `/wp-content/plugins/` or install the ZIP through Plugins > Add New > Upload Plugin.
2. Activate AegisGuard Security.
3. Open AegisGuard > Dashboard.
4. Run the first full security scan to establish an integrity baseline.
5. Review AegisGuard > Settings before switching the firewall to Strict mode.
6. Configure MFA from AegisGuard > Identity for privileged accounts.

== Frequently Asked Questions ==

= Does AegisGuard replace a CDN or reverse-proxy WAF? =

No. Its included firewall is an in-process WordPress application firewall. Edge DDoS mitigation and origin shielding require reverse-proxy or hosting infrastructure.

= Does the scanner execute suspicious PHP? =

No. It performs read-only pattern, checksum, configuration, database, and integrity analysis.

= Can it quarantine files automatically? =

The plugin includes encrypted manual quarantine with explicit restore and permanent-delete workflows. Automatic destructive remediation is deliberately not enabled by default because false positives can take a production site offline.

= Is WooCommerce required? =

No. WooCommerce-specific hooks are registered safely and simply remain unused when WooCommerce is absent.

= Are MFA secrets affected by WordPress authentication-salt rotation? =

No. AegisGuard uses a dedicated per-site MFA encryption key. Recovery codes remain available as an independent recovery mechanism.

== Changelog ==

= 1.0.1 =
* Serialize audit-chain writes, verification, and retention pruning to preserve chain integrity under concurrency.
* Create cryptographic keys before activation can emit audit events.
* Reject TOTP replay and make recovery-code consumption atomic.
* Keep IP-wide login-abuse counters after a successful login.
* Strengthen encoded-traversal inspection, large-upload tail inspection, and quarantine symlink/restore safeguards.
* Suppress process-execution heuristics only for files that match official WordPress core checksums.
* Add WordPress integration regressions, reproducible development dependencies, and CI quality checks.

= 1.0.0 =
* Initial production-oriented local security agent.
