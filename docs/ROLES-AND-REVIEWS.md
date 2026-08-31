# Implementation Roles and Review Matrix

The project is reviewed as a multidisciplinary security product. These are engineering/review roles, not WordPress user roles.

## 1. Product security architect
Owns threat model, trust boundaries, defense in depth, local/cloud split, recovery paths, and failure-safe defaults.

## 2. WordPress plugin architect
Owns bootstrap lifecycle, hooks, activation/deactivation/uninstall behavior, multisite behavior, capabilities, Options API usage, cron, REST interactions, compatibility, internationalization, and WordPress Coding Standards.

## 3. Application security engineer
Reviews authentication, authorization, CSRF, XSS, injection, SSRF, file handling, deserialization risk, sensitive-data handling, cryptography use, nonce/capability coverage, input validation, and output escaping.

## 4. WAF / IDS engineer
Reviews detection patterns, scoring, false positives, request normalization, block thresholds, rate limiting, proxy/IP trust, learning/monitor modes, and bypass resistance.

## 5. Malware / reverse-engineering analyst
Owns malware signals, web-shell markers, obfuscation heuristics, persistence indicators, safe scanning, false-positive classification, and quarantine safety.

## 6. Identity and access-management engineer
Owns login policy, TOTP MFA, recovery codes, session behavior, dedicated secret-at-rest key management, privileged account controls, and authentication recovery.

## 7. Incident response and forensics engineer
Owns event evidence, chain hashes, incident grouping, alert severity, containment, quarantine, lockdown, recovery access, and audit-retention requirements.

## 8. Database security engineer
Reviews custom-table schemas, indexes, query preparation, data retention, database scanning, sensitive-field avoidance, and uninstall behavior.

## 9. Backend PHP engineer
Owns modularity, error handling, compatibility with PHP 7.4+, performance, memory behavior, safe filesystem operations, and maintainability.

## 10. REST/API security engineer
Owns WordPress REST exposure, user enumeration, authenticated API compatibility, future cloud API boundaries, SSRF considerations, and permission checks.

## 11. WooCommerce security specialist
Validates optional WooCommerce hooks and ensures security controls do not break checkout, refunds, customer accounts, REST APIs, Action Scheduler, or payment workflows.

## 12. Frontend engineer
Owns admin UI behavior, responsive layout, progressive enhancement, JavaScript minimalism, confirmation interactions, browser compatibility, and avoidance of inline application logic.

## 13. UI/UX security designer
Owns information hierarchy, risk communication, safe defaults, destructive-action friction, readable terminology, scan finding presentation, and preventing configuration-induced lockouts.

## 14. Accessibility specialist
Reviews keyboard operation, labels, focus behavior, semantic tables/forms, non-color-only states, responsive behavior, reduced motion, and WCAG-oriented admin UX.

## 15. Privacy/compliance reviewer
Reviews IP storage/anonymization, retention, alert payloads, secret redaction, future telemetry consent, uninstall retention, and accurate compliance claims.

## 16. Performance engineer
Owns scan ceilings, file-size limits, bounded queries, log cleanup, alert throttling, no unbounded recursion, and avoidance of heavyweight work on normal page views.

## 17. QA / test engineer
Owns syntax tests, regression passes, auth flows, role/capability failures, nonce failures, upload edge cases, WAF false positives, scan truncation, recovery flows, and multisite scenarios.

## 18. DevOps / release engineer
Owns packaging, reproducible ZIP contents, versioning, CI recommendations, PHPCS/WPCS, PHP compatibility, WordPress matrix testing, and release integrity.

## 19. Technical writer
Owns WordPress readme, developer README, installation, operational boundaries, recovery procedures, and unambiguous security wording.

## 20. Open-source licensing reviewer
Owns SPDX/license correctness, dependency licensing, WordPress.org GPL compatibility, third-party asset provenance, and attribution.

## Review passes performed for 1.0.0

### Pass 1 — Architecture and standards
- Modular bootstrap and no WordPress core modifications.
- GPL-2.0-or-later selected for WordPress compatibility.
- Dedicated capabilities instead of relying only on `manage_options`.
- Custom tables installed with `dbDelta`.

### Pass 2 — Security flows
- State changes require both capabilities and nonces.
- Login endpoints use authentication hooks where a nonce does not exist yet.
- Sensitive event fields are redacted.
- Proxy headers are ignored unless the immediate proxy is explicitly trusted.
- Quarantine rejects paths outside `wp-content` and refuses to quarantine AegisGuard itself.

### Pass 3 — Identity and recovery
- TOTP secrets are encrypted.
- Recovery codes are hashed and one-use.
- MFA encryption uses a dedicated per-site key so WordPress authentication-salt rotation does not invalidate enrolled TOTP secrets; recovery codes remain an independent fallback.
- MFA/rate-limit errors survive username-enumeration masking.

### Pass 4 — UI/UX and accessibility
- Safety-oriented dashboard rather than exposing every toggle on the landing page.
- Destructive quarantine requires explicit confirmation.
- Strict firewall is not the default.
- Responsive admin layout and semantic form labels.
- Status is communicated with text as well as color.
- Reduced-motion preference respected.

### Pass 5 — Compatibility and false-positive review
- REST user protection moved from global route removal to dispatch-time authorization to avoid breaking authenticated API clients.
- File scanning is bounded and exits when the configured file ceiling is reached.
- The scanner does not classify its own signature-list source as malware.
- Unverified WooCommerce hooks were removed; refund monitoring uses a currently verified two-argument hook.
- Hidden settings are preserved when the visible settings form is saved.

### Pass 6 — Operational recovery
- Emergency lockdown leaves WP-CLI available.
- Plugin data deletion on uninstall is opt-in.
- Manual authenticated-encryption quarantine is used instead of automatic deletion, with nonce/capability-protected restore and permanent-delete workflows.
- First scan establishes a file-integrity baseline; later scans highlight changed/new scannable files.

### Pass 7 — Forensics, proxy trust, and release hardening
- Reworked trusted-proxy parsing to traverse the forwarding chain from the server backwards, preventing a spoofed left-most X-Forwarded-For value from being accepted merely because the immediate proxy is trusted.
- Corrected the “disable XML-RPC” control so all exposed XML-RPC methods are removed in addition to disabling authenticated methods.
- Added missing-file integrity detection only after a complete filesystem walk; resource-limited scans explicitly skip that check to prevent false positives.
- Added sensitive-file, privileged-administrator MFA posture, and high-frequency cron checks.
- Moved audit-chain signing to a dedicated random per-site key and added chain verification; WordPress salt rotation no longer destroys ordinary audit-chain verifiability.
- Made the in-request audit hash cache multisite-aware so blog switching cannot cross-link event chains.

### Pass 8 — Release-flow closure
- Added a complete encrypted-quarantine management UI with verified restore and permanent-delete actions.
- Prevented a resource-limited first scan from becoming the accepted integrity baseline.
- Preserved audit-chain continuity across retention cleanup with a per-site chain anchor.
- Decoupled MFA encryption from WordPress salts with a dedicated per-site encryption key.
