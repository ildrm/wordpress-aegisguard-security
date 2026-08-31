# Test Plan

## Automated/static checks required in CI

1. `php -l` for every PHP file on PHP 7.4, 8.0, 8.1, 8.2, 8.3, and current supported PHP.
2. PHP_CodeSniffer with WordPress-Core, WordPress-Docs, and WordPress-Extra.
3. PHPCompatibilityWP against PHP 7.4+.
4. WordPress Plugin Check.
5. PHPUnit integration tests against supported WordPress versions.
6. Playwright browser tests for admin flows and login/MFA.

## Critical integration tests

- Fresh activate/deactivate/reactivate.
- Multisite network activation.
- No-capability access returns 403.
- Forged/missing nonce cannot save settings, scan, quarantine, restore/delete quarantine records, resolve incidents, or toggle lockdown.
- Login rate limit activates and later expires.
- Username enumeration errors remain generic.
- MFA valid/invalid/recovery-code flows.
- MFA recovery after salt rotation.
- Authenticated REST APIs remain functional while public user enumeration is hidden.
- XML-RPC on/off behavior.
- Upload PHP, double extension, and PHP-in-image/polyglot cases.
- WordPress core checksum mismatch.
- Scanner file-count ceiling.
- Scanner first baseline and later file change.
- Database suspicious-content finding.
- Emergency lockdown, administrator access policy, and WP-CLI recovery.
- Quarantine rejects traversal/outside-content/AegisGuard paths.
- Event-chain population and incident grouping.
- WooCommerce refund event on the latest WooCommerce.
- Responsive admin at desktop/tablet/mobile widths.
- Keyboard-only navigation and screen-reader labels.

## Manual compatibility matrix

- Apache + mod_php/FPM.
- Nginx + FPM.
- LiteSpeed/OpenLiteSpeed.
- Direct origin and Cloudflare/reverse proxy.
- WooCommerce latest stable.
- Major page builders and caching plugins.
- REST/API-driven and headless WordPress.
