# Release Review — 1.0.0

## Scope

This release is a functional standalone WordPress security agent. Capabilities that inherently require a globally operated service—edge DDoS/WAF, live exploit intelligence, distributed virtual patches, breach-corpus checks, immutable off-site evidence, and fleet SaaS—are intentionally documented as infrastructure work rather than represented as local functionality.

## Review roles

The release was reviewed using the 20-role matrix in `ROLES-AND-REVIEWS.md`, with special emphasis on WordPress architecture, application security, WAF behavior, malware analysis, IAM/MFA, incident response, PHP backend quality, REST/API behavior, WooCommerce compatibility, frontend/UI/UX, accessibility, privacy, performance, QA, release engineering, and licensing.

## Executed checks

- PHP syntax lint across every PHP file.
- JavaScript syntax check for the admin script.
- Pure smoke tests for RFC 6238 TOTP and WAF matching behavior.
- Static review of every PHP superglobal access for sanitization, nonce applicability, and read-only exceptions.
- Static search for executable-danger primitives such as `eval`, shell execution, and process-spawning calls in runtime code; scanner signatures are data-only regex patterns.
- Review of capability + nonce protection on administrator state changes.
- Review of output escaping in admin views.
- Multisite activation/deactivation/new-site/uninstall lifecycle review.
- Recovery review for lockdown, WAF blocks, MFA loss, salt rotation, quarantine failures, and integrity-baseline rebuilds.
- Package identity review confirming the plugin name and slug do not use the author name or account name.
- Verified quarantine restore/delete UI and authenticated original-path recovery flow.
- Verified integrity-baseline initialization occurs only after a complete, non-resource-limited first filesystem scan.
- Verified audit-chain continuity across retention cleanup through a preserved chain anchor.
- Verified MFA encryption uses a dedicated per-site key independent of WordPress salt rotation.

## Environment limitation

The release includes `composer.json` and `phpcs.xml.dist` configured for WordPress Coding Standards and PHP compatibility tooling. The current build environment does not provide Composer/PHPCS and could not download those dependencies, so an actual WPCS/Plugin Check execution was not possible here. This is documented rather than represented as a passed check. A CI pipeline should run those checks before public-directory publication.

## Security limitations worth preserving in product messaging

- The local WAF starts when WordPress loads this plugin; it is not a reverse-proxy or server-prepend firewall.
- Local audit-chain storage can detect many edits but is not equivalent to immutable remote evidence if an attacker gains full database/filesystem control.
- Malware heuristics are intentionally conservative; findings require review and quarantine is manual.
- The scanner does not claim a live CVE database without a maintained vulnerability-intelligence service.
- WooCommerce monitoring is deliberately narrow where stable, verified hooks are available.
