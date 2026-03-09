# Task: Secure Guard MVP Implementation

## Status

- PARTIAL_VERIFY

## Task

Implement WordPress plugin `secure-guard` with core security features:

1. REST API lockdown (default deny)
2. Access token validation (hashed storage)
3. Sensitive endpoint blocking
4. User enumeration blocking
5. Sensitive path and XML-RPC protections
6. Rate limiting
7. IP allowlist
8. Audit log
9. Security headers
10. Admin pages for settings/tokens/logs/rules

## Context

- Repository is greenfield with only `package.json`.
- Target runtime: WordPress 6.4+, PHP 8.1+.
- Deployment target: single-site.

## Plan

1. Create plugin bootstrap, installer, and module loader.
2. Implement repositories for tokens/logs/rate limits.
3. Implement security guards and WordPress hook integration.
4. Build admin pages for settings, tokens, rules, and logs.
5. Add uninstall cleanup behavior.
6. Run verification commands and record results.

## Risks

- Request IP extraction may vary behind proxies.
- Aggressive route lock can block expected integrations if misconfigured.
- No local WP runtime in repository may limit runtime verification.

## Verification

- `php -l` on all PHP files.
- If available: `wp plugin activate secure-guard`.
- If available: endpoint smoke tests for deny/allow paths.

## Propose (Approved)

- Files to modify: plugin scaffold and modules under `includes/`, admin pages
  under `admin/`, uninstall script, architecture docs.
- Architecture impact: introduces centralized guard pipeline and custom tables
  for secure token/log/rate data.
- Dependencies: WordPress core functions, `$wpdb`, no external PHP packages.

## Execution Log

- 2026-03-09 10:34: Task initialized and architecture baseline defined.
- 2026-03-09 10:35-10:45: Implemented plugin bootstrap, installer, repositories,
  security guards, and admin pages.
- 2026-03-09 10:46: Executed PHP syntax validation across all plugin PHP files
  (PASS).
- 2026-03-09 10:46: Verified WP-CLI availability (PASS).
- 2026-03-09 10:47: WordPress core not initialized in current workspace,
  activation + runtime endpoint smoke tests could not run.
- 2026-03-09 11:00-11:20: Expanded implementation to include login protection,
  global bot/firewall controls, WordPress hardening, admin area protection, file
  integrity monitoring, security event logging, and dashboard metrics.
- 2026-03-09 11:21: Re-ran PHP syntax validation across all plugin files (PASS).

## Verification Results

- `php -l` on all plugin files: PASSED.
- `wp --info`: PASSED.
- `wp core is-installed`: FAILED (workspace is not an initialized WP install).

## Expanded MVP Coverage

- [x] REST API lockdown
- [x] Login protection and escalating lockouts
- [x] Bot/spam rate limiting
- [x] Hide WordPress information
- [x] User enumeration protection
- [x] Security logging (failed login, blocked IP, API, role change, plugin
      changes)
- [x] Automatic IP blocking
- [x] XML-RPC protection
- [x] File change detection via cron scan
- [x] Security headers
- [x] Admin area protection
- [x] Security dashboard

## Pass Condition

- Not marked PASSED because runtime verification (activation and request smoke
  tests) requires a live WordPress installation.
