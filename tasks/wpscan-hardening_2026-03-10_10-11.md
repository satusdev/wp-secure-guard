# Task: WPScan Hardening and Scanner-Facing Security Coverage

## Status

- IMPLEMENTED_PENDING_RUNTIME_VERIFICATION

## Context

- Goal: harden Secure Guard to reduce common WPScan findings and strengthen
  default protections.
- Selected policy defaults:
  - Strict anti-enumeration behavior.
  - Sensitive REST endpoints remain blocked even when global REST lock is
    disabled.
  - `xmlrpc.php` should return hard 403 when XML-RPC protection is enabled.
  - Safe-strict modern security headers with low compatibility risk.
- Scope is plugin-layer hardening; some passive fingerprinting vectors require
  web server or CDN controls.

## Plan

1. Decouple sensitive endpoint enforcement from global REST lock checks.
2. Expand user enumeration blocking beyond `?author=` probes.
3. Add explicit hard block path handling for `xmlrpc.php`.
4. Expand sensitive probe file and exposure path detection.
5. Strengthen response header baseline.
6. Update admin copy and project documentation to reflect behavior and limits.
7. Run syntax validation for all modified PHP files.

## Risks

- Strict enumeration blocking may affect sites intentionally using author
  archives.
- Additional protected path patterns can block direct access to files some
  legacy workflows still expose.
- Header tightening must avoid defaults likely to break front-end script
  behavior.

## Verification

- Run `php -l` on each modified PHP file.
- Confirm no editor diagnostics in modified files.
- Validate task pass only after checks succeed.

## Proposed Changes (Approved)

- Modify security guards under `includes/security` for REST, enumeration,
  XML-RPC, path protection, and headers.
- Keep module boundaries and hook wiring in `includes/class-plugin.php`.
- Update settings/rules descriptions in `admin` where behavior changed.
- Update `PROJECT.md` source-of-truth hardening coverage and constraints.

## Execution Log

- 2026-03-10 10:11: Task initialized with strict scanner-hardening policy.
- 2026-03-10 10:12-10:16: Implemented REST sensitive endpoint decoupling from
  REST lock, expanded strict enumeration controls, and direct XML-RPC hard 403
  behavior.
- 2026-03-10 10:16-10:18: Expanded sensitive path and exposure probe blocking in
  endpoint and hardening modules.
- 2026-03-10 10:18-10:19: Implemented safe-strict modern headers and added
  settings defaults/controls.
- 2026-03-10 10:19-10:20: Updated plugin hook wiring, API Rules descriptions,
  and `PROJECT.md` architecture/source-of-truth documentation.
- 2026-03-10 10:28-10:30: Fixed CSS asset loading compatibility by making CSP
  opt-in by default, auto-migrating legacy strict default value, and clarifying
  CSP risk in settings UI.
- 2026-03-10 11:58-12:04: Implemented plugin-level REST hard shutdown policy in
  `class-rest-guard.php` to return 403 for all REST routes and methods, removing
  role/token/settings-based REST bypass behavior.
- 2026-03-10 12:04-12:06: Updated admin settings and API Rules copy to reflect
  that REST is force-disabled globally and verification should be curl-only 403
  checks.
- 2026-03-10 12:06-12:07: Updated `PROJECT.md` architecture/source-of-truth to
  document global REST deny behavior.

## Verification Results

- PHP syntax checks passed:
  - `php -l includes/security/class-rest-guard.php`
  - `php -l includes/security/class-user-enumeration-blocker.php`
  - `php -l includes/security/class-xmlrpc-protector.php`
  - `php -l includes/security/class-endpoint-blocker.php`
  - `php -l includes/security/class-traffic-firewall.php`
  - `php -l includes/security/class-wp-hardening.php`
  - `php -l includes/security/class-security-headers.php`
  - `php -l includes/class-plugin.php`
  - `php -l includes/class-config.php`
  - `php -l admin/class-settings-page.php`
  - `php -l admin/class-rules-page.php`
- Editor diagnostics show no errors in modified files.
- WP-CLI runtime verification is blocked in this workspace path:
  - `wp --info` passed.
  - `wp core is-installed` failed because this directory is plugin source, not
    an initialized WordPress install.
- CSS fix validation passed:
  - `php -l includes/class-config.php`
  - `php -l includes/security/class-security-headers.php`
  - `php -l admin/class-settings-page.php`
  - Editor diagnostics show no errors in these files.
- REST hard-shutdown change validation passed:
  - `php -l includes/security/class-rest-guard.php`
  - `php -l admin/class-settings-page.php`
  - `php -l admin/class-rules-page.php`
  - Editor diagnostics show no errors in modified files.
- Curl-only runtime verification (staging) passed with global 403:
  - `GET /wp-json` -> `403`
  - `GET /wp-json/wp/v2/users` -> `403`
  - `GET /wp-json/wp/v2/posts` -> `403`
  - `POST /wp-json/wp/v2/posts` -> `403`
  - `PUT /wp-json/wp/v2/posts/1` -> `403`
  - `DELETE /wp-json/wp/v2/posts/1` -> `403`
  - `GET /?rest_route=/wp/v2/users` -> `403`

## Pass Condition

- Not marked `PASSED` yet because live runtime smoke verification against an
  active WordPress instance could not be executed from this workspace path.
