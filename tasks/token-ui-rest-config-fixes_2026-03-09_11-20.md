# Task: Token UI, REST Route Normalization, and Config Save Recursion Fix

## Status

- IMPLEMENTED_PENDING_RUNTIME_VERIFICATION

## Context

- `options.php` save triggers fatal memory exhaustion due to recursive setting
  save path.
- REST logs can show `ALLOWED` while request still returns `rest_no_route`
  because auth phase passes before route resolution.
- Token page needs clearer UI and explicit hidden-by-default token visibility
  with on-demand re-display.
- Admin pages need improved operator UX and embedded usage docs with curl
  examples (with/without token).
- Users collection endpoint should respond for token-authorized access even when
  upstream route registration omits GET collection route.
- Tokens table requires permanent delete action in addition to revoke.
- Token storage must remain hash-only for existing security model.

## Plan

1. Remove recursive config write in sanitize path.
2. Normalize REST route extraction for subdirectory and `rest_route` query URL
   forms.
3. Improve tokens page UI and add explicit Show/Hide behavior for newly
   generated tokens only.
4. Improve dashboard, logs, rules, and settings page usability and add
   verification docs.
5. Add users endpoint fallback injection when `/wp/v2/users` GET route is
   missing.
6. Add permanent token delete action in tokens table.
7. Update project documentation for token visibility constraints and REST
   behavior.
8. Verify syntax and run targeted checks.

## Risks

- Token re-display cannot support previously created tokens without reversible
  storage.
- REST normalization must not alter unrelated route matching behavior.

## Verification

- Save settings on `wp-admin/options.php` without fatal errors.
- Confirm route extraction correctness for `/wp-json/...`, `/wp/wp-json/...`,
  and `?rest_route=...` requests.
- Confirm token table hides token by default and reveals only on explicit action
  when available.
- Run PHP syntax checks on modified files.

## Verification Results

- PHP syntax checks passed:
  - `php -l includes/class-config.php`
  - `php -l admin/class-settings-page.php`
  - `php -l includes/security/class-rest-guard.php`
  - `php -l admin/class-tokens-page.php`
- Editor diagnostics report no errors in modified files.
- Runtime verification against a live WordPress admin instance is still pending.
- Admin UI/docs pass syntax checks passed:
  - `php -l admin/class-dashboard-page.php`
  - `php -l admin/class-logs-page.php`
  - `php -l admin/class-rules-page.php`
  - `php -l admin/class-settings-page.php`
  - `php -l admin/class-tokens-page.php`
- Additional syntax checks passed:
  - `php -l includes/class-plugin.php`
  - `php -l admin/class-admin-menu.php`
  - `php -l includes/data/class-token-repository.php`
- Live probe from current shell still returns `rest_no_route` for
  `/wp-json/wp/v2/users`, indicating runtime instance likely not yet executing
  the updated plugin code.
