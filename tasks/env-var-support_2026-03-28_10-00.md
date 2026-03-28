# Task: Environment Variable Support for JWT Settings

## Status: PASSED

## Context

Bedrock WordPress projects use phpdotenv to load a `.env` file. Settings stored
in `wp_options` travel with a database export; the JWT `iss`/`aud` claims baked
into token strings are tied to the URL used at signing time.

Users want to pin JWT secret, issuer, and audience to per-environment `.env`
values so tokens remain portable when cloning staging → production databases.

## Plan

### Files Modified

- `includes/class-config.php` — Add `ENV_VARS` map, `get_env_value()`,
  `is_env_overridden()`; apply env overrides in `get_settings()`; preserve
  existing DB values in `save_settings()` when env override is active.
- `admin/class-settings-page.php` — JWT Secret, Issuer, Audience fields show
  "ENV" badge and disable input when the corresponding env var is active. Add
  `row_url_env()` helper.
- `admin/class-rules-page.php` — New "Environment Variable Overrides" card
  listing all three env vars with active/inactive status.

### Priority Chain (after change)

1. PHP constant (`define('SECURE_GUARD_JWT_SECRET', ...)`
2. Env var in `.env` / system env (`SECURE_GUARD_JWT_SECRET`)
3. Database setting (plugin settings page)
4. `AUTH_KEY` fallback (jwt_secret only)

### Bedrock .env Example

```
SECURE_GUARD_JWT_SECRET=your-long-random-secret-here
SECURE_GUARD_JWT_ISSUER=https://example.com/
SECURE_GUARD_JWT_AUDIENCE=https://example.com/
```

Setting issuer and audience to the same value in both staging and production
`.env` files means tokens signed on staging will validate on production after a
DB clone — no manual re-signing required.

## Verification

1. Set env var in server environment, confirm settings page shows ENV badge.
2. Submit settings form while env var is active, confirm DB value not
   overwritten.
3. Confirm `get_settings()` returns env var value for overridden keys.
4. Confirm `php -l` passes on all modified files.

## Status Notes

- No DB schema changes.
- No changes to `class-token-manager.php` — `get_settings()` populates settings
  array before token manager construction, so env values flow automatically.
