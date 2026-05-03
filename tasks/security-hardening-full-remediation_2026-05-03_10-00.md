# Task: Security Hardening & Vulnerability Remediation

**Date**: 2026-05-03  
**Status**: PASSED

---

## 1. Context

Security audit of ct.lamah.com identified these issues against this plugin:

| #   | Finding                                                                                | Severity |
| --- | -------------------------------------------------------------------------------------- | -------- |
| 1   | User enumeration via `/wp-json/wp/v2/users` — independent of REST lock setting         | HIGH     |
| 2   | XML-RPC active on non-standard Bedrock paths (`/app/xmlrpc.php`)                       | HIGH     |
| 3   | `debug.log` publicly readable at `/app/debug.log` (Bedrock path, not covered)          | HIGH     |
| 4   | Server-level hardening rules absent — PHP-layer cannot protect statically served files | HIGH     |
| 5   | `secure_guard_token_expiry_check` cron orphaned after plugin deactivation              | MEDIUM   |
| 6   | No audit logging for token management actions (create/edit/revoke/delete)              | MEDIUM   |
| 7   | Scopes not validated against a whitelist at creation time                              | MEDIUM   |
| 8   | IDS patterns in admin protector and traffic firewall too sparse (6 patterns)           | MEDIUM   |
| 9   | Default CSP includes `unsafe-inline` in `script-src`                                   | LOW      |

---

## 2. Plan

### Phase 1 — Critical Fixes

1. **User enumeration**: Add `block_rest_users_endpoint()` at
   `rest_pre_dispatch` priority 5 in `class-user-enumeration-blocker.php`. Works
   independently of `rest_lock_enabled` / `block_sensitive_endpoints`. Allows
   JWT tokens with `full_api_access` scope to pass.
2. **XML-RPC non-standard paths**: Expand `block_direct_request()` to catch any
   path ending in `/xmlrpc.php` and detect via `SCRIPT_FILENAME` basename.
3. **debug.log coverage**: Replace hardcoded paths with catch-all regex/string
   matching for any path ending in `debug.log` or containing `error_log`.
4. **Server-level hardening**: New `infra/` directory with Apache, Nginx, and
   Cloudflare rules.

### Phase 2 — Bug Fixes

5. Fix orphaned `secure_guard_token_expiry_check` cron deactivation.
6. Inject `Secure_Guard_Log_Repository` into `Secure_Guard_Tokens_Page`, log all
   token lifecycle events.
7. Add `VALID_SCOPES` constant to `Secure_Guard_Config`; filter scopes at
   creation/edit time.

### Phase 3 — Hardening

8. Expand IDS patterns from 6 → ~25 in both `class-admin-area-protector.php` and
   `class-traffic-firewall.php`. Add `is_malicious_request()` method to traffic
   firewall.
9. Update default CSP: remove `unsafe-inline` from `script-src` (keep in
   `style-src`).

---

## 3. Files Modified

- `secure-guard.php`
- `includes/security/class-user-enumeration-blocker.php`
- `includes/security/class-xmlrpc-protector.php`
- `includes/security/class-endpoint-blocker.php`
- `includes/security/class-wp-hardening.php`
- `includes/security/class-traffic-firewall.php`
- `includes/security/class-admin-area-protector.php`
- `includes/class-config.php`
- `includes/class-plugin.php`
- `admin/class-tokens-page.php`

## 4. Files Created

- `infra/apache/secure-guard-hardening.conf`
- `infra/nginx/secure-guard-hardening.conf`
- `infra/cloudflare/waf-rules.md`
- `infra/README.md`

---

## 5. Verification

- [ ] `php -l` passes on all modified PHP files
- [ ] `GET /wp-json/wp/v2/users` → 403 with `block_user_enumeration=1` and no
      auth
- [ ] JWT with `full_api_access` scope → 200 on `/wp/v2/users` (valid
      programmatic access)
- [ ] XML-RPC request to any path ending in `/xmlrpc.php` → 403
- [ ] Token create/edit/revoke/delete events appear in security logs with AUDIT
      result code
- [ ] Scope outside `VALID_SCOPES` silently dropped; token still created with
      `read_posts` default
- [ ] Default CSP in `defaults()` does not contain `unsafe-inline` in
      `script-src`
- [ ] Plugin deactivation unschedules all 3 cron events (verified with
      `wp_next_scheduled`)
- [ ] Infra config files syntactically valid (Apache: `apachectl configtest`,
      Nginx: `nginx -t` after include)
