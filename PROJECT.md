# Secure Guard Project

## Status

- Architecture baseline established on 2026-03-09.
- Scope: WordPress plugin MVP for API and endpoint hardening.

## Domain

Secure Guard is a WordPress security plugin that enforces default-deny behavior
for REST API and sensitive endpoints. Access is granted only when request
conditions pass policy checks (token, IP, role, route, rate).

### Core Capabilities

- REST API lockdown by default.
- Token-based API access using hashed storage.
- Token values are hidden by default in admin and can only be re-shown briefly
  for recently generated tokens in the same admin session.
- Sensitive endpoint blocking (`users`, `settings`, `plugins`, XML-RPC, known
  exposure paths).
- User enumeration protections.
- Login endpoint protection with escalating lockouts and automatic IP blocks.
- Bot and spam rate limiting for general request traffic.
- WordPress fingerprint reduction (generator/version/readme/license
  protections).
- Admin area protection for non-authenticated and suspicious requests.
- File integrity monitoring for `wp-admin` and `wp-includes` via scheduled
  checksum scans.
- Audit logging for deny/security events and security-sensitive admin events.
- Security dashboard metrics for blocked IPs, failed logins, API requests, and
  active tokens.
- Security header injection including HSTS on HTTPS.

## Architecture

### Runtime Flow

1. Plugin bootstrap loads configuration and module instances.
2. Installer creates required tables and stores schema version.
3. Request guards run through WordPress hooks:
   - `rest_authentication_errors`
   - `rest_pre_dispatch`

- `init`
- `template_redirect`
- `wp_login_failed`
- `wp_login`
- `set_user_role`
- `upgrader_process_complete`
- `secure_guard_integrity_scan`
- `xmlrpc_enabled`
- `send_headers`

4. Guard pipeline evaluates in this order:
   - Bypass rules (admin user/capability where intended)
   - Sensitive route policy
   - Token validation and scope checks
   - IP allowlist checks
   - Rate limiting
5. Denials are logged to audit storage with normalized metadata.
6. REST auth logs reflect authentication/authorization decisions; unresolved
   routes still return core WordPress `rest_no_route` responses.

### Module Boundaries

- `includes/data/*`: persistence and DB access only.
- `includes/security/*`: policy and request validation logic.
- `admin/*`: dashboard pages and admin actions.
- `includes/class-plugin.php`: composition root and hook wiring.

### Security Modules

- `class-rest-guard.php`: REST auth pipeline, token checks, endpoint
  restrictions.
- `class-login-protection.php`: failed login tracking and lockout policy.
- `class-traffic-firewall.php`: global request throttling and IP block checks.
- `class-admin-area-protector.php`: `/wp-admin` access guard.
- `class-wp-hardening.php`: generator/version/readme/license hardening.
- `class-file-integrity-monitor.php`: checksum baseline + scheduled change
  detection.
- `class-security-events.php`: audit hooks for role/plugin changes.

## Data Model

### Table: `{prefix}sg_tokens`

- `id` bigint primary key
- `name` varchar(190)
- `token_hash` char(64) unique
- `scope` text (comma-delimited scopes)
- `allowed_endpoints` text (newline-separated patterns)
- `allowed_ips` text (newline-separated IPv4/IPv6/CIDR)
- `rate_limit_per_minute` int
- `expires_at` datetime nullable
- `last_used_at` datetime nullable
- `created_at` datetime
- `revoked_at` datetime nullable

### Table: `{prefix}sg_logs`

- `id` bigint primary key
- `ip` varchar(64)
- `endpoint` varchar(255)
- `method` varchar(12)
- `result` varchar(32)
- `reason` varchar(190)
- `context` longtext JSON string
- `created_at` datetime

### Table: `{prefix}sg_rate_limits`

- `id` bigint primary key
- `subject` varchar(255) unique
- `window_started_at` datetime
- `hit_count` int
- `blocked_until` datetime nullable

## Configuration Conventions

- Option key: `secure_guard_settings`.
- Capability required for admin actions: `manage_options`.
- Defaults:
  - REST lock enabled.
  - XML-RPC blocked.
  - User enumeration blocked.
  - Sensitive routes blocked.
  - Rate limit = 100 requests per minute.

## Coding Conventions

- Target PHP 8.1+ and WordPress 6.4+.
- Strict sanitization of all external input.
- No direct SQL outside repository/installer classes.
- Use prepared statements for all queries.
- Keep request checks side-effect free except logging and limiter persistence.

## Folder Structure

- `secure-guard.php`
- `includes/`
  - `class-config.php`
  - `class-loader.php`
  - `class-plugin.php`
  - `install/class-installer.php`
  - `data/*.php`
  - `security/*.php`
- `admin/*.php`
- `tasks/*.md`
- `uninstall.php`

## Verification Standard

- PHP syntax validation over plugin files.
- Runtime smoke checks via WordPress hooks.
- If test harness exists, execute and require green before marking PASS.

## MVP Feature Matrix

1. REST API Lockdown: implemented.
2. Login Protection: implemented with threshold lockouts.
3. Bot & Spam Rate Limiting: implemented per-IP fixed window.
4. Hide WordPress Information: implemented.
5. User Enumeration Protection: implemented.
6. Security Logging: implemented (API/login/role/plugin).
7. Automatic IP Blocking: implemented for login abuse, bot limit, and 404 scans.
8. XML-RPC Protection: implemented.
9. File Change Detection: implemented via WP-Cron baseline scans.
10. Security Headers: implemented.
11. Admin Area Protection: implemented.
12. Security Dashboard: implemented.
