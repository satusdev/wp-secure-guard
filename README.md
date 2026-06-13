# Secure Guard

[![WordPress Version](https://img.shields.io/badge/WordPress-6.4%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-8.1%2B-8892BF.svg)](https://www.php.net/)
[![License](https://img.shields.io/badge/License-GPL--2.0--or--later-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

**Secure Guard** is a professional-grade, high-performance security plugin for WordPress designed to enforce strict JWT-only REST API authentication, block sensitive endpoints, protect against bot traffic, secure the login interface, and monitor core file integrity.

It is specifically engineered for decoupled architectures (headless WordPress), modern hosting stacks (like Bedrock/Sage), and production environments requiring resilient, automated shielding.

---

## Table of Contents

- [Core Features](#core-features)
- [Architecture & Runtime Flow](#architecture--runtime-flow)
  - [The Watchdog MU-Plugin](#the-watchdog-mu-plugin)
  - [Request Validation Pipeline](#request-validation-pipeline)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Settings Option Structure](#settings-option-structure)
  - [Environment Variables (Bedrock/Docker)](#environment-variables-bedrockdocker)
- [Security Presets](#security-presets)
- [Whitelists & Allowed Bot Services](#whitelists--allowed-bot-services)
- [API Client Authentication (JWT)](#api-client-authentication-jwt)
- [Database Schema Reference](#database-schema-reference)
- [Developer Hooks (Filters & Actions)](#developer-hooks-filters--actions)
- [Troubleshooting & Recovery](#troubleshooting--recovery)
- [License](#license)

---

## Core Features

### 1. REST API Lockdown & Hardening
*   **JWT-Only REST Access:** Restricts REST API endpoints to authenticated JSON Web Token (JWT) clients.
*   **Zero Cookie Bypass:** Removes cookie/session-based authentication for external REST requests, preventing session hijacking or accidental bypasses.
*   **REST Strict Mode:** Completely disables the REST API for all unauthenticated users and strips REST API discovery links from headers.
*   **Fallback Users Block:** Disables the standard user endpoint fallback (`/wp/v2/users`) in tough security modes.

### 2. Traffic Firewall & Adaptive Security
*   **Behavioral Bot Fingerprinting:** Analyzes request headers and User-Agent patterns to assign a bot score (0-100), automatically blocking headless browsers and scrapers.
*   **Bad Bot Blocking:** Rejects known malicious User-Agents, command-line utilities (like curl, python-requests, wget), and security scanners.
*   **Progressive Throttling:** Artificially delays suspicious requests dynamically based on the IP's reputation score.
*   **Emergency Lockdown:** Fallback emergency lockdown (`secure_guard_lock_state`) to temporarily return `503 Service Unavailable` to public unauthenticated requests while allowing administrators to log in.

### 3. Login Endpoint & User Protections
*   **Escalating Lockouts:** Tracks failed login attempts and applies progressive transients and database-level IP blocks.
*   **User Enumeration Protection:** Detects and blocks author query string scans (`/?author=N`), author slug archives, and direct user REST routing probes.
*   **XML-RPC Shield:** Shuts down direct requests to `/xmlrpc.php` and Bedrock `/wp/xmlrpc.php` paths.

### 4. Hardening & Fingerprint Reduction
*   **WordPress Version Hiding:** Strips generator meta tags, style/script version parameters, and blocks public exposure of `readme.html` or `license.txt`.
*   **Security Header Injection:** Configures robust modern HTTP security headers including balanced Content Security Policy (CSP), `Referrer-Policy`, `Permissions-Policy`, cross-origin policies (COOP/CORP), and HTTP Strict Transport Security (HSTS).
*   **Public WP-Cron Protection:** Rejects external HTTP requests targeting `wp-cron.php` while preserving CLI and loopback crons.
*   **Self-Protection:** Guards itself against accidental or malicious deactivation from the WordPress administrator panel.

### 5. File Integrity Monitoring
*   **Checksum Verification:** Periodically scans core directories (`wp-admin` and `wp-includes`) against official WordPress checksum baselines and generates email/admin alerts for modifications.

---

## Architecture & Runtime Flow

Secure Guard separates data persistence (`includes/data/*`), core policy logic (`includes/security/*`), and administrative experience (`admin/*`) to maintain a lean, highly maintainable codebase.

### The Watchdog MU-Plugin

To prevent performance degradation and ensure the highest security profile, Secure Guard automatically deploys a lightweight **Watchdog** plugin directly into the WordPress Must-Use (MU) plugins directory (`wp-content/mu-plugins/secure-guard-watchdog.php`).

```mermaid
graph TD
    A[Incoming HTTP Request] --> B[WordPress Bootstrap: mu-plugins]
    B --> C[Secure Guard Watchdog MU-Plugin]
    C -->|Emergency Lockdown Active?| D[503 Service Unavailable]
    C -->|IP in Reputation DB Block List?| E[403 Forbidden]
    C -->|IP / UA in Transients Block List?| F[403 Forbidden]
    C -->|Passed Watchdog Gate| G[Load Active Plugins & Themes]
    G --> H[Secure Guard Core hooks on init / rest_pre_dispatch]
```

#### Why a Watchdog?
1.  **Fast Path Blocking:** Rejects blacklisted IPs and handles emergency lockdown state *before* WordPress parses the main plugin file, the active theme, or database queries.
2.  **Reactivation Lock:** Maintains security configurations and emergency lockdowns even if a database update or user action attempts to deactivate the main plugin.

### Request Validation Pipeline

When the request proceeds to the main plugin bootstrap, the guard pipeline evaluates hooks in the following sequence:

1.  **IP Whitelist Check (Global):** If the client IP is whitelisted, the firewall bypasses all subsequent block and rate-limiting gates.
2.  **Reputation Scoring & Delay:** Evaluates IP history and applies progressive delay (progressive throttle).
3.  **Endpoint Checks:** Checks for public wp-cron access, sensitive path access (`.env`, `debug.log`), and User-Agent bad bot signatures.
4.  **REST API Filter Gate:** Restricts endpoint queries and validates JWT bearer scopes.

---

## Installation

### Manual Installation
1.  Upload the `wp-secure-guard` folder to your `/wp-content/plugins/` directory.
2.  Run `composer install` inside the plugin folder to install PHP JWT dependencies.
3.  Activate the plugin through the **Plugins** menu in WordPress.

### Composer (Bedrock)
Add the repository source to your Bedrock `composer.json` file:
```json
{
  "require": {
    "satusdev/wp-secure-guard": "^1.1.2"
  }
}
```
Run `composer update` and activate the plugin. The Must-Use watchdog plugin will be deployed automatically to `/app/mu-plugins/` (or your configured path).

---

## Configuration

### Settings Option Structure

Secure Guard stores all settings under a single option key `secure_guard_settings` to keep database reads extremely efficient. High-frequency transient data is cached separately.

### Environment Variables (Bedrock/Docker)

For staging-to-production deployment configurations, you should manage your cryptographic secrets and endpoint parameters via environment variables (e.g. in your Bedrock `.env` file). Environment variable overrides take priority over database settings:

| Settings Tab | Database Key | Env Variable Override | Description |
| :--- | :--- | :--- | :--- |
| **REST & JWT** | `jwt_secret` | `SECURE_GUARD_JWT_SECRET` | Secret key used to sign and verify JWT tokens. |
| **REST & JWT** | `jwt_issuer` | `SECURE_GUARD_JWT_ISSUER` | Token issuer URL. |
| **REST & JWT** | `jwt_audience` | `SECURE_GUARD_JWT_AUDIENCE` | Token audience URL. |

> [!TIP]
> Setting the same `SECURE_GUARD_JWT_ISSUER` and `SECURE_GUARD_JWT_AUDIENCE` across staging and production ensures that active API client tokens survive database cloning operations without re-signing.

---

## Security Presets

Secure Guard features pre-configured security profiles that map to setting keys, accessible through the **Security Assistant**:

| Preset | Target Environment | Strategy |
| :--- | :--- | :--- |
| **Beginner** | Blogs, creators, brochure sites | Standard security with low false-positive rates. Public WP-Cron is allowed; rate limits are high. |
| **Balanced** (Recommended) | Production business & e-commerce | Strongly locked REST API, moderate rate limits (100 req/min), blocked public WP-Cron, and enabled reputation engine. |
| **Maximum Security** | Headless APIs, SaaS portals, admin panels | Strict REST Mode enabled. Aggressive limits (45 req/min), short login lockout thresholds, and immediate lockdown under high threat velocity. |
| **Custom** | Tailored integrations | Displays when database values diverge from standard presets. |

---

## Whitelists & Allowed Bot Services

The **Whitelists** tab lets you configure bypass lists to ensure legitimate clients are never locked out:

### Global IP Whitelist
Specify individual IPv4/IPv6 addresses or CIDR blocks (e.g., `192.168.1.0/24`, `2001:db8::/32`). These IPs bypass all rate limiting, reputation drops, and bot fingerprinting blocks.

### Allowed Bot User-Agents / Ping Services
If you run remote monitors, ping tools, or uptime sensors (such as UptimeRobot, Pingdom, BetterStack, or custom monitoring scripts), their request headers will often fail the behavioral bot fingerprint test due to missing browser headers, causing them to get blocked.

To allow them to ping your site safely:
1.  Go to **Security API Guard** -> **Whitelists**.
2.  Locate **Allowed Bot User-Agents / Ping Services**.
3.  Add the User-Agent substring you want to permit (e.g., `UptimeRobot`, `Pingdom`).
4.  Use the **Quick Allow Bot Services** buttons to automatically add common monitoring headers with one click.

---

## API Client Authentication (JWT)

Secure Guard tokens are cryptographically secure JWTs.

### Request Format
All client HTTP requests to protected REST endpoints must present the token via the `Authorization` header:

```http
GET /wp-json/wp/v2/posts HTTP/1.1
Host: example.com
Authorization: Bearer YOUR_GENERATED_JWT_TOKEN
```

### Valid Scopes
Tokens can be configured with specific granular permission scopes:

-   `read_posts` / `write_posts`
-   `read_media` / `write_media`
-   `read_users` / `write_users`
-   `read_settings`
-   `full_api_access` (Required for sensitive endpoints like `settings` or `plugins` even with valid token)

---

## Database Schema Reference

On activation, the installer creates four custom database tables to support log auditing, rate limiting, and token management:

### `{prefix}sg_tokens`
Stores metadata and configurations for generated API tokens.
*   `id`: unique token identifier (BigInt)
*   `name`: descriptive label
*   `token_type`: `static` or `jwt`
*   `token_hash`: SHA-256 hash of the token
*   `jti`/`kid`: JWT unique identifier and key ID
*   `scope`: comma-separated permissions
*   `allowed_ips`/`allowed_endpoints`: restriction rules
*   `expires_at`/`revoked_at`: validation timestamps

### `{prefix}sg_jwt_denylist`
Revoked tokens list used for invalidating tokens prior to their natural expiration date.
*   `jti`: revoked token identifier
*   `revoked_until`: timestamp when the token naturally expires

### `{prefix}sg_logs`
Detailed security audit trail.
*   `ip`: requester client IP
*   `endpoint`/`method`: request target and verb
*   `result`: `ALLOWED` or `BLOCKED`
*   `reason`: reason for denial or event detail
*   `attack_cluster`: categorizes security event patterns (e.g., brute-force, path-traversal)
*   `context`: JSON payload containing request metadata

### `{prefix}sg_rate_limits`
Tracks rate limiting metrics and client reputation.
*   `subject`: subject string (e.g., `traffic:{ip}`, `rep:{ip}`)
*   `hit_count`: requests made in current window
*   `reputation_score`: score value (0-100+) representing client threat level
*   `blocked_until`: lockout release timestamp

---

## Developer Hooks (Filters & Actions)

Extend or customize Secure Guard behaviors using standard WordPress hooks.

### Action Hooks

*   `do_action('secure_guard_integrity_scan')`
    Triggers a manual file integrity scan.
*   `do_action('secure_guard_log_retention_purge')`
    Triggers the cleanup of expired logs based on configured retention duration.
*   `do_action('secure_guard_reputation_decay')`
    Fires on the decay scheduled task to slowly restore IP reputation.

### Filter Hooks

*   `apply_filters('rest_authentication_errors', $errors)`
    Evaluates REST client JWT validation.
*   `apply_filters('rest_pre_dispatch', $result, $server, $request)`
    Evaluates endpoints before processing for sensitive path locks.
*   `apply_filters('pre_update_option_active_plugins', $new_value, $old_value)`
    Enforces the self-protection mechanism for the active plugins option.

---

## Troubleshooting & Recovery

### A Real User is Locked Out
*   **Action:** Navigate to **Security API Guard** -> **Blocked IPs**.
*   **Resolution:** Select the IP and trigger a **Login-Only Unblock** to clear their failed login attempts counter while preserving the traffic firewall state. Use **Full Unblock** to clear both states completely.

### Monitoring/Ping Service is Blocked
*   **Symptoms:** Monitor dashboard reports `403 Forbidden` from WordPress, and the Secure Guard audit logs record `Malicious bot behavior blocked`.
*   **Resolution:** Ensure the monitor's User-Agent string is added to the **Allowed Bot User-Agents / Ping Services** list in the **Whitelists** settings tab, or add the source IP to the **Global IP Whitelist**.

### Lost Administrator Access during Lockdown
If an active lockdown blocks access to the admin panel:
1.  Log in to your hosting server via SSH/FTP.
2.  Navigate to your database (e.g., via WP-CLI or phpMyAdmin).
3.  Delete the lockdown parameters by running the following SQL commands:
    ```sql
    DELETE FROM wp_options WHERE option_name = 'secure_guard_lock_state';
    DELETE FROM wp_options WHERE option_name = '_transient_sg_lock_state';
    ```
4.  If self-protection prevents plugin disabling, you can force-deactivate the plugin via WP-CLI:
    ```bash
    wp plugin deactivate secure-guard --skip-plugins
    ```

---

## License

This project is licensed under the GPL-2.0-or-later License. See the `LICENSE` file or [GNU GPL](https://www.gnu.org/licenses/gpl-2.0.html) details.
