<?php

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Email notification manager for security events.
 *
 * Each notification type uses a transient-based deduplication key so the
 * WordPress admin mailbox is not flooded if the same event fires repeatedly
 * within a short window.
 *
 * Dedup TTLs:
 *  - IP blocked:        1 hour  per unique IP
 *  - Integrity alert:   1 hour  (site-wide)
 *  - Token expiry:      1 day   per unique token id
 */
final class Secure_Guard_Alert_Manager {

    private array $settings;

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    // ──────────────────────────────────────────────────────────────────
    // Public API
    // ──────────────────────────────────────────────────────────────────

    /**
     * Send an alert when an IP is hard-blocked by the firewall or login
     * protection.
     *
     * @param string $ip             The IPv4/IPv6 address that was blocked.
     * @param string $reason         Human-readable reason (e.g. "Too many failed logins").
     * @param string $expires_until  UTC datetime string when the block expires.
     */
    public function notify_ip_blocked(string $ip, string $reason, string $expires_until): void {
        if (empty($this->settings['email_alerts_enabled'])) {
            return;
        }
        if (empty($this->settings['alert_on_hard_block'])) {
            return;
        }

        $dedup_key = 'sg_alert_ib_' . substr(md5($ip), 0, 12);
        if (get_transient($dedup_key)) {
            return;
        }
        set_transient($dedup_key, 1, HOUR_IN_SECONDS);

        $site  = get_bloginfo('name');
        $subj  = sprintf(
            /* translators: 1: site name, 2: IP address */
            __('[%1$s] Security Alert: IP %2$s blocked', 'secure-guard'),
            $site,
            $ip
        );

        $body  = sprintf(
            /* translators: 1: site name */
            __("Secure Guard has blocked an IP address on %s.\n\n", 'secure-guard'),
            $site
        );
        $body .= sprintf(__("IP Address : %s\n", 'secure-guard'), $ip);
        $body .= sprintf(__("Reason     : %s\n", 'secure-guard'), $reason);
        $body .= sprintf(__("Expires    : %s UTC\n", 'secure-guard'), $expires_until);
        $body .= "\n" . sprintf(
            /* translators: URL to blocked IPs admin page */
            __("Manage blocked IPs: %s\n", 'secure-guard'),
            admin_url('admin.php?page=secure-guard-blocked')
        );

        $this->send($subj, $body);
    }

    /**
     * Send an alert when the file integrity scan detects changes.
     *
     * @param int $change_count Number of changed/new/deleted files.
     */
    public function notify_integrity_alert(int $change_count): void {
        if (empty($this->settings['email_alerts_enabled'])) {
            return;
        }
        if (empty($this->settings['alert_on_integrity'])) {
            return;
        }

        $dedup_key = 'sg_alert_fi_dedup';
        if (get_transient($dedup_key)) {
            return;
        }
        set_transient($dedup_key, 1, HOUR_IN_SECONDS);

        $site = get_bloginfo('name');
        $subj = sprintf(
            /* translators: site name */
            __('[%s] Security Alert: File integrity changes detected', 'secure-guard'),
            $site
        );

        $body  = sprintf(
            /* translators: 1: number of files, 2: site name */
            __("Secure Guard detected %1\$d file change(s) on %2\$s.\n\n", 'secure-guard'),
            $change_count,
            $site
        );
        $body .= __("Core WordPress files (wp-admin, wp-includes) have changed since the last recorded baseline.\n", 'secure-guard');
        $body .= "\n" . __("To review and reset the baseline, visit the Security Dashboard:\n", 'secure-guard');
        $body .= admin_url('admin.php?page=secure-guard') . "\n";

        $this->send($subj, $body);
    }

    /**
     * Send an alert when a token is about to expire.
     *
     * @param array<string,mixed> $token_row Row from sg_tokens.
     */
    public function notify_token_expiry(array $token_row): void {
        if (empty($this->settings['email_alerts_enabled'])) {
            return;
        }

        $token_id  = (int) ($token_row['id'] ?? 0);
        $token_name = (string) ($token_row['name'] ?? 'Unknown');
        $expires_at = (string) ($token_row['expires_at'] ?? '');

        if ($token_id <= 0 || $expires_at === '') {
            return;
        }

        $dedup_key = 'sg_alert_te_' . substr(md5((string) $token_id), 0, 12);
        if (get_transient($dedup_key)) {
            return;
        }
        set_transient($dedup_key, 1, DAY_IN_SECONDS);

        $days_left = max(0, (int) ceil((strtotime($expires_at) - time()) / DAY_IN_SECONDS));
        $site      = get_bloginfo('name');
        $subj      = sprintf(
            /* translators: 1: site name, 2: token name */
            __('[%1$s] Security Alert: Token "%2$s" expiring soon', 'secure-guard'),
            $site,
            $token_name
        );

        $body  = sprintf(
            /* translators: 1: token name, 2: site name */
            __("The JWT token \"%1\$s\" on %2\$s is expiring soon.\n\n", 'secure-guard'),
            $token_name,
            $site
        );
        $body .= sprintf(__("Token ID   : %d\n", 'secure-guard'), $token_id);
        $body .= sprintf(__("Expires    : %s UTC\n", 'secure-guard'), $expires_at);
        $body .= sprintf(__("Days left  : %d\n", 'secure-guard'), $days_left);
        $body .= "\n" . sprintf(
            /* translators: URL to tokens admin page */
            __("Manage tokens: %s\n", 'secure-guard'),
            admin_url('admin.php?page=secure-guard-tokens')
        );

        $this->send($subj, $body);
    }

    // ──────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────

    private function send(string $subject, string $body): void {
        $to = (string) get_option('admin_email', '');
        if ($to === '') {
            return;
        }

        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        wp_mail($to, $subject, $body, $headers);
    }
}
