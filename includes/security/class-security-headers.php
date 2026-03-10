<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Security_Headers {
    private array $settings;

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function send(): void {
        header('X-Frame-Options: SAMEORIGIN', true);
        header('X-Content-Type-Options: nosniff', true);
        header('Referrer-Policy: ' . sanitize_text_field((string) ($this->settings['referrer_policy'] ?? 'strict-origin-when-cross-origin')), true);
        header('Permissions-Policy: ' . sanitize_text_field((string) ($this->settings['permissions_policy'] ?? 'camera=(), microphone=(), geolocation=()')), true);

        if (!empty($this->settings['enable_coop'])) {
            header('Cross-Origin-Opener-Policy: same-origin', true);
        }

        if (!empty($this->settings['enable_corp'])) {
            header('Cross-Origin-Resource-Policy: same-site', true);
        }

        header('X-Permitted-Cross-Domain-Policies: none', true);

        $csp = sanitize_text_field((string) ($this->settings['csp'] ?? ''));
        if ($csp !== '') {
            header('Content-Security-Policy: ' . $csp, true);
        }

        if (!empty($this->settings['enable_hsts']) && is_ssl()) {
            $max_age = max(0, (int) ($this->settings['hsts_max_age'] ?? 31536000));
            header('Strict-Transport-Security: max-age=' . $max_age . '; includeSubDomains', true);
        }
    }
}
