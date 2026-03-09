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
        header('X-XSS-Protection: 1; mode=block', true);
        header('X-Content-Type-Options: nosniff', true);

        $csp = sanitize_text_field((string) ($this->settings['csp'] ?? "default-src 'self'"));
        if ($csp !== '') {
            header('Content-Security-Policy: ' . $csp, true);
        }

        if (!empty($this->settings['enable_hsts']) && is_ssl()) {
            $max_age = max(0, (int) ($this->settings['hsts_max_age'] ?? 31536000));
            header('Strict-Transport-Security: max-age=' . $max_age . '; includeSubDomains', true);
        }
    }
}
