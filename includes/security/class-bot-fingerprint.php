<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Bot_Fingerprint {
    private array $settings;

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function analyze(): int {
        if (empty($this->settings['bot_fingerprint_enabled'])) {
            return 0;
        }

        $score = 0;
        $ua = strtolower(sanitize_text_field((string) ($_SERVER['HTTP_USER_AGENT'] ?? '')));

        // 1. Missing or Anomalous Headers
        $required_headers = [
            'HTTP_ACCEPT_LANGUAGE' => 15,
            'HTTP_SEC_FETCH_SITE'  => 10,
            'HTTP_SEC_FETCH_MODE'  => 10,
            'HTTP_SEC_FETCH_DEST'  => 10,
        ];

        foreach ($required_headers as $header => $weight) {
            if (empty($_SERVER[$header])) {
                $score += $weight;
            }
        }

        // 2. Client Hints Consistency
        $ch_ua = sanitize_text_field((string) ($_SERVER['HTTP_SEC_CH_UA'] ?? ''));
        if ($ch_ua !== '') {
            $ua_chrome = str_contains($ua, 'chrome');
            $ch_chrome = str_contains(strtolower($ch_ua), 'chrome') || str_contains(strtolower($ch_ua), 'chromium');
            if ($ua_chrome !== $ch_chrome) {
                $score += 35;
            }
        }

        // 3. Accept Header Quality
        $accept = strtolower(sanitize_text_field((string) ($_SERVER['HTTP_ACCEPT'] ?? '')));
        if ($accept === '*/*' || $accept === '') {
            if (!defined('REST_REQUEST') && !str_contains($ua, 'wordpress')) {
                $score += 20;
            }
        }

        // 4. Headless & Bot Indicators
        $indicators = [
            'headlesschrome', 'phantomjs', 'selenium', 'puppeteer', 'playwright',
            'python-requests', 'go-http-client', 'java/', 'curl/', 'wget/', 'libwww-perl',
            'scrper', 'crawler', 'spider', 'bot/'
        ];
        foreach ($indicators as $indicator) {
            if (str_contains($ua, $indicator)) {
                $score += 50;
            }
        }

        // 5. User-Agent length
        if (strlen($ua) < 15) {
            $score += 25;
        }

        return min(100, $score);
    }
}
