<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_IP_Whitelist {
    private array $settings;

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function get_request_ip(): string {
        $candidates = [];

        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $candidates[] = (string) $_SERVER['HTTP_CF_CONNECTING_IP'];
        }

        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwarded = explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']);
            foreach ($forwarded as $ip) {
                $candidates[] = trim($ip);
            }
        }

        if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
            $candidates[] = (string) $_SERVER['HTTP_X_REAL_IP'];
        }

        if (!empty($_SERVER['REMOTE_ADDR'])) {
            $candidates[] = (string) $_SERVER['REMOTE_ADDR'];
        }

        foreach ($candidates as $candidate) {
            $candidate = sanitize_text_field($candidate);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return '0.0.0.0';
    }

    public function is_allowed(string $ip, ?string $token_ips = null): bool {
        $global_list = trim((string) ($this->settings['ip_whitelist'] ?? ''));
        $token_list = trim((string) ($token_ips ?? ''));

        if ($global_list === '' && $token_list === '') {
            return true;
        }

        return $this->ip_in_list($ip, $global_list) || $this->ip_in_list($ip, $token_list);
    }

    private function ip_in_list(string $ip, string $raw_list): bool {
        if ($raw_list === '') {
            return false;
        }

        $entries = preg_split('/\r\n|\r|\n/', $raw_list) ?: [];
        foreach ($entries as $entry) {
            $entry = trim($entry);
            if ($entry === '') {
                continue;
            }
            if ($entry === $ip) {
                return true;
            }
            if (str_contains($entry, '/') && $this->match_cidr($ip, $entry)) {
                return true;
            }
        }

        return false;
    }

    private function match_cidr(string $ip, string $cidr): bool {
        [$subnet, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
        if ($subnet === null || $bits === null || !is_numeric($bits)) {
            return false;
        }

        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);

        if ($ip_long === false || $subnet_long === false) {
            return false;
        }

        $bits = (int) $bits;
        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));

        return (($ip_long & $mask) === ($subnet_long & $mask));
    }
}
