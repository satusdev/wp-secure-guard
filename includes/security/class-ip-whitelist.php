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
        $remote_addr = sanitize_text_field((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        $candidates = [];

        if ($this->is_trusted_proxy($remote_addr)) {
            if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
                $candidates[] = (string) $_SERVER['HTTP_CF_CONNECTING_IP'];
            }

            if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                // Walk from the proxy nearest WordPress toward the client.
                // This prevents a caller-prepended XFF value from winning.
                $forwarded = array_reverse(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR']));
                foreach ($forwarded as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP) && !$this->is_trusted_proxy($ip)) {
                        $candidates[] = $ip;
                        break;
                    }
                }
            }

            if (!empty($_SERVER['HTTP_X_REAL_IP'])) {
                $candidates[] = (string) $_SERVER['HTTP_X_REAL_IP'];
            }
        }

        // Fall back to the socket peer. For trusted proxies the verified
        // forwarding headers above must take precedence over the proxy address.
        if ($remote_addr !== '') {
            $candidates[] = $remote_addr;
        }

        foreach ($candidates as $candidate) {
            $candidate = sanitize_text_field($candidate);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }

        return $this->normalize_fallback_ip($remote_addr);
    }

    public function is_allowed(string $ip, ?string $token_ips = null): bool {
        // Always allow localhost loopbacks and CLI fallback IPs
        if ($ip === '127.0.0.1' || $ip === '::1' || $ip === '0.0.0.0') {
            return true;
        }

        // Always allow server's own public/internal IPs to prevent self-blocking
        $server_ips = $this->get_server_ips();
        if (in_array($ip, $server_ips, true)) {
            return true;
        }

        $global_list = trim((string) ($this->settings['ip_whitelist'] ?? ''));
        $token_list = trim((string) ($token_ips ?? ''));

        if ($global_list === '' && $token_list === '') {
            return false;
        }

        return $this->ip_in_list($ip, $global_list) || $this->ip_in_list($ip, $token_list);
    }

    /**
     * Public facade for checking whether $ip matches any entry in a newline-delimited
     * list string (exact IP or CIDR range). Used by modules that maintain their own
     * allow-lists separate from the global whitelist setting.
     */
    public function check_list(string $ip, string $raw_list): bool {
        return $this->ip_in_list($ip, $raw_list);
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

        if (!filter_var($ip, FILTER_VALIDATE_IP) || !filter_var($subnet, FILTER_VALIDATE_IP)) {
            return false;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return $this->match_cidr_v4($ip, $subnet, (int) $bits);
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return $this->match_cidr_v6($ip, $subnet, (int) $bits);
        }

        return false;
    }

    private function match_cidr_v4(string $ip, string $subnet, int $bits): bool {
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);

        if ($ip_long === false || $subnet_long === false) {
            return false;
        }

        if ($bits < 0 || $bits > 32) {
            return false;
        }

        $mask = $bits === 0 ? 0 : (-1 << (32 - $bits));

        return (($ip_long & $mask) === ($subnet_long & $mask));
    }

    private function match_cidr_v6(string $ip, string $subnet, int $bits): bool {
        if ($bits < 0 || $bits > 128) {
            return false;
        }

        $ip_bin = @inet_pton($ip);
        $subnet_bin = @inet_pton($subnet);
        if ($ip_bin === false || $subnet_bin === false) {
            return false;
        }

        $full_bytes = intdiv($bits, 8);
        $remaining_bits = $bits % 8;

        if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($subnet_bin, 0, $full_bytes)) {
            return false;
        }

        if ($remaining_bits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remaining_bits)) & 0xFF;
        $ip_byte = ord($ip_bin[$full_bytes]);
        $subnet_byte = ord($subnet_bin[$full_bytes]);

        return (($ip_byte & $mask) === ($subnet_byte & $mask));
    }

    private function is_trusted_proxy(string $remote_addr): bool {
        if ($remote_addr === '') {
            return false;
        }

        $proxy_list = trim((string) ($this->settings['trusted_proxy_ips'] ?? ''));
        if ($proxy_list === '') {
            return false;
        }

        return $this->ip_in_list($remote_addr, $proxy_list);
    }

    private function normalize_fallback_ip(string $remote_addr): string {
        if (filter_var($remote_addr, FILTER_VALIDATE_IP)) {
            return $remote_addr;
        }

        return '0.0.0.0';
    }

    /**
     * Resolves the server's own public and internal IPs and caches them.
     */
    private function get_server_ips(): array {
        $cache_key = 'sg_server_ips';
        $ips = get_transient($cache_key);
        if (is_array($ips)) {
            return $ips;
        }

        $ips = [];
        $server_addr = $_SERVER['SERVER_ADDR'] ?? '';
        if ($server_addr && filter_var($server_addr, FILTER_VALIDATE_IP)) {
            $ips[] = $server_addr;
        }

        // Resolve the site domain name to get its public IPs
        $url = function_exists('site_url') ? site_url() : '';
        if ($url) {
            $host = parse_url($url, PHP_URL_HOST);
            if ($host) {
                // Get IPv4
                $ip_v4 = gethostbyname($host);
                if ($ip_v4 && $ip_v4 !== $host && filter_var($ip_v4, FILTER_VALIDATE_IP)) {
                    $ips[] = $ip_v4;
                }
                // Get IPv6 (AAAA records)
                if (function_exists('dns_get_record')) {
                    $records = @dns_get_record($host, DNS_AAAA);
                    if (is_array($records)) {
                        foreach ($records as $record) {
                            if (!empty($record['ipv6']) && filter_var($record['ipv6'], FILTER_VALIDATE_IP)) {
                                    $ips[] = $record['ipv6'];
                            }
                        }
                    }
                }
            }
        }

        $ips = array_unique(array_filter($ips));
        set_transient($cache_key, $ips, DAY_IN_SECONDS);
        return $ips;
    }
}
