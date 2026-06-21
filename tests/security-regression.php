<?php

define('ABSPATH', __DIR__ . '/');

function sanitize_text_field($value) { return trim((string) $value); }
function __($value) { return $value; }
function is_user_logged_in() { return false; }

final class WP_Error {
    public string $code;
    public function __construct(string $code) { $this->code = $code; }
}

final class Secure_Guard_Log_Repository {
    public function log(...$args): void {}
}
final class Secure_Guard_Token_Manager {
    public function extract_bearer_token(): string { return ''; }
    public function validate_token($token) { return null; }
}
final class Secure_Guard_Rate_Limit {}
final class Secure_Guard_Endpoint_Blocker {}
final class Secure_Guard_Reputation_Engine {
    public const TIER_BLOCKED = 'blocked';
    public const TIER_CHALLENGED = 'challenged';
    public const TIER_THROTTLED = 'throttled';
    public function get_tier(string $ip): string { return self::TIER_BLOCKED; }
    public function add_score(...$args): void {}
}
final class Secure_Guard_Endpoint_Sensitivity {}
final class Secure_Guard_Lock_State {}

require_once dirname(__DIR__) . '/includes/security/class-ip-whitelist.php';
require_once dirname(__DIR__) . '/includes/security/class-rest-guard.php';

function expect_true(bool $condition, string $message): void {
    if (!$condition) {
        fwrite(STDERR, "FAIL: {$message}\n");
        exit(1);
    }
}

$settings = [
    'ip_whitelist' => "41.242.21.99/32\n192.168.0.0/16\n2001:db8::/32",
    'trusted_proxy_ips' => '10.0.0.0/8',
];
$whitelist = new Secure_Guard_IP_Whitelist($settings);
expect_true($whitelist->is_allowed('41.242.21.99'), 'exact management IP is trusted');
expect_true($whitelist->is_allowed('192.168.4.20'), 'private CIDR is trusted');
expect_true($whitelist->is_allowed('2001:db8::5'), 'IPv6 CIDR is trusted');
expect_true(!$whitelist->is_allowed('203.0.113.9'), 'unlisted IP remains untrusted');

$_SERVER = [
    'REMOTE_ADDR' => '10.0.0.2',
    'HTTP_X_FORWARDED_FOR' => '127.0.0.1, 41.242.21.99, 10.0.0.2',
];
expect_true($whitelist->get_request_ip() === '41.242.21.99', 'trusted proxy rejects a caller-prepended XFF address');

$guard = new Secure_Guard_REST_Guard(
    $settings,
    new Secure_Guard_Log_Repository(),
    new Secure_Guard_Token_Manager(),
    $whitelist,
    new Secure_Guard_Rate_Limit(),
    new Secure_Guard_Endpoint_Blocker(),
    new Secure_Guard_Reputation_Engine(),
    new Secure_Guard_Endpoint_Sensitivity(),
    new Secure_Guard_Lock_State()
);

$_SERVER = [
    'REMOTE_ADDR' => '41.242.21.99',
    'REQUEST_URI' => '/wp-json/wp/v2/plugins',
    'REQUEST_METHOD' => 'GET',
];
$trusted_result = $guard->authenticate(null);
expect_true($trusted_result instanceof WP_Error && $trusted_result->code === 'secure_guard_invalid_token', 'trusted IP bypasses reputation but not authentication');

$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
$blocked_result = $guard->authenticate(null);
expect_true($blocked_result instanceof WP_Error && $blocked_result->code === 'secure_guard_reputation_blocked', 'untrusted blocked reputation is enforced');

echo "security regression checks passed\n";
