<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Lock_State {
    private array $settings;
    private const TRANSIENT_KEY = 'sg_lock_state';
    private const OPTION_KEY = 'secure_guard_lock_state';

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function is_locked(): bool {
        if (empty($this->settings['lock_state_enabled'])) {
            return false;
        }

        return $this->get_lock_data() !== null;
    }

    public function engage_lock(int $duration_seconds = 3600, string $reason = 'Manual'): void {
        $data = [
            'locked_at' => time(),
            'reason'    => $reason,
            'expires'   => time() + $duration_seconds,
        ];

        set_transient(self::TRANSIENT_KEY, $data, $duration_seconds);
        update_option(self::OPTION_KEY, $data, false);
    }

    public function release_lock(): void {
        delete_transient(self::TRANSIENT_KEY);
        delete_option(self::OPTION_KEY);
    }

    public function get_lock_data(): ?array {
        $data = get_transient(self::TRANSIENT_KEY);
        if (!is_array($data)) {
            $data = get_option(self::OPTION_KEY, null);
        }

        if (!is_array($data)) {
            return null;
        }

        $expires = (int) ($data['expires'] ?? 0);
        if ($expires > 0 && $expires <= time()) {
            $this->release_lock();
            return null;
        }

        $ttl = $expires > time() ? $expires - time() : HOUR_IN_SECONDS;
        set_transient(self::TRANSIENT_KEY, $data, $ttl);

        return $data;
    }

    public function is_route_allowed_in_lockdown(string $route): bool {
        // Admin pages and whitelisted routes are allowed
        if (is_admin()) {
            return true;
        }

        // Add more logic here if needed (e.g. specific REST namespaces)
        return false;
    }
}
