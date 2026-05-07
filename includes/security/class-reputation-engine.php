<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Reputation_Engine {
    private Secure_Guard_Rate_Limit_Repository $repository;
    private array $settings;
    private ?Secure_Guard_Lock_State $lock_state;

    public const TIER_NORMAL = 'normal';
    public const TIER_THROTTLED = 'throttled';
    public const TIER_CHALLENGED = 'challenged';
    public const TIER_BLOCKED = 'blocked';

    public function __construct(Secure_Guard_Rate_Limit_Repository $repository, array $settings, ?Secure_Guard_Lock_State $lock_state = null) {
        $this->repository = $repository;
        $this->settings = $settings;
        $this->lock_state = $lock_state;
    }

    public function get_score(string $ip): int {
        return $this->repository->get_reputation('rep:' . $ip);
    }

    public function add_score(string $ip, int $points, string $reason): void {
        if (empty($this->settings['reputation_enabled'])) {
            return;
        }

        $new_score = $this->repository->upsert_reputation('rep:' . $ip, $points);

        if ($points > 0) {
            $this->track_attack_velocity($points, $reason);
        }
    }

    private function track_attack_velocity(int $points, string $reason): void {
        if ($this->lock_state === null || !$this->lock_state->is_locked()) {
            $key = 'sg_attack_velocity';
            $velocity = (int) get_transient($key);
            $velocity += $points;
            set_transient($key, $velocity, 30); // 30 second window

            $threshold = (int) ($this->settings['lockdown_velocity_threshold'] ?? 500);
            if ($velocity >= $threshold && $this->lock_state !== null) {
                $this->lock_state->engage_lock(3600, 'Automatic: High attack velocity (' . $reason . ')');
            }
        }
    }

    public function get_tier(string $ip): string {
        $score = $this->get_score($ip);

        if ($score >= (int) ($this->settings['reputation_block_score'] ?? 100)) {
            return self::TIER_BLOCKED;
        }

        if ($score >= (int) ($this->settings['reputation_challenge_score'] ?? 50)) {
            return self::TIER_CHALLENGED;
        }

        if ($score >= (int) ($this->settings['reputation_throttle_score'] ?? 20)) {
            return self::TIER_THROTTLED;
        }

        return self::TIER_NORMAL;
    }

    public function decay(): void {
        // Decay score by 10% or at least 1 point
        $this->repository->decay_reputation(1);
    }
}
