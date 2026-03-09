<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Rate_Limit {
    private Secure_Guard_Rate_Limit_Repository $repository;
    private array $settings;

    public function __construct(Secure_Guard_Rate_Limit_Repository $repository, array $settings) {
        $this->repository = $repository;
        $this->settings = $settings;
    }

    public function allow(string $subject, ?int $token_limit = null): bool {
        $limit = $token_limit && $token_limit > 0 ? $token_limit : (int) ($this->settings['rate_limit_per_minute'] ?? 100);
        return $this->allow_with_policy($subject, $limit, 60, 60);
    }

    public function allow_with_policy(string $subject, int $limit, int $window_seconds, int $block_seconds): bool {
        $now = time();
        $window_start = gmdate('Y-m-d H:i:s', $now - max(1, $window_seconds));
        $current = $this->repository->get($subject);

        if (!$current) {
            $this->repository->upsert($subject, gmdate('Y-m-d H:i:s', $now), 1, null);
            return true;
        }

        if (!empty($current['blocked_until']) && strtotime((string) $current['blocked_until']) > $now) {
            return false;
        }

        $started_at = strtotime((string) $current['window_started_at']) ?: 0;
        $hit_count = (int) $current['hit_count'];

        if ($started_at < strtotime($window_start)) {
            $this->repository->upsert($subject, gmdate('Y-m-d H:i:s', $now), 1, null);
            return true;
        }

        $hit_count++;
        if ($hit_count > $limit) {
            $this->repository->upsert($subject, (string) $current['window_started_at'], $hit_count, gmdate('Y-m-d H:i:s', $now + max(1, $block_seconds)));
            return false;
        }

        $this->repository->upsert($subject, (string) $current['window_started_at'], $hit_count, null);
        return true;
    }
}
