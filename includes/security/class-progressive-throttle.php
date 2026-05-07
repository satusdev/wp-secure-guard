<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Progressive_Throttle {
    private array $settings;

    public function __construct(array $settings) {
        $this->settings = $settings;
    }

    public function apply(string $tier): void {
        if (empty($this->settings['progressive_throttle_enabled'])) {
            return;
        }

        $delay_ms = 0;

        switch ($tier) {
            case Secure_Guard_Reputation_Engine::TIER_CHALLENGED:
                $delay_ms = 1000;
                header('X-SG-Challenge: 1');
                break;
            case Secure_Guard_Reputation_Engine::TIER_THROTTLED:
                $delay_ms = 250;
                break;
        }

        if ($delay_ms > 0) {
            usleep($delay_ms * 1000);
        }
    }
}
