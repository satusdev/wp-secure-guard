<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Loader {
    public function action(string $hook, $callback, int $priority = 10, int $accepted_args = 1): void {
        add_action($hook, $callback, $priority, $accepted_args);
    }

    public function filter(string $hook, $callback, int $priority = 10, int $accepted_args = 1): void {
        add_filter($hook, $callback, $priority, $accepted_args);
    }
}
