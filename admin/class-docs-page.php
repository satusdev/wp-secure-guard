<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Docs_Page {
    public function register(): void {
        // Documentation has no form handlers yet. This keeps the page contract
        // consistent with other admin page classes.
    }

    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php esc_html_e('Documentation & Usage', 'secure-guard'); ?></h1>

            <div class="sg-docs-layout">
                <aside class="sg-docs-sidebar">
                    <nav class="sg-docs-nav" aria-label="<?php esc_attr_e('Secure Guard documentation sections', 'secure-guard'); ?>">
                        <ul>
                            <li><a href="#getting-started"><?php esc_html_e('Getting Started', 'secure-guard'); ?></a></li>
                            <li><a href="#security-assistant"><?php esc_html_e('Security Assistant', 'secure-guard'); ?></a></li>
                            <li><a href="#presets"><?php esc_html_e('Security Presets', 'secure-guard'); ?></a></li>
                            <li><a href="#jwt-authentication"><?php esc_html_e('JWT Authentication', 'secure-guard'); ?></a></li>
                            <li><a href="#rest-api-security"><?php esc_html_e('REST API Security', 'secure-guard'); ?></a></li>
                            <li><a href="#whitelists-compatibility"><?php esc_html_e('Whitelists & Compatibility', 'secure-guard'); ?></a></li>
                            <li><a href="#login-unban-recovery"><?php esc_html_e('Login & Unban Recovery', 'secure-guard'); ?></a></li>
                            <li><a href="#emergency-lockdown"><?php esc_html_e('Emergency Lockdown', 'secure-guard'); ?></a></li>
                            <li><a href="#adaptive-security"><?php esc_html_e('Adaptive Security', 'secure-guard'); ?></a></li>
                            <li><a href="#hardening"><?php esc_html_e('Hardening', 'secure-guard'); ?></a></li>
                            <li><a href="#logs-reports"><?php esc_html_e('Logs & Reports', 'secure-guard'); ?></a></li>
                            <li><a href="#troubleshooting"><?php esc_html_e('Troubleshooting', 'secure-guard'); ?></a></li>
                        </ul>
                    </nav>
                </aside>

                <main class="sg-docs-content">
                    <section id="getting-started" class="card">
                        <h2><?php esc_html_e('Getting Started', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Start with the Security Assistant, confirm the Balanced preset, configure JWT authentication, and add trusted infrastructure to Whitelists before enabling strict controls on a production site.', 'secure-guard'); ?></p>
                        <ol>
                            <li><?php printf(esc_html__('Open %s and review the top recommendations.', 'secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-assistant')) . '">' . esc_html__('Security Assistant', 'secure-guard') . '</a>'); ?></li>
                            <li><?php printf(esc_html__('Set a stable JWT secret in %s or by environment variable.', 'secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-settings&tab=rest-jwt')) . '">' . esc_html__('Settings → REST & JWT', 'secure-guard') . '</a>'); ?></li>
                            <li><?php printf(esc_html__('Add office, VPN, monitoring, and proxy addresses in %s.', 'secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-whitelists')) . '">' . esc_html__('Whitelists', 'secure-guard') . '</a>'); ?></li>
                        </ol>
                    </section>

                    <section id="security-assistant" class="card">
                        <h2><?php esc_html_e('Security Assistant', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Security Assistant is the primary operating page. It summarizes risk, active blocks, token status, the current preset, lockdown state, and recovery actions.', 'secure-guard'); ?></p>
                        <p><a class="button button-primary" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-assistant')); ?>"><?php esc_html_e('Open Security Assistant', 'secure-guard'); ?></a></p>
                    </section>

                    <section id="presets" class="card">
                        <h2><?php esc_html_e('Security Presets', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Presets update normal Secure Guard settings. Balanced is recommended for most sites because it keeps strong REST and login protection while avoiding avoidable plugin compatibility problems.', 'secure-guard'); ?></p>
                        <ul>
                            <li><strong><?php esc_html_e('Beginner:', 'secure-guard'); ?></strong> <?php esc_html_e('Safer defaults for new sites and compatibility testing.', 'secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Balanced:', 'secure-guard'); ?></strong> <?php esc_html_e('Recommended production baseline.', 'secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Maximum Security:', 'secure-guard'); ?></strong> <?php esc_html_e('Strict controls for high-risk periods. Confirm whitelists and API clients first.', 'secure-guard'); ?></li>
                        </ul>
                    </section>

                    <section id="jwt-authentication" class="card">
                        <h2><?php esc_html_e('JWT Authentication', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('External clients authenticate with Bearer JWTs. JWT issuer, audience, and secret may be managed in settings or by environment variables for Bedrock and other deployment pipelines.', 'secure-guard'); ?></p>
                        <pre><code>Authorization: Bearer YOUR_TOKEN_HERE</code></pre>
                        <p><?php esc_html_e('If an environment variable is active, Secure Guard shows an ENV badge and preserves the stored database value as a fallback.', 'secure-guard'); ?></p>
                    </section>

                    <section id="rest-api-security" class="card">
                        <h2><?php esc_html_e('REST API Security', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('JWT-only mode protects external REST requests. Logged-in browser sessions for allowed roles remain compatible with Gutenberg, media workflows, and page builders.', 'secure-guard'); ?></p>
                        <p><?php esc_html_e('REST Strict Mode hides unauthenticated REST discovery. Use allowed namespaces for public plugin endpoints such as contact forms.', 'secure-guard'); ?></p>
                    </section>

                    <section id="whitelists-compatibility" class="card">
                        <h2><?php esc_html_e('Whitelists & Compatibility', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Use the Whitelists page for global IP allow rules, admin-area allow rules, trusted proxy IPs, allowed REST namespaces, and role-based bypasses.', 'secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-whitelists')); ?>"><?php esc_html_e('Open Whitelists', 'secure-guard'); ?></a></p>
                    </section>

                    <section id="login-unban-recovery" class="card">
                        <h2><?php esc_html_e('Login & Unban Recovery', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Blocked IPs supports full unblocks, login-only recovery, selected bulk unblocks, and clearing all login lockouts. Full unblock clears firewall and login state. Login-only recovery preserves firewall blocks while allowing legitimate users to try again.', 'secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-blocked-ips')); ?>"><?php esc_html_e('Open Blocked IPs', 'secure-guard'); ?></a></p>
                    </section>

                    <section id="emergency-lockdown" class="card">
                        <h2><?php esc_html_e('Emergency Lockdown', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Emergency lockdown temporarily returns maintenance responses for unauthenticated public requests while allowing administrators to log in and recover. The lock state is stored in both a transient and persistent option so cache restarts do not silently remove an active lockdown.', 'secure-guard'); ?></p>
                    </section>

                    <section id="adaptive-security" class="card">
                        <h2><?php esc_html_e('Adaptive Security', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('The reputation engine scores suspicious behavior and can throttle, challenge, block, or trigger automatic lockdown when attack velocity crosses the configured threshold.', 'secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-settings&tab=adaptive-security')); ?>"><?php esc_html_e('Open Adaptive Security Settings', 'secure-guard'); ?></a></p>
                    </section>

                    <section id="hardening" class="card">
                        <h2><?php esc_html_e('Hardening', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Hardening options reduce WordPress fingerprinting, disable risky admin features, enforce security headers, and monitor core file integrity.', 'secure-guard'); ?></p>
                    </section>

                    <section id="logs-reports" class="card">
                        <h2><?php esc_html_e('Logs & Reports', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Use Logs for individual events, IP Reputation for risk scoring, and Dashboard for summaries. CSV exports are intended for security review and incident response.', 'secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-logs')); ?>"><?php esc_html_e('Open Logs', 'secure-guard'); ?></a></p>
                    </section>

                    <section id="troubleshooting" class="card">
                        <h2><?php esc_html_e('Troubleshooting', 'secure-guard'); ?></h2>
                        <h3><?php esc_html_e('A real user is locked out', 'secure-guard'); ?></h3>
                        <p><?php printf(esc_html__('Go to %s and clear login-only lockouts first. Use full unblock only when the IP should be trusted again.', 'secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-blocked-ips')) . '">' . esc_html__('Blocked IPs', 'secure-guard') . '</a>'); ?></p>
                        <h3><?php esc_html_e('An API client stopped working', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('Verify the token is active, the JWT secret/issuer/audience match the environment, and the required scope is assigned.', 'secure-guard'); ?></p>
                        <h3><?php esc_html_e('A monitoring tool is blocked', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('Add its source IP to the Global IP Whitelist and confirm proxy IP detection is configured if the site runs behind Cloudflare, Varnish, or a load balancer.', 'secure-guard'); ?></p>
                    </section>
                </main>
            </div>
        </div>
        <?php
    }
}
