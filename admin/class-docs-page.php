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
            wp_die(esc_html__('Unauthorized', 'wp-secure-guard'));
        }

        ?>
        <div class="wrap secure-guard-ui">
            <h1><span class="dashicons dashicons-book-alt" style="font-size:28px;width:28px;height:28px;color:var(--sg-primary);"></span> <?php esc_html_e('Documentation & Usage', 'wp-secure-guard'); ?></h1>
            <p class="description"><?php esc_html_e('Guides for JWT authentication, REST API security, hardening, and incident response.', 'wp-secure-guard'); ?></p>

            <div class="sg-docs-quicknav">
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-assistant')); ?>">
                    <span class="dashicons dashicons-shield-alt"></span>
                    <?php esc_html_e('Security Assistant', 'wp-secure-guard'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-settings')); ?>">
                    <span class="dashicons dashicons-admin-settings"></span>
                    <?php esc_html_e('Settings', 'wp-secure-guard'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-whitelists')); ?>">
                    <span class="dashicons dashicons-yes-alt"></span>
                    <?php esc_html_e('Whitelists', 'wp-secure-guard'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-logs')); ?>">
                    <span class="dashicons dashicons-list-view"></span>
                    <?php esc_html_e('Logs', 'wp-secure-guard'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-blocked-ips')); ?>">
                    <span class="dashicons dashicons-dismiss"></span>
                    <?php esc_html_e('Blocked IPs', 'wp-secure-guard'); ?>
                </a>
                <a href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-tokens')); ?>">
                    <span class="dashicons dashicons-admin-network"></span>
                    <?php esc_html_e('Tokens', 'wp-secure-guard'); ?>
                </a>
            </div>

            <div class="sg-docs-layout">
                <aside class="sg-docs-sidebar">
                    <nav class="sg-docs-nav" id="sg-docs-nav" aria-label="<?php esc_attr_e('Secure Guard documentation sections', 'wp-secure-guard'); ?>">
                        <span class="sg-docs-nav-group-label"><?php esc_html_e('Overview', 'wp-secure-guard'); ?></span>
                        <ul>
                            <li><a href="#getting-started" data-section="getting-started"><span class="dashicons dashicons-welcome-learn-more" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Getting Started', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#security-assistant" data-section="security-assistant"><span class="dashicons dashicons-shield-alt" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Security Assistant', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#presets" data-section="presets"><span class="dashicons dashicons-admin-settings" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Security Presets', 'wp-secure-guard'); ?></a></li>
                        </ul>
                        <span class="sg-docs-nav-group-label"><?php esc_html_e('Features', 'wp-secure-guard'); ?></span>
                        <ul>
                            <li><a href="#jwt-authentication" data-section="jwt-authentication"><span class="dashicons dashicons-lock" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('JWT Authentication', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#rest-api-security" data-section="rest-api-security"><span class="dashicons dashicons-rest-api" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('REST API Security', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#whitelists-compatibility" data-section="whitelists-compatibility"><span class="dashicons dashicons-yes-alt" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Whitelists', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#adaptive-security" data-section="adaptive-security"><span class="dashicons dashicons-chart-line" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Adaptive Security', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#hardening" data-section="hardening"><span class="dashicons dashicons-hammer" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Hardening', 'wp-secure-guard'); ?></a></li>
                        </ul>
                        <span class="sg-docs-nav-group-label"><?php esc_html_e('Operations', 'wp-secure-guard'); ?></span>
                        <ul>
                            <li><a href="#login-unban-recovery" data-section="login-unban-recovery"><span class="dashicons dashicons-admin-users" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Login & Unban', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#emergency-lockdown" data-section="emergency-lockdown"><span class="dashicons dashicons-warning" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Emergency Lockdown', 'wp-secure-guard'); ?></a></li>
                            <li><a href="#logs-reports" data-section="logs-reports"><span class="dashicons dashicons-list-view" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Logs & Reports', 'wp-secure-guard'); ?></a></li>
                        </ul>
                        <span class="sg-docs-nav-group-label"><?php esc_html_e('Help', 'wp-secure-guard'); ?></span>
                        <ul>
                            <li><a href="#troubleshooting" data-section="troubleshooting"><span class="dashicons dashicons-sos" style="font-size:14px;width:14px;height:14px;"></span> <?php esc_html_e('Troubleshooting', 'wp-secure-guard'); ?></a></li>
                        </ul>
                    </nav>
                </aside>

                <main class="sg-docs-content">
                    <section id="getting-started" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-welcome-learn-more"></span></span><?php esc_html_e('Getting Started', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Start with the Security Assistant, confirm the Balanced preset, configure JWT authentication, and add trusted infrastructure to Whitelists before enabling strict controls on a production site.', 'wp-secure-guard'); ?></p>
                        <ol>
                            // translators: %s: link to Security Assistant page
                            <li><?php echo wp_kses_post(sprintf(esc_html__('Open %s and review the top recommendations.', 'wp-secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-assistant')) . '">' . esc_html__('Security Assistant', 'wp-secure-guard') . '</a>')); ?></li>
                            // translators: %s: link to Settings REST & JWT tab
                            <li><?php echo wp_kses_post(sprintf(esc_html__('Set a stable JWT secret in %s or by environment variable.', 'wp-secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-settings&tab=rest-jwt')) . '">' . esc_html__('Settings → REST & JWT', 'wp-secure-guard') . '</a>')); ?></li>
                            // translators: %s: link to Whitelists page
                            <li><?php echo wp_kses_post(sprintf(esc_html__('Add office, VPN, monitoring, and proxy addresses in %s.', 'wp-secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-whitelists')) . '">' . esc_html__('Whitelists', 'wp-secure-guard') . '</a>')); ?></li>
                        </ol>
                    </section>

                    <section id="security-assistant" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-shield-alt"></span></span><?php esc_html_e('Security Assistant', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Security Assistant is the primary operating page. It summarizes risk, active blocks, token status, the current preset, lockdown state, and recovery actions.', 'wp-secure-guard'); ?></p>
                        <p><?php esc_html_e('The operations overview uses the same Safe, Review, and Opt-in language as Bedrock Forge. Use it to confirm whether protections are routine, need review, or should only run during an incident.', 'wp-secure-guard'); ?></p>
                        <ul>
                            <li><?php esc_html_e('Safe hardening covers low-risk controls such as headers, sensitive file blocking, and admin editor lockdown.', 'wp-secure-guard'); ?></li>
                            <li><?php esc_html_e('Bedrock app shield checks direct access to app path files such as .env, logs, package metadata, and unknown extensionless files.', 'wp-secure-guard'); ?></li>
                            <li><?php esc_html_e('Risky repair/update actions should be run deliberately from Forge or during an incident with logs open.', 'wp-secure-guard'); ?></li>
                        </ul>
                        <p><a class="button button-primary" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-assistant')); ?>"><?php esc_html_e('Open Security Assistant', 'wp-secure-guard'); ?></a></p>
                    </section>

                    <section id="presets" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-admin-settings"></span></span><?php esc_html_e('Security Presets', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Presets update normal Secure Guard settings. Balanced is recommended for most sites because it keeps strong REST and login protection while avoiding avoidable plugin compatibility problems.', 'wp-secure-guard'); ?></p>
                        <ul>
                            <li><strong><?php esc_html_e('Beginner:', 'wp-secure-guard'); ?></strong> <?php esc_html_e('Safer defaults for new sites and compatibility testing.', 'wp-secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Balanced:', 'wp-secure-guard'); ?></strong> <?php esc_html_e('Recommended production baseline.', 'wp-secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Maximum Security:', 'wp-secure-guard'); ?></strong> <?php esc_html_e('Strict controls for high-risk periods. Confirm whitelists and API clients first.', 'wp-secure-guard'); ?></li>
                        </ul>
                    </section>

                    <section id="jwt-authentication" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-lock"></span></span><?php esc_html_e('JWT Authentication', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('External clients authenticate with Bearer JWTs. JWT issuer, audience, and secret may be managed in settings or by environment variables for Bedrock and other deployment pipelines.', 'wp-secure-guard'); ?></p>
                        <pre><code>Authorization: Bearer YOUR_TOKEN_HERE</code></pre>
                        <p><?php esc_html_e('If an environment variable is active, Secure Guard shows an ENV badge and preserves the stored database value as a fallback.', 'wp-secure-guard'); ?></p>
                    </section>

                    <section id="rest-api-security" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-rest-api"></span></span><?php esc_html_e('REST API Security', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('JWT-only mode protects external REST requests. Logged-in browser sessions for allowed roles remain compatible with Gutenberg, media workflows, and page builders.', 'wp-secure-guard'); ?></p>
                        <p><?php esc_html_e('REST Strict Mode hides unauthenticated REST discovery. Use allowed namespaces for public plugin endpoints such as contact forms.', 'wp-secure-guard'); ?></p>
                    </section>

                    <section id="whitelists-compatibility" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-yes-alt"></span></span><?php esc_html_e('Whitelists & Compatibility', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Use the Whitelists page for global IP allow rules, admin-area allow rules, trusted proxy IPs, allowed REST namespaces, and role-based bypasses.', 'wp-secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-whitelists')); ?>"><?php esc_html_e('Open Whitelists', 'wp-secure-guard'); ?></a></p>
                    </section>

                    <section id="login-unban-recovery" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-admin-users"></span></span><?php esc_html_e('Login & Unban Recovery', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Blocked IPs supports full unblocks, login-only recovery, selected bulk unblocks, and clearing all login lockouts. Full unblock clears firewall and login state. Login-only recovery preserves firewall blocks while allowing legitimate users to try again.', 'wp-secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-blocked-ips')); ?>"><?php esc_html_e('Open Blocked IPs', 'wp-secure-guard'); ?></a></p>
                    </section>

                    <section id="emergency-lockdown" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-warning"></span></span><?php esc_html_e('Emergency Lockdown', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Emergency lockdown temporarily returns maintenance responses for unauthenticated public requests while allowing administrators to log in and recover. The lock state is stored in both a transient and persistent option so cache restarts do not silently remove an active lockdown.', 'wp-secure-guard'); ?></p>
                    </section>

                    <section id="adaptive-security" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-chart-line"></span></span><?php esc_html_e('Adaptive Security', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('The reputation engine scores suspicious behavior and can throttle, challenge, block, or trigger automatic lockdown when attack velocity crosses the configured threshold.', 'wp-secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-settings&tab=adaptive-security')); ?>"><?php esc_html_e('Open Adaptive Security Settings', 'wp-secure-guard'); ?></a></p>
                    </section>

                    <section id="hardening" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-hammer"></span></span><?php esc_html_e('Hardening', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Hardening options reduce WordPress fingerprinting, disable risky admin features, enforce security headers, and monitor core file integrity.', 'wp-secure-guard'); ?></p>
                        <p><?php esc_html_e('The Bedrock app path rules block direct reads of secrets, logs, backups, package metadata, PHP entry points, and unknown non-static files while allowing normal public assets such as CSS, JavaScript, images, fonts, and uploads.', 'wp-secure-guard'); ?></p>
                        <p><?php esc_html_e('For destructive cleanup, core reinstall, or bulk plugin updates, prefer the Forge hardening job flow so operators can preview the action, watch the execution log, and re-scan after completion.', 'wp-secure-guard'); ?></p>
                    </section>

                    <section id="logs-reports" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-list-view"></span></span><?php esc_html_e('Logs & Reports', 'wp-secure-guard'); ?></h2>
                        <p><?php esc_html_e('Use Logs for individual events, IP Reputation for risk scoring, and Dashboard for summaries. CSV exports are intended for security review and incident response.', 'wp-secure-guard'); ?></p>
                        <p><a class="button" href="<?php echo esc_url(admin_url('admin.php?page=secure-guard-logs')); ?>"><?php esc_html_e('Open Logs', 'wp-secure-guard'); ?></a></p>
                    </section>

                    <section id="troubleshooting" class="card">
                        <h2><span class="sg-docs-icon"><span class="dashicons dashicons-sos"></span></span><?php esc_html_e('Troubleshooting', 'wp-secure-guard'); ?></h2>
                        <h3><?php esc_html_e('A real user is locked out', 'wp-secure-guard'); ?></h3>
                        // translators: %s: link to Blocked IPs page
                        <p><?php echo wp_kses_post(sprintf(esc_html__('Go to %s and clear login-only lockouts first. Use full unblock only when the IP should be trusted again.', 'wp-secure-guard'), '<a href="' . esc_url(admin_url('admin.php?page=secure-guard-blocked-ips')) . '">' . esc_html__('Blocked IPs', 'wp-secure-guard') . '</a>')); ?></p>
                        <h3><?php esc_html_e('An API client stopped working', 'wp-secure-guard'); ?></h3>
                        <p><?php esc_html_e('Verify the token is active, the JWT secret/issuer/audience match the environment, and the required scope is assigned.', 'wp-secure-guard'); ?></p>
                        <h3><?php esc_html_e('A monitoring tool is blocked', 'wp-secure-guard'); ?></h3>
                        <p><?php esc_html_e('Add its source IP to the Global IP Whitelist and confirm proxy IP detection is configured if the site runs behind Cloudflare, Varnish, or a load balancer.', 'wp-secure-guard'); ?></p>
                    </section>
                </main>
            </div>
        </div>
        <script>
        (function() {
            if (!('IntersectionObserver' in window)) return;
            var navLinks = document.querySelectorAll('#sg-docs-nav a[data-section]');
            var sections = Array.from(navLinks).map(function(a) {
                return document.getElementById(a.getAttribute('data-section'));
            }).filter(Boolean);
            var observer = new IntersectionObserver(function(entries) {
                entries.forEach(function(entry) {
                    var id = entry.target.id;
                    var link = document.querySelector('#sg-docs-nav a[data-section="' + id + '"]');
                    if (!link) return;
                    if (entry.isIntersecting) {
                        navLinks.forEach(function(l) { l.classList.remove('is-active'); });
                        link.classList.add('is-active');
                    }
                });
            }, { rootMargin: '-10% 0px -70% 0px' });
            sections.forEach(function(s) { observer.observe(s); });
        })();
        </script>
        <?php
    }
}
