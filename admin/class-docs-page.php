<?php

if (!defined('ABSPATH')) {
    exit;
}

final class Secure_Guard_Docs_Page {
    public function render(): void {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'secure-guard'));
        }

        ?>
        <div class="wrap secure-guard-ui">
            <h1><?php esc_html_e('Documentation & Usage', 'secure-guard'); ?></h1>

            <div class="sg-docs-layout">
                <aside class="sg-docs-sidebar">
                    <nav class="sg-docs-nav">
                        <ul>
                            <li><a href="#getting-started"><?php esc_html_e('Getting Started', 'secure-guard'); ?></a></li>
                            <li><a href="#jwt-authentication"><?php esc_html_e('JWT Authentication', 'secure-guard'); ?></a></li>
                            <li><a href="#rest-security"><?php esc_html_e('REST API Security', 'secure-guard'); ?></a></li>
                            <li><a href="#plugin-compatibility"><?php esc_html_e('Plugin Compatibility', 'secure-guard'); ?></a></li>
                            <li><a href="#hardening"><?php esc_html_e('Hardening Features', 'secure-guard'); ?></a></li>
                            <li><a href="#troubleshooting"><?php esc_html_e('Troubleshooting', 'secure-guard'); ?></a></li>
                        </ul>
                    </nav>
                </aside>

                <main class="sg-docs-content">
                    <section id="getting-started" class="card">
                        <h2><?php esc_html_e('Getting Started', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Secure Guard is a comprehensive security plugin designed to lock down your WordPress REST API and sensitive endpoints. By default, it enforces JWT (JSON Web Token) authentication for all external REST requests.', 'secure-guard'); ?></p>
                        <ol>
                            <li><strong><?php esc_html_e('Configure JWT Secret', 'secure-guard'); ?>:</strong> <?php esc_html_e('Go to Settings > REST & JWT and ensure a strong JWT Secret is set. You can also set this via your .env file.', 'secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Create a Token', 'secure-guard'); ?>:</strong> <?php esc_html_e('Navigate to the Tokens page to generate an API key for your external applications.', 'secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Review Hardening', 'secure-guard'); ?>:</strong> <?php esc_html_e('Check the Hardening tab to enable additional security measures like disabling XML-RPC or hiding WordPress version info.', 'secure-guard'); ?></li>
                        </ol>
                    </section>

                    <section id="jwt-authentication" class="card">
                        <h2><?php esc_html_e('JWT Authentication', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('This plugin uses industry-standard JWT for secure, stateless authentication. When "JWT-Only REST Mode" is enabled, all requests to the REST API must include a valid Bearer token.', 'secure-guard'); ?></p>
                        
                        <h3><?php esc_html_e('How to Use Tokens', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('Include the token in your request headers:', 'secure-guard'); ?></p>
                        <pre><code>Authorization: Bearer YOUR_TOKEN_HERE</code></pre>

                        <h3><?php esc_html_e('Token Scopes', 'secure-guard'); ?></h3>
                        <ul>
                            <li><code>read_posts</code>: <?php esc_html_e('Access to read posts, pages, and custom post types.', 'secure-guard'); ?></li>
                            <li><code>write_posts</code>: <?php esc_html_e('Permission to create and edit content.', 'secure-guard'); ?></li>
                            <li><code>full_api_access</code>: <?php esc_html_e('Administrative access, required for sensitive endpoints.', 'secure-guard'); ?></li>
                        </ul>
                    </section>

                    <section id="rest-security" class="card">
                        <h2><?php esc_html_e('REST API Security', 'secure-guard'); ?></h2>
                        <h3><?php esc_html_e('Strict Mode', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('In Strict Mode, the entire REST API is hidden from unauthenticated users. Requests to /wp-json will return a 404 error instead of a 403, making it harder for attackers to even discover that an API exists.', 'secure-guard'); ?></p>
                        
                        <h3><?php esc_html_e('Sensitive Endpoints', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('Endpoints like /wp/v2/users, /wp/v2/settings, and /wp/v2/plugins are automatically blocked unless the token has the "full_api_access" scope.', 'secure-guard'); ?></p>
                    </section>

                    <section id="plugin-compatibility" class="card">
                        <h2><?php esc_html_e('Plugin Compatibility', 'secure-guard'); ?></h2>
                        <p><?php esc_html_e('Some plugins (like Contact Form 7) need to use the REST API for public features (e.g., form submissions). To allow these while keeping everything else locked down:', 'secure-guard'); ?></p>
                        <ol>
                            <li><?php esc_html_e('Go to Settings > Compatibility.', 'secure-guard'); ?></li>
                            <li><?php esc_html_e('Add the REST namespace for the plugin (one per line).', 'secure-guard'); ?></li>
                            <li><?php esc_html_e('Example for Contact Form 7:', 'secure-guard'); ?> <code>contact-form-7/v1</code></li>
                        </ol>
                        <div class="notice notice-info inline">
                            <p><?php esc_html_e('Whitelisting a namespace allows anonymous (public) access to those specific endpoints only.', 'secure-guard'); ?></p>
                        </div>
                    </section>

                    <section id="hardening" class="card">
                        <h2><?php esc_html_e('Hardening Features', 'secure-guard'); ?></h2>
                        <ul>
                            <li><strong><?php esc_html_e('Hide WordPress Fingerprint', 'secure-guard'); ?>:</strong> <?php esc_html_e('Removes generator tags and version strings that reveal your WP version to scanners.', 'secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('Block User Enumeration', 'secure-guard'); ?>:</strong> <?php esc_html_e('Prevents bots from scanning your site to find valid usernames via author archives or REST user lookups.', 'secure-guard'); ?></li>
                            <li><strong><?php esc_html_e('File Integrity Monitoring', 'secure-guard'); ?>:</strong> <?php esc_html_e('Scans core WordPress files for unauthorized changes and alerts you via email.', 'secure-guard'); ?></li>
                        </ul>
                    </section>

                    <section id="troubleshooting" class="card">
                        <h2><?php esc_html_e('Troubleshooting', 'secure-guard'); ?></h2>
                        <h3><?php esc_html_e('"REST API requires a valid JWT token"', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('This means your request reached the API but didn\'t have a valid token. Check your Authorization header and ensure the token hasn\'t expired.', 'secure-guard'); ?></p>

                        <h3><?php esc_html_e('Gutenberg or Page Builders not working?', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('Ensure you are logged into WordPress. Logged-in browser sessions are automatically exempt from JWT enforcement.', 'secure-guard'); ?></p>
                        
                        <h3><?php esc_html_e('CORS Issues', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('If you are calling the API from a different domain, ensure your server sends the correct Access-Control-Allow-Origin headers. Secure Guard manages CSP but not CORS.', 'secure-guard'); ?></p>

                        <h3><?php esc_html_e('Why did all my tokens stop working?', 'secure-guard'); ?></h3>
                        <p><?php esc_html_e('If you changed the JWT Secret (or it was reset), all existing tokens are immediately invalidated because their signatures no longer match. You will need to reissue tokens for your callers.', 'secure-guard'); ?></p>
                    </section>
                </main>
            </div>
        </div>

        <style>
        .sg-docs-layout {
            display: grid;
            grid-template-columns: 240px 1fr;
            gap: 24px;
            align-items: start;
            margin-top: 20px;
        }
        .sg-docs-sidebar {
            position: sticky;
            top: 50px;
            background: #fff;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #c3c4c7;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        .sg-docs-nav ul {
            margin: 0;
            padding: 0;
            list-style: none;
        }
        .sg-docs-nav li {
            margin-bottom: 8px;
        }
        .sg-docs-nav a {
            text-decoration: none;
            color: #1d2327;
            font-weight: 500;
            display: block;
            padding: 5px 10px;
            border-radius: 4px;
            transition: background 0.2s;
        }
        .sg-docs-nav a:hover {
            background: #f0f0f1;
            color: #2271b1;
        }
        .sg-docs-content .card {
            margin-bottom: 24px;
            padding: 24px;
            border-top: 4px solid #2271b1;
        }
        .sg-docs-content h2 {
            margin-top: 0;
            font-size: 20px;
            border-bottom: 1px solid #f0f0f1;
            padding-bottom: 12px;
            margin-bottom: 20px;
        }
        .sg-docs-content h3 {
            font-size: 16px;
            margin-top: 24px;
        }
        .sg-docs-content pre {
            background: #272822;
            color: #f8f8f2;
            padding: 12px;
            border-radius: 4px;
            overflow-x: auto;
            font-family: monospace;
        }
        @media (max-width: 960px) {
            .sg-docs-layout {
                grid-template-columns: 1fr;
            }
            .sg-docs-sidebar {
                position: static;
            }
        }
        </style>
        <?php
    }
}
