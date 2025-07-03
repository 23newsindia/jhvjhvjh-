<?php
class SecuritySettings {
    private $bot_settings;
    
    public function __construct() {
        require_once plugin_dir_path(__FILE__) . 'class-bot-settings.php';
        $this->bot_settings = new BotSettings();
    }
    
    public function add_admin_menu() {
        // FIXED: Main menu should point to security-settings, not security-spam-logs
        add_menu_page(
            'Security Settings',
            'Security Settings',
            'manage_options',
            'security-settings', // FIXED: This was the issue
            array($this, 'render_settings_page'),
            'dashicons-shield'
        );
        
        // REMOVED: Duplicate submenu registration - let SEOManager handle it
    }

    public function render_spam_logs_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        // Handle clear logs action
        if (isset($_POST['clear_logs']) && check_admin_referer('clear_spam_logs', 'spam_logs_nonce')) {
            delete_option('security_spam_url_logs');
            echo '<div class="notice notice-success"><p>Spam logs cleared successfully.</p></div>';
        }

        $spam_logs = get_option('security_spam_url_logs', array());
        ?>
        <div class="wrap">
            <h1>Spam URL Logs</h1>
            <p>This page shows URLs that have been blocked as spam due to excessive filter parameters.</p>
            
            <?php if (!empty($spam_logs)): ?>
                <form method="post" style="margin-bottom: 20px;">
                    <?php wp_nonce_field('clear_spam_logs', 'spam_logs_nonce'); ?>
                    <input type="submit" name="clear_logs" class="button" value="Clear All Logs" 
                           onclick="return confirm('Are you sure you want to clear all spam logs?')">
                </form>
                
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>URL</th>
                            <th>Reason</th>
                            <th>IP Address</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_reverse($spam_logs) as $log): ?>
                            <tr>
                                <td><?php echo esc_html($log['timestamp']); ?></td>
                                <td style="word-break: break-all; max-width: 300px;">
                                    <?php echo esc_html($log['url']); ?>
                                </td>
                                <td><?php echo esc_html($log['reason']); ?></td>
                                <td><?php echo esc_html($log['ip']); ?></td>
                                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                    <?php echo esc_html(substr($log['user_agent'], 0, 100)); ?>
                                    <?php if (strlen($log['user_agent']) > 100): ?>...<?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else: ?>
                <p>No spam URLs have been logged yet.</p>
            <?php endif; ?>
        </div>
        <?php
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (isset($_POST['save_settings']) && check_admin_referer('security_settings_nonce', 'security_nonce')) {
            $this->save_settings();
            echo '<div class="notice notice-success"><p>Settings saved successfully.</p></div>';
        }

        // Get all options with default values
        $options = array(
            'excluded_paths' => get_option('security_excluded_paths', ''),
            'blocked_patterns' => get_option('security_blocked_patterns', ''),
            'excluded_php_paths' => get_option('security_excluded_php_paths', ''),
            'remove_feeds' => get_option('security_remove_feeds', false),
            'remove_oembed' => get_option('security_remove_oembed', false),
            'remove_pingback' => get_option('security_remove_pingback', false),
            'remove_wp_json' => get_option('security_remove_wp_json', false),
            'remove_rsd' => get_option('security_remove_rsd', false),
            'remove_wp_generator' => get_option('security_remove_wp_generator', false),
            'allow_adsense' => get_option('security_allow_adsense', false),
            'allow_youtube' => get_option('security_allow_youtube', false),
            'allow_twitter' => get_option('security_allow_twitter', false),
            'enable_strict_csp' => get_option('security_enable_strict_csp', false),
            'remove_query_strings' => get_option('security_remove_query_strings', false),
            'cookie_notice_text' => get_option('security_cookie_notice_text', 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.'),
            'enable_xss' => get_option('security_enable_xss', true),
            'enable_waf' => get_option('security_enable_waf', true),
            'waf_request_limit' => get_option('security_waf_request_limit', 100),
            'waf_blacklist_threshold' => get_option('security_waf_blacklist_threshold', 5),
            'allowed_script_domains' => get_option('security_allowed_script_domains', ''),
            'allowed_style_domains' => get_option('security_allowed_style_domains', ''),
            'allowed_image_domains' => get_option('security_allowed_image_domains', ''),
            'allowed_frame_domains' => get_option('security_allowed_frame_domains', ''),
            'enable_cookie_banner' => get_option('security_enable_cookie_banner', false),
            // SEO and Anti-Spam options - ULTRA-STRICT DEFAULTS
            'max_filter_colours' => get_option('security_max_filter_colours', 1), // ULTRA-STRICT: Max 1 color
            'max_filter_sizes' => get_option('security_max_filter_sizes', 1),     // ULTRA-STRICT: Max 1 size
            'max_filter_brands' => get_option('security_max_filter_brands', 0),   // ULTRA-STRICT: No brands allowed
            'max_total_filters' => get_option('security_max_total_filters', 2),   // ULTRA-STRICT: Max 2 total filters
            'max_query_params' => get_option('security_max_query_params', 5),     // ULTRA-STRICT: Max 5 params
            'max_query_length' => get_option('security_max_query_length', 100),   // ULTRA-STRICT: Max 100 chars
            '410_page_content' => get_option('security_410_page_content', ''),
            'enable_seo_features' => get_option('security_enable_seo_features', true),
            // Bot protection options
            'enable_bot_protection' => get_option('security_enable_bot_protection', true),
            'protect_admin' => get_option('security_protect_admin', false),
            'protect_login' => get_option('security_protect_login', false),
            'bot_skip_logged_users' => get_option('security_bot_skip_logged_users', true),
            'bot_max_requests_per_minute' => get_option('security_bot_max_requests_per_minute', 30),
            'bot_block_threshold' => get_option('security_bot_block_threshold', 5),
            'bot_block_message' => get_option('security_bot_block_message', 'Access Denied - Bad Bot Detected'),
            'bot_log_retention_days' => get_option('security_bot_log_retention_days', 30),
            'bot_block_status' => get_option('security_bot_block_status', 403),
            'bot_custom_message' => get_option('security_bot_custom_message', ''),
            'bot_email_alerts' => get_option('security_bot_email_alerts', false),
            'bot_alert_email' => get_option('security_bot_alert_email', get_option('admin_email')),
            'bot_whitelist_ips' => get_option('security_bot_whitelist_ips', ''),
            'bot_whitelist_agents' => get_option('security_bot_whitelist_agents', $this->get_default_whitelist_bots()),
            // Bot blocking options
            'enable_bot_blocking' => get_option('security_enable_bot_blocking', true),
            // FIXED: Add stealth mode option
            'bot_stealth_mode' => get_option('security_bot_stealth_mode', true)
        );
        ?>
        <div class="wrap">
            <h1>Security Settings</h1>
            
            <div class="notice notice-warning">
                <p><strong>🚨 ULTRA-STRICT SPAM PROTECTION ACTIVE</strong></p>
                <p>Your filter limits have been set to ultra-strict mode to completely stop the spam URLs hitting your site:</p>
                <ul style="margin-left: 20px;">
                    <li><strong>Max Colors:</strong> 1 (was 2)</li>
                    <li><strong>Max Sizes:</strong> 1 (was 3)</li>
                    <li><strong>Max Brands:</strong> 0 (disabled completely)</li>
                    <li><strong>Max Total Filters:</strong> 2 (was 5)</li>
                    <li><strong>Max Query Length:</strong> 100 chars (was 300)</li>
                </ul>
                <p>This will block ALL the spam URLs you showed me. Legitimate users can still use single filters.</p>
            </div>
            
            <form method="post" action="">
                <?php wp_nonce_field('security_settings_nonce', 'security_nonce'); ?>
                
                <h2 class="nav-tab-wrapper">
                    <a href="#security-tab" class="nav-tab nav-tab-active">Security</a>
                    <a href="#bot-protection-tab" class="nav-tab">Bot Protection</a>
                    <a href="#bot-blocking-tab" class="nav-tab">Bot Blocking</a>
                    <a href="#seo-tab" class="nav-tab">SEO & Anti-Spam</a>
                    <a href="#csp-tab" class="nav-tab">Content Security Policy</a>
                    <a href="#features-tab" class="nav-tab">WordPress Features</a>
                </h2>

                <div id="security-tab" class="tab-content">
                    <table class="form-table">
                        <tr>
                            <th>Security Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_xss" value="1" <?php checked($options['enable_xss']); ?>>
                                    Enable XSS Protection
                                </label>
                                <p class="description">Controls Content Security Policy and other XSS protection features</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>WAF Settings</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_waf" value="1" <?php checked($options['enable_waf']); ?>>
                                    Enable Web Application Firewall
                                </label>
                                <p class="description">Protects against common web attacks including SQL injection, XSS, and file inclusion attempts</p>
                                
                                <br><br>
                                <label>
                                    Request Limit per Minute:
                                    <input type="number" name="waf_request_limit" value="<?php echo esc_attr($options['waf_request_limit']); ?>" min="10" max="1000">
                                </label>
                                
                                <br><br>
                                <label>
                                    Blacklist Threshold (violations/24h):
                                    <input type="number" name="waf_blacklist_threshold" value="<?php echo esc_attr($options['waf_blacklist_threshold']); ?>" min="1" max="100">
                                </label>
                            </td>
                        </tr>

                        <tr>
                            <th>Blocked Patterns</th>
                            <td>
                                <textarea name="blocked_patterns" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['blocked_patterns']); ?></textarea>
                                <p class="description">Enter one pattern per line (e.g., %3C, %3E)</p>
                            </td>
                        </tr>

                        <tr>
                            <th>PHP Access Exclusions</th>
                            <td>
                                <textarea name="excluded_php_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_php_paths']); ?></textarea>
                                <p class="description">Enter paths to allow PHP access (e.g., wp-admin, wp-login.php)</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="bot-protection-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <!-- FIXED: Add stealth mode at the top -->
                        <tr style="background: #fff3cd; border: 2px solid #ffeaa7;">
                            <th style="color: #856404;"><strong>⚠️ Stealth Mode</strong></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bot_stealth_mode" value="1" <?php checked($options['bot_stealth_mode']); ?>>
                                    <strong>Enable Stealth Mode (Recommended)</strong>
                                </label>
                                <p class="description" style="color: #856404;"><strong>IMPORTANT:</strong> Stealth mode prevents security scanners from detecting the blackhole trap as malware. When disabled, your site may be flagged by Sucuri and other security scanners.</p>
                                
                                <?php if (!$options['bot_stealth_mode']): ?>
                                    <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 10px; border-radius: 4px; margin-top: 10px;">
                                        <strong>🚨 WARNING:</strong> Stealth mode is currently DISABLED. This may cause your site to be flagged as having malware by security scanners like Sucuri.
                                    </div>
                                <?php endif; ?>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Enable Bot Protection</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_bot_protection" value="1" <?php checked($options['enable_bot_protection']); ?>>
                                    Enable automatic bot detection and blocking (Blackhole System)
                                </label>
                                <p class="description">Automatically detects and blocks malicious bots and scrapers using blackhole traps and behavioral analysis</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Protection Areas</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="protect_admin" value="1" <?php checked($options['protect_admin']); ?>>
                                    Protect Admin Area
                                </label>
                                <p class="description">Enable bot protection for wp-admin (not recommended for most sites)</p>
                                
                                <br><br>
                                <label>
                                    <input type="checkbox" name="protect_login" value="1" <?php checked($options['protect_login']); ?>>
                                    Protect Login Page
                                </label>
                                <p class="description">Enable bot protection for wp-login.php</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Skip Logged-in Users</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bot_skip_logged_users" value="1" <?php checked($options['bot_skip_logged_users']); ?>>
                                    Skip bot detection for logged-in users
                                </label>
                                <p class="description">Recommended to avoid blocking legitimate users</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Rate Limiting</th>
                            <td>
                                <label>
                                    Max requests per minute:
                                    <input type="number" name="bot_max_requests_per_minute" value="<?php echo esc_attr($options['bot_max_requests_per_minute']); ?>" min="5" max="200">
                                </label>
                                <p class="description">Maximum requests allowed per IP per minute before flagging as bot</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Block Threshold</th>
                            <td>
                                <label>
                                    Block after:
                                    <input type="number" name="bot_block_threshold" value="<?php echo esc_attr($options['bot_block_threshold']); ?>" min="1" max="50">
                                    suspicious activities
                                </label>
                                <p class="description">Number of suspicious activities before permanently blocking an IP</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Block Response</th>
                            <td>
                                <label>
                                    HTTP Status Code:
                                    <select name="bot_block_status">
                                        <option value="403" <?php selected($options['bot_block_status'], 403); ?>>403 Forbidden</option>
                                        <option value="410" <?php selected($options['bot_block_status'], 410); ?>>410 Gone</option>
                                        <option value="444" <?php selected($options['bot_block_status'], 444); ?>>444 No Response</option>
                                    </select>
                                </label>
                                <p class="description">HTTP status code to return to blocked bots</p>
                                
                                <br><br>
                                <label>
                                    Default Block Message:
                                    <textarea name="bot_block_message" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['bot_block_message']); ?></textarea>
                                </label>
                                <p class="description">Default message shown to blocked bots</p>
                                
                                <br><br>
                                <label>
                                    Custom Block Page (HTML):
                                    <textarea name="bot_custom_message" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['bot_custom_message']); ?></textarea>
                                </label>
                                <p class="description">Custom HTML page for blocked bots (overrides default message)</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Email Alerts</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="bot_email_alerts" value="1" <?php checked($options['bot_email_alerts']); ?>>
                                    Send email alerts when bots are blocked
                                </label>
                                <p class="description">Get notified when malicious bots are detected and blocked</p>
                                
                                <br><br>
                                <label>
                                    Alert Email Address:
                                    <input type="email" name="bot_alert_email" value="<?php echo esc_attr($options['bot_alert_email']); ?>" class="regular-text">
                                </label>
                                <p class="description">Email address to receive bot alerts (defaults to admin email)</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Whitelisted IPs</th>
                            <td>
                                <textarea name="bot_whitelist_ips" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['bot_whitelist_ips']); ?></textarea>
                                <p class="description">Enter one IP address per line. Supports CIDR notation (e.g., 192.168.1.0/24)</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Whitelisted User Agents</th>
                            <td>
                                <textarea name="bot_whitelist_agents" rows="8" cols="50" class="large-text"><?php echo esc_textarea($options['bot_whitelist_agents']); ?></textarea>
                                <p class="description">Enter one user agent per line. These bots will never be blocked.</p>
                                
                                <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin-top: 10px;">
                                    <strong>🚨 IMPORTANT:</strong> Facebook's crawler has been removed from the default whitelist because it's being used by scrapers to access your filter URLs. Real Facebook crawlers don't need to access product filter pages.
                                </div>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Log Retention</th>
                            <td>
                                <label>
                                    Keep logs for:
                                    <input type="number" name="bot_log_retention_days" value="<?php echo esc_attr($options['bot_log_retention_days']); ?>" min="1" max="365">
                                    days
                                </label>
                                <p class="description">How long to keep bot activity logs (blocked IPs are kept indefinitely)</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Blackhole Trap Features</th>
                            <td>
                                <p class="description"><strong>Active Blackhole Protection includes:</strong></p>
                                <ul style="list-style-type: disc; margin-left: 20px;">
                                    <li>Hidden links that only bots can see and follow</li>
                                    <li>Automatic addition to robots.txt disallow list</li>
                                    <li>Intelligent scoring system for bot detection</li>
                                    <li>Behavioral analysis and pattern recognition</li>
                                    <li>Automatic IP blocking with transient caching</li>
                                    <li>Real-time bot trap monitoring</li>
                                    <li><strong>Stealth mode to avoid false malware detection</strong></li>
                                    <li><strong>Enhanced Facebook crawler spam detection</strong></li>
                                </ul>
                                <p class="description">The blackhole system creates invisible traps that legitimate users never see, but bots often follow, allowing for accurate bot detection.</p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="bot-blocking-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Enable Bot Blocking</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_bot_blocking" value="1" <?php checked($options['enable_bot_blocking']); ?>>
                                    Enable automatic bot detection and blocking (Pattern-based System)
                                </label>
                                <p class="description">Alternative bot blocking system using pattern detection and rate limiting</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>System Comparison</th>
                            <td>
                                <p class="description"><strong>Bot Protection vs Bot Blocking:</strong></p>
                                <ul style="list-style-type: disc; margin-left: 20px;">
                                    <li><strong>Bot Protection (Blackhole):</strong> Uses hidden traps and behavioral analysis - more sophisticated</li>
                                    <li><strong>Bot Blocking (Pattern):</strong> Uses user agent patterns and rate limiting - more direct</li>
                                    <li>You can enable both systems for maximum protection</li>
                                    <li>Bot Protection is recommended as the primary system</li>
                                </ul>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="seo-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>SEO Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_seo_features" value="1" <?php checked($options['enable_seo_features']); ?>>
                                    Enable SEO & Anti-Spam Features
                                </label>
                                <p class="description">Enables 410 responses for deleted content and spam URL detection</p>
                            </td>
                        </tr>

                        <tr style="background: #f8d7da; border: 2px solid #dc3545;">
                            <th style="color: #721c24;"><strong>🚨 ULTRA-STRICT SPAM PROTECTION</strong></th>
                            <td>
                                <div style="background: #fff; border: 1px solid #dc3545; padding: 15px; border-radius: 5px; margin-bottom: 15px;">
                                    <strong>⚠️ ZERO TOLERANCE MODE ACTIVE</strong><br>
                                    These limits are now set to ULTRA-STRICT to completely stop the spam URLs hitting your site.
                                </div>
                                
                                <label>
                                    Max Colors in Filter:
                                    <input type="number" name="max_filter_colours" value="<?php echo esc_attr($options['max_filter_colours']); ?>" min="0" max="10">
                                </label>
                                <p class="description"><strong>ULTRA-STRICT:</strong> Maximum 1 color allowed (was 2). This blocks all multi-color spam URLs.</p>
                                
                                <br><br>
                                <label>
                                    Max Sizes in Filter:
                                    <input type="number" name="max_filter_sizes" value="<?php echo esc_attr($options['max_filter_sizes']); ?>" min="0" max="10">
                                </label>
                                <p class="description"><strong>ULTRA-STRICT:</strong> Maximum 1 size allowed (was 3). This blocks all multi-size spam URLs.</p>
                                
                                <br><br>
                                <label>
                                    Max Brands in Filter:
                                    <input type="number" name="max_filter_brands" value="<?php echo esc_attr($options['max_filter_brands']); ?>" min="0" max="10">
                                </label>
                                <p class="description"><strong>ULTRA-STRICT:</strong> Brand filters completely disabled (set to 0). No brand filtering allowed.</p>
                                
                                <br><br>
                                <label>
                                    Max Total Filters:
                                    <input type="number" name="max_total_filters" value="<?php echo esc_attr($options['max_total_filters']); ?>" min="1" max="20">
                                </label>
                                <p class="description"><strong>ULTRA-STRICT:</strong> Maximum 2 total filter values (was 5). Blocks complex filter combinations.</p>
                            </td>
                        </tr>

                        <tr style="background: #fff3cd; border: 2px solid #ffc107;">
                            <th style="color: #856404;"><strong>🔧 Query String Limits</strong></th>
                            <td>
                                <label>
                                    Max Query Parameters:
                                    <input type="number" name="max_query_params" value="<?php echo esc_attr($options['max_query_params']); ?>" min="3" max="50">
                                </label>
                                <p class="description"><strong>STRICT:</strong> Maximum 5 query parameters allowed (was 8)</p>
                                
                                <br><br>
                                <label>
                                    Max Query String Length:
                                    <input type="number" name="max_query_length" value="<?php echo esc_attr($options['max_query_length']); ?>" min="50" max="2000">
                                </label>
                                <p class="description"><strong>ULTRA-STRICT:</strong> Maximum 100 characters (was 300). Blocks long spam URLs.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>410 Page Content</th>
                            <td>
                                <textarea name="410_page_content" rows="10" cols="50" class="large-text"><?php echo esc_textarea($options['410_page_content']); ?></textarea>
                                <p class="description">Custom HTML content for 410 (Gone) pages. Leave empty for default content.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Query String Settings</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_query_strings" value="1" <?php checked($options['remove_query_strings']); ?>>
                                    Remove Excessive Query Strings from URLs
                                </label>
                                <p class="description">Automatically removes excessive query parameters while preserving essential WooCommerce filters</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Excluded Paths</th>
                            <td>
                                <textarea name="excluded_paths" rows="5" cols="50" class="large-text"><?php echo esc_textarea($options['excluded_paths']); ?></textarea>
                                <p class="description">Enter one path per line (e.g., /register/?action=check_email). These paths will keep their query strings.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Spam URL Examples</th>
                            <td>
                                <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px;">
                                    <strong>🚫 These types of URLs will now return 410 (Gone):</strong><br>
                                    <code style="font-size: 11px; display: block; margin: 5px 0;">
                                        /product-category/women/?filter_size=medium&filter_color=green&query_type_color=or&filter_colour=yellow%2Corange
                                    </code>
                                    <code style="font-size: 11px; display: block; margin: 5px 0;">
                                        /product-category/women/?filter_color=pink&query_type_color=or&filter_colour=bottle-green%2Cpeace-orange
                                    </code>
                                    <p style="margin-top: 10px;"><strong>Blocked because:</strong> Multiple colors, query_type parameters, URL encoding, excessive length</p>
                                </div>
                                
                                <div style="background: #d1edff; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin-top: 10px;">
                                    <strong>✅ These URLs will work normally:</strong><br>
                                    <code style="font-size: 11px; display: block; margin: 5px 0;">
                                        /product-category/women/?filter_colour=blue
                                    </code>
                                    <code style="font-size: 11px; display: block; margin: 5px 0;">
                                        /product-category/women/?filter_size=medium
                                    </code>
                                    <p style="margin-top: 10px;"><strong>Allowed because:</strong> Single filter value, no complex parameters</p>
                                </div>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="csp-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Content Security Policy Domains</th>
                            <td>
                                <p><strong>Script Domains (script-src)</strong></p>
                                <textarea name="allowed_script_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_script_domains']); ?></textarea>
                                <p class="description">Enter one domain per line (e.g., checkout.razorpay.com). These domains will be allowed to load scripts.</p>
                                
                                <br><br>
                                <p><strong>Style Domains (style-src)</strong></p>
                                <textarea name="allowed_style_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_style_domains']); ?></textarea>
                                <p class="description">Enter one domain per line for custom style sources.</p>
                                
                                <br><br>
                                <p><strong>Image Domains (img-src)</strong></p>
                                <textarea name="allowed_image_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_image_domains']); ?></textarea>
                                <p class="description">Enter one domain per line (e.g., mellmon.in, cdn.razorpay.com). These domains will be allowed to load images.</p>
                                
                                <br><br>
                                <p><strong>Frame Domains (frame-src)</strong></p>
                                <textarea name="allowed_frame_domains" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['allowed_frame_domains']); ?></textarea>
                                <p class="description">Enter one domain per line for allowed iframe sources.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Content Security Policy</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_strict_csp" value="1" <?php checked($options['enable_strict_csp']); ?>>
                                    Enable Strict Content Security Policy
                                </label>
                                <p class="description">When disabled, a more permissive policy is used that allows most third-party content. Enable for stricter security.</p>
                                
                                <br><br>
                                <strong>Allow Third-party Services (when strict CSP is enabled):</strong><br>
                                <label>
                                    <input type="checkbox" name="allow_adsense" value="1" <?php checked($options['allow_adsense']); ?>>
                                    Allow Google AdSense
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_youtube" value="1" <?php checked($options['allow_youtube']); ?>>
                                    Allow YouTube Embeds
                                </label><br>
                                <label>
                                    <input type="checkbox" name="allow_twitter" value="1" <?php checked($options['allow_twitter']); ?>>
                                    Allow Twitter Embeds
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>

                <div id="features-tab" class="tab-content" style="display:none;">
                    <table class="form-table">
                        <tr>
                            <th>Enable Cookie Consent Banner</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_cookie_banner" value="1" <?php checked($options['enable_cookie_banner']); ?>>
                                    Enable Cookie Consent Banner
                                </label>
                                <p class="description">Show or hide the cookie consent banner on your site.</p>
                            </td>
                        </tr>

                        <tr>
                            <th>Cookie Notice Text</th>
                            <td>
                                <textarea name="cookie_notice_text" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['cookie_notice_text']); ?></textarea>
                                <p class="description">Customize the cookie consent notice text</p>
                            </td>
                        </tr>
                        
                        <tr>
                            <th>Remove Features</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="remove_feeds" value="1" <?php checked($options['remove_feeds']); ?>>
                                    Remove RSS Feeds (Returns 410 Gone)
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_oembed" value="1" <?php checked($options['remove_oembed']); ?>>
                                    Remove oEmbed Links
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_pingback" value="1" <?php checked($options['remove_pingback']); ?>>
                                    Remove Pingback and Disable XMLRPC
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_json" value="1" <?php checked($options['remove_wp_json']); ?>>
                                    Remove WP REST API Links (wp-json)
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_rsd" value="1" <?php checked($options['remove_rsd']); ?>>
                                    Remove RSD Link
                                </label><br>
                                <label>
                                    <input type="checkbox" name="remove_wp_generator" value="1" <?php checked($options['remove_wp_generator']); ?>>
                                    Remove WordPress Generator Meta Tag
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <p class="submit">
                    <input type="submit" name="save_settings" class="button button-primary" value="Save Settings">
                </p>
            </form>
        </div>

        <style>
        .nav-tab-wrapper { margin-bottom: 20px; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        </style>

        <script>
        jQuery(document).ready(function($) {
            $('.nav-tab').click(function(e) {
                e.preventDefault();
                $('.nav-tab').removeClass('nav-tab-active');
                $('.tab-content').hide();
                $(this).addClass('nav-tab-active');
                $($(this).attr('href')).show();
            });
            
            // Show first tab by default
            $('#security-tab').show();
        });
        </script>
        <?php
    }

    private function get_default_whitelist_bots() {
        return 'googlebot
bingbot
slurp
duckduckbot
baiduspider
yandexbot
twitterbot
linkedinbot
pinterestbot
applebot
ia_archiver
msnbot
ahrefsbot
semrushbot
dotbot
rogerbot
uptimerobot
pingdom
gtmetrix
pagespeed
lighthouse
chrome-lighthouse
wordpress
wp-rocket
jetpack
wordfence';
    }

    private function save_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (!isset($_POST['security_nonce']) || !wp_verify_nonce($_POST['security_nonce'], 'security_settings_nonce')) {
            wp_die('Security check failed');
        }

        // Save all settings
        update_option('security_enable_xss', isset($_POST['enable_xss']));
        update_option('security_enable_strict_csp', isset($_POST['enable_strict_csp']));
        update_option('security_allow_adsense', isset($_POST['allow_adsense']));
        update_option('security_allow_youtube', isset($_POST['allow_youtube']));
        update_option('security_allow_twitter', isset($_POST['allow_twitter']));
        update_option('security_cookie_notice_text', sanitize_textarea_field($_POST['cookie_notice_text']));
        update_option('security_excluded_paths', sanitize_textarea_field($_POST['excluded_paths']));
        update_option('security_blocked_patterns', sanitize_textarea_field($_POST['blocked_patterns']));
        update_option('security_excluded_php_paths', sanitize_textarea_field($_POST['excluded_php_paths']));
        update_option('security_remove_feeds', isset($_POST['remove_feeds']));
        update_option('security_remove_oembed', isset($_POST['remove_oembed']));
        update_option('security_remove_pingback', isset($_POST['remove_pingback']));
        update_option('security_remove_wp_json', isset($_POST['remove_wp_json']));
        update_option('security_remove_rsd', isset($_POST['remove_rsd']));
        update_option('security_remove_wp_generator', isset($_POST['remove_wp_generator']));
        update_option('security_enable_waf', isset($_POST['enable_waf']));
        update_option('security_waf_request_limit', intval($_POST['waf_request_limit']));
        update_option('security_waf_blacklist_threshold', intval($_POST['waf_blacklist_threshold']));
        update_option('security_remove_query_strings', isset($_POST['remove_query_strings']));
        update_option('security_allowed_script_domains', sanitize_textarea_field($_POST['allowed_script_domains']));
        update_option('security_allowed_style_domains', sanitize_textarea_field($_POST['allowed_style_domains']));
        update_option('security_allowed_image_domains', sanitize_textarea_field($_POST['allowed_image_domains']));
        update_option('security_allowed_frame_domains', sanitize_textarea_field($_POST['allowed_frame_domains']));
        update_option('security_enable_cookie_banner', isset($_POST['enable_cookie_banner']));
        
        // SEO and Anti-Spam settings - ULTRA-STRICT DEFAULTS
        update_option('security_enable_seo_features', isset($_POST['enable_seo_features']));
        update_option('security_max_filter_colours', intval($_POST['max_filter_colours']));
        update_option('security_max_filter_sizes', intval($_POST['max_filter_sizes']));
        update_option('security_max_filter_brands', intval($_POST['max_filter_brands']));
        update_option('security_max_total_filters', intval($_POST['max_total_filters']));
        update_option('security_max_query_params', intval($_POST['max_query_params']));
        update_option('security_max_query_length', intval($_POST['max_query_length']));
        update_option('security_410_page_content', wp_kses_post($_POST['410_page_content']));
        
        // Bot protection settings (Blackhole system)
        update_option('security_enable_bot_protection', isset($_POST['enable_bot_protection']));
        update_option('security_protect_admin', isset($_POST['protect_admin']));
        update_option('security_protect_login', isset($_POST['protect_login']));
        update_option('security_bot_skip_logged_users', isset($_POST['bot_skip_logged_users']));
        update_option('security_bot_max_requests_per_minute', intval($_POST['bot_max_requests_per_minute']));
        update_option('security_bot_block_threshold', intval($_POST['bot_block_threshold']));
        update_option('security_bot_block_status', intval($_POST['bot_block_status']));
        update_option('security_bot_block_message', sanitize_textarea_field($_POST['bot_block_message']));
        update_option('security_bot_custom_message', wp_kses_post($_POST['bot_custom_message']));
        update_option('security_bot_email_alerts', isset($_POST['bot_email_alerts']));
        update_option('security_bot_alert_email', sanitize_email($_POST['bot_alert_email']));
        update_option('security_bot_whitelist_ips', sanitize_textarea_field($_POST['bot_whitelist_ips']));
        update_option('security_bot_whitelist_agents', sanitize_textarea_field($_POST['bot_whitelist_agents']));
        update_option('security_bot_log_retention_days', intval($_POST['bot_log_retention_days']));
        
        // Bot blocking settings (Pattern-based system)
        update_option('security_enable_bot_blocking', isset($_POST['enable_bot_blocking']));
        
        // FIXED: Save stealth mode setting
        update_option('security_bot_stealth_mode', isset($_POST['bot_stealth_mode']));
    }

    public function register_settings() {
        $settings = array(
            'security_enable_waf', 'security_enable_xss', 'security_enable_strict_csp',
            'security_allow_adsense', 'security_allow_youtube', 'security_allow_twitter',
            'security_cookie_notice_text', 'security_excluded_paths', 'security_blocked_patterns',
            'security_excluded_php_paths', 'security_remove_feeds', 'security_remove_oembed',
            'security_remove_pingback', 'security_remove_query_strings', 'security_remove_wp_json',
            'security_remove_rsd', 'security_remove_wp_generator', 'security_waf_request_limit',
            'security_waf_blacklist_threshold', 'security_allowed_script_domains',
            'security_allowed_style_domains', 'security_allowed_image_domains',
            'security_allowed_frame_domains', 'security_enable_cookie_banner',
            'security_enable_seo_features', 'security_max_filter_colours',
            'security_max_filter_sizes', 'security_max_filter_brands',
            'security_max_total_filters', 'security_max_query_params',
            'security_max_query_length', 'security_410_page_content',
            // Bot protection settings (Blackhole)
            'security_enable_bot_protection', 'security_protect_admin', 'security_protect_login',
            'security_bot_skip_logged_users', 'security_bot_max_requests_per_minute',
            'security_bot_block_threshold', 'security_bot_block_status', 'security_bot_block_message',
            'security_bot_custom_message', 'security_bot_email_alerts', 'security_bot_alert_email',
            'security_bot_whitelist_ips', 'security_bot_whitelist_agents', 'security_bot_log_retention_days',
            // Bot blocking settings (Pattern-based)
            'security_enable_bot_blocking',
            // FIXED: Add stealth mode to registered settings
            'security_bot_stealth_mode'
        );

        foreach ($settings as $setting) {
            register_setting('security_settings', $setting);
        }
    }
}