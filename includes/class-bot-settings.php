<?php
// includes/class-bot-settings.php

if (!defined('ABSPATH')) {
    exit;
}

class BotSettings {
    public function add_bot_settings_section($settings) {
        // Add bot protection settings to the main settings class
        $settings->add_settings_section('bot-protection', 'Bot Protection', array($this, 'render_bot_settings'));
        return $settings;
    }
    
    public function render_bot_settings() {
        $options = array(
            'enable_bot_protection' => get_option('security_enable_bot_protection', true),
            'bot_skip_logged_users' => get_option('security_bot_skip_logged_users', true),
            'bot_max_requests_per_minute' => get_option('security_bot_max_requests_per_minute', 30),
            'bot_block_threshold' => get_option('security_bot_block_threshold', 5),
            'bot_block_message' => get_option('security_bot_block_message', 'Access Denied: Automated requests not allowed.'),
            'bot_log_retention_days' => get_option('security_bot_log_retention_days', 30),
            'bot_whitelist_ips' => get_option('security_bot_whitelist_ips', ''),
            'bot_whitelist_agents' => get_option('security_bot_whitelist_agents', $this->get_default_whitelist_bots()),
            'bot_email_alerts' => get_option('security_bot_email_alerts', false),
            'bot_alert_email' => get_option('security_bot_alert_email', get_option('admin_email')),
            'bot_block_status' => get_option('security_bot_block_status', 403),
            'bot_custom_message' => get_option('security_bot_custom_message', ''),
            'protect_admin' => get_option('security_protect_admin', false),
            'protect_login' => get_option('security_protect_login', false)
        );
        ?>
        <div id="bot-protection-tab" class="tab-content" style="display:none;">
            <table class="form-table">
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
                    <th>Blackhole Trap</th>
                    <td>
                        <p class="description"><strong>Blackhole Trap Features:</strong></p>
                        <ul style="list-style-type: disc; margin-left: 20px;">
                            <li>Hidden links that only bots can see and follow</li>
                            <li>Automatic addition to robots.txt disallow list</li>
                            <li>Intelligent scoring system for bot detection</li>
                            <li>Behavioral analysis and pattern recognition</li>
                            <li>Automatic IP blocking with transient caching</li>
                        </ul>
                        <p class="description">The blackhole system creates invisible traps that legitimate users never see, but bots often follow, allowing for accurate bot detection.</p>
                    </td>
                </tr>
            </table>
        </div>
        <?php
    }
    
    private function get_default_whitelist_bots() {
        return 'googlebot
bingbot
slurp
duckduckbot
baiduspider
yandexbot
facebookexternalhit
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
    
    public function save_bot_settings() {
        // Save bot protection settings
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
    }
    
    public function register_bot_settings() {
        $settings = array(
            'security_enable_bot_protection',
            'security_protect_admin',
            'security_protect_login',
            'security_bot_skip_logged_users',
            'security_bot_max_requests_per_minute',
            'security_bot_block_threshold',
            'security_bot_block_status',
            'security_bot_block_message',
            'security_bot_custom_message',
            'security_bot_email_alerts',
            'security_bot_alert_email',
            'security_bot_whitelist_ips',
            'security_bot_whitelist_agents',
            'security_bot_log_retention_days'
        );
        
        foreach ($settings as $setting) {
            register_setting('security_settings', $setting);
        }
    }
}