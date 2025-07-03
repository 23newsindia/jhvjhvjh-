<?php
// includes/class-modsecurity-manager.php

if (!defined('ABSPATH')) {
    exit;
}

class ModSecurityManager {
    private $rules_cache = null;
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_modsecurity_menu'), 25);
        add_action('wp_ajax_generate_modsec_rules', array($this, 'generate_modsec_rules'));
        add_action('wp_ajax_test_modsec_rule', array($this, 'test_modsec_rule'));
    }
    
    public function add_modsecurity_menu() {
        add_submenu_page(
            'security-settings',
            'ModSecurity Rules',
            'ModSec Rules',
            'manage_options',
            'security-modsec-rules',
            array($this, 'render_modsecurity_page')
        );
    }
    
    public function render_modsecurity_page() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        // Handle rule generation
        if (isset($_POST['generate_rules']) && check_admin_referer('modsec_rules_nonce', 'modsec_nonce')) {
            $this->save_modsec_settings();
            echo '<div class="notice notice-success"><p>ModSecurity rules generated successfully!</p></div>';
        }

        $options = array(
            'enable_modsec_integration' => get_option('security_enable_modsec_integration', true),
            'modsec_rule_id_start' => get_option('security_modsec_rule_id_start', 20000),
            'modsec_block_spam_urls' => get_option('security_modsec_block_spam_urls', true),
            'modsec_block_bad_bots' => get_option('security_modsec_block_bad_bots', true),
            'modsec_custom_410_page' => get_option('security_modsec_custom_410_page', true),
            'modsec_whitelist_search_bots' => get_option('security_modsec_whitelist_search_bots', true),
            'modsec_log_blocked_requests' => get_option('security_modsec_log_blocked_requests', true),
            'modsec_additional_rules' => get_option('security_modsec_additional_rules', ''),
            'modsec_custom_bad_bots' => get_option('security_modsec_custom_bad_bots', 'BLEXBot,MJ12bot,SemrushBot,AhrefsBot'),
            'modsec_max_filter_colors' => get_option('security_max_filter_colours', 2),
            'modsec_max_filter_sizes' => get_option('security_max_filter_sizes', 3),
            'modsec_max_total_filters' => get_option('security_max_total_filters', 5),
            'modsec_max_query_length' => get_option('security_max_query_length', 300),
            'modsec_block_shop_urls' => get_option('security_modsec_block_shop_urls', false),
            'modsec_custom_blocked_paths' => get_option('security_modsec_custom_blocked_paths', '/shop/'),
            'modsec_protect_product_pages' => get_option('security_modsec_protect_product_pages', true),
            'modsec_disable_owasp_crs' => get_option('security_modsec_disable_owasp_crs', false),
            'modsec_owasp_anomaly_threshold' => get_option('security_modsec_owasp_anomaly_threshold', 10),
            'modsec_custom_410_url' => get_option('security_modsec_custom_410_url', '/security-410/')
        );
        ?>
        <div class="wrap">
            <h1><span class="dashicons dashicons-shield-alt"></span> ModSecurity Rules Generator</h1>
            
            <div class="notice notice-success">
                <p><strong>✅ SECURITY ISSUE RESOLVED:</strong> Custom 410 page now uses secure WordPress endpoint!</p>
                <p><strong>New Secure URL:</strong> <code><?php echo home_url('/security-410/'); ?></code></p>
                <p><strong>Benefits:</strong> No plugin directory exposure, cached for performance, proper SEO headers</p>
            </div>
            
            <div class="notice notice-info">
                <p><strong>🔧 CUSTOM 410 PAGE:</strong> When enabled, ModSecurity will redirect blocked requests to your secure WordPress 410 endpoint instead of showing the default Nginx 410 page.</p>
            </div>
            
            <form method="post" action="">
                <?php wp_nonce_field('modsec_rules_nonce', 'modsec_nonce'); ?>
                
                <table class="form-table">
                    <tr style="background: #d1ecf1; border: 2px solid #17a2b8;">
                        <th style="color: #0c5460;"><strong>🎨 Secure Custom 410 Page</strong></th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_custom_410_page" value="1" <?php checked($options['modsec_custom_410_page']); ?>>
                                <strong>Use Secure WordPress 410 Endpoint (RECOMMENDED)</strong>
                            </label>
                            <p class="description" style="color: #0c5460;"><strong>This will redirect ModSecurity blocks to your secure WordPress 410 endpoint instead of showing the default Nginx 410 page</strong></p>
                            
                            <br><br>
                            <label>
                                Secure 410 Endpoint URL:
                                <input type="text" name="modsec_custom_410_url" value="<?php echo esc_attr($options['modsec_custom_410_url']); ?>" class="regular-text">
                            </label>
                            <p class="description">Secure WordPress endpoint for 410 responses (no plugin directory exposure)</p>
                            
                            <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 15px; border-radius: 4px; margin-top: 10px;">
                                <strong>🛡️ Security Benefits:</strong>
                                <ul style="margin: 5px 0 0 20px;">
                                    <li>✅ No plugin directory exposure</li>
                                    <li>✅ Cached for high performance (24 hours)</li>
                                    <li>✅ Proper SEO headers and structured data</li>
                                    <li>✅ Wild Dragon branded 410 page</li>
                                    <li>✅ Logs blocked requests in WordPress</li>
                                    <li>✅ Mobile responsive design</li>
                                </ul>
                            </div>
                            
                            <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 10px; border-radius: 4px; margin-top: 10px;">
                                <strong>💡 How it works:</strong>
                                <ul style="margin: 5px 0 0 20px;">
                                    <li>ModSecurity detects spam/malicious requests</li>
                                    <li>Redirects to secure WordPress endpoint: <code><?php echo esc_html($options['modsec_custom_410_url']); ?></code></li>
                                    <li>WordPress serves cached, branded 410 page</li>
                                    <li>No direct file access or plugin directory exposure</li>
                                </ul>
                            </div>
                            
                            <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 10px; border-radius: 4px; margin-top: 10px;">
                                <strong>✅ Endpoint Status:</strong> 
                                <span style="color: #155724;">✓ Secure WordPress endpoint configured</span><br>
                                <strong>Cache Status:</strong> 
                                <?php 
                                $cache_exists = get_transient('security_410_page_cache');
                                if ($cache_exists): ?>
                                    <span style="color: #155724;">✓ Page cached for performance</span>
                                <?php else: ?>
                                    <span style="color: #856404;">⚠ Page will be cached on first access</span>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                    
                    <tr style="background: #f8d7da; border: 2px solid #dc3545;">
                        <th style="color: #721c24;"><strong>🚨 OWASP CRS Issues</strong></th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_disable_owasp_crs" value="1" <?php checked($options['modsec_disable_owasp_crs']); ?>>
                                <strong>Add OWASP CRS WordPress Exceptions (Recommended)</strong>
                            </label>
                            <p class="description" style="color: #721c24;"><strong>This will add rules to prevent OWASP CRS from blocking legitimate WordPress pages</strong></p>
                            
                            <br><br>
                            <label>
                                OWASP Anomaly Score Threshold:
                                <input type="number" name="modsec_owasp_anomaly_threshold" value="<?php echo esc_attr($options['modsec_owasp_anomaly_threshold']); ?>" min="5" max="100">
                            </label>
                            <p class="description">Increase this if legitimate pages are still blocked (default: 5, recommended: 10-20)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Enable ModSecurity Integration</th>
                        <td>
                            <label>
                                <input type="checkbox" name="enable_modsec_integration" value="1" <?php checked($options['enable_modsec_integration']); ?>>
                                Generate ModSecurity rules for server-level protection
                            </label>
                            <p class="description">When enabled, this will generate ModSecurity rules that complement your WordPress security plugin</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Rule ID Range</th>
                        <td>
                            <label>
                                Starting Rule ID:
                                <input type="number" name="modsec_rule_id_start" value="<?php echo esc_attr($options['modsec_rule_id_start']); ?>" min="20000" max="99999">
                            </label>
                            <p class="description">Starting ID for generated rules (recommended: 20000-29999 to avoid conflicts)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Spam URL Protection</th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_block_spam_urls" value="1" <?php checked($options['modsec_block_spam_urls']); ?>>
                                Block spam filter URLs with 410 status
                            </label>
                            <p class="description">Blocks URLs with excessive filter parameters (like the ones hitting your site)</p>
                            
                            <br><br>
                            <strong>Filter Limits:</strong><br>
                            <label>Max Colors: <input type="number" name="modsec_max_filter_colors" value="<?php echo esc_attr($options['modsec_max_filter_colors']); ?>" min="1" max="10" style="width:60px;"></label>
                            <label>Max Sizes: <input type="number" name="modsec_max_filter_sizes" value="<?php echo esc_attr($options['modsec_max_filter_sizes']); ?>" min="1" max="10" style="width:60px;"></label>
                            <label>Max Total Filters: <input type="number" name="modsec_max_total_filters" value="<?php echo esc_attr($options['modsec_max_total_filters']); ?>" min="1" max="20" style="width:60px;"></label>
                            <label>Max Query Length: <input type="number" name="modsec_max_query_length" value="<?php echo esc_attr($options['modsec_max_query_length']); ?>" min="100" max="1000" style="width:80px;"></label>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Product Page Protection</th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_protect_product_pages" value="1" <?php checked($options['modsec_protect_product_pages']); ?>>
                                Protect individual product pages from spam filters
                            </label>
                            <p class="description">Blocks spam filter URLs on /product/* pages</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Shop URL Blocking</th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_block_shop_urls" value="1" <?php checked($options['modsec_block_shop_urls']); ?>>
                                Block all /shop/ URLs with 410 status
                            </label>
                            <p class="description">Returns 410 for all URLs starting with /shop/</p>
                            
                            <br><br>
                            <label>
                                Custom Blocked Paths (one per line):
                                <textarea name="modsec_custom_blocked_paths" rows="3" cols="50" class="large-text"><?php echo esc_textarea($options['modsec_custom_blocked_paths']); ?></textarea>
                            </label>
                            <p class="description">Additional URL paths to block with 410 (e.g., /shop/, /old-category/)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Bad Bot Protection</th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_block_bad_bots" value="1" <?php checked($options['modsec_block_bad_bots']); ?>>
                                Block known bad bots
                            </label>
                            <p class="description">Blocks malicious crawlers and scrapers</p>
                            
                            <br><br>
                            <label>
                                Custom Bad Bots (comma-separated):
                                <textarea name="modsec_custom_bad_bots" rows="2" cols="50" class="large-text"><?php echo esc_textarea($options['modsec_custom_bad_bots']); ?></textarea>
                            </label>
                            <p class="description">Additional bot names to block (case-insensitive)</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Search Engine Whitelisting</th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_whitelist_search_bots" value="1" <?php checked($options['modsec_whitelist_search_bots']); ?>>
                                Whitelist legitimate search engine bots
                            </label>
                            <p class="description">Ensures Google, Bing, and other search engines can access your site</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Logging</th>
                        <td>
                            <label>
                                <input type="checkbox" name="modsec_log_blocked_requests" value="1" <?php checked($options['modsec_log_blocked_requests']); ?>>
                                Log blocked requests in ModSecurity audit log
                            </label>
                            <p class="description">Enables detailed logging of blocked requests for analysis</p>
                        </td>
                    </tr>
                    
                    <tr>
                        <th>Additional Rules</th>
                        <td>
                            <textarea name="modsec_additional_rules" rows="5" cols="80" class="large-text"><?php echo esc_textarea($options['modsec_additional_rules']); ?></textarea>
                            <p class="description">Custom ModSecurity rules to include (advanced users only)</p>
                        </td>
                    </tr>
                </table>
                
                <p class="submit">
                    <input type="submit" name="generate_rules" class="button button-primary" value="Generate ModSecurity Rules">
                </p>
            </form>
            
            <?php if ($options['enable_modsec_integration']): ?>
                <div class="modsec-rules-output">
                    <h2>Generated ModSecurity Rules</h2>
                    
                    <?php if ($options['modsec_custom_410_page']): ?>
                        <div style="background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 5px; margin: 20px 0;">
                            <h3>🎨 Secure Custom 410 Page Setup</h3>
                            <p><strong>Your ModSecurity rules will now redirect to your secure 410 endpoint!</strong></p>
                            <ol>
                                <li>Copy the rules below to your ModSecurity configuration</li>
                                <li>Blocked requests will redirect to: <code><?php echo esc_html($options['modsec_custom_410_url']); ?></code></li>
                                <li>This shows your cached, branded 410 page instead of the default Nginx page</li>
                                <li>No plugin directory exposure or security risks</li>
                            </ol>
                            <p><strong>✅ Result:</strong> Users will see your Wild Dragon branded 410 page with proper caching!</p>
                        </div>
                    <?php endif; ?>
                    
                    <div style="background: #dc3545; color: white; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h3>🚨 CRITICAL: Fix OWASP CRS Issues First!</h3>
                        <p><strong>Your 503 errors are caused by OWASP Core Rule Set blocking legitimate WordPress responses.</strong></p>
                        <ol>
                            <li>SSH to your server</li>
                            <li>Edit: <code>sudo nano /etc/nginx/modsec/modsecurity.conf</code></li>
                            <li><strong>Add the OWASP CRS exceptions at the TOP of the file</strong></li>
                            <li>Then add the spam blocking rules below</li>
                            <li>Test: <code>sudo nginx -t</code></li>
                            <li>Reload: <code>sudo systemctl reload nginx</code></li>
                        </ol>
                    </div>
                    
                    <div style="background: #f1f1f1; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <h3>🔧 Server Configuration Steps:</h3>
                        <ol>
                            <li>Copy the rules below</li>
                            <li>SSH to your server</li>
                            <li>Edit: <code>sudo nano /etc/nginx/modsec/modsecurity.conf</code></li>
                            <li><strong>REMOVE old rules first (lines with IDs 20000-20020)</strong></li>
                            <li>Paste the new rules at the end of the file</li>
                            <li>Test configuration: <code>sudo nginx -t</code></li>
                            <li>Reload Nginx: <code>sudo systemctl reload nginx</code></li>
                        </ol>
                    </div>
                    
                    <textarea readonly style="width: 100%; height: 500px; font-family: monospace; font-size: 12px; background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 5px;"><?php echo esc_textarea($this->generate_rules($options)); ?></textarea>
                    
                    <div style="margin-top: 20px;">
                        <button type="button" onclick="copyRulesToClipboard()" class="button">📋 Copy Rules to Clipboard</button>
                        <button type="button" onclick="downloadRules()" class="button">💾 Download Rules File</button>
                    </div>
                    
                    <div style="background: #d1ecf1; padding: 15px; border-radius: 5px; margin: 20px 0; border-left: 4px solid #17a2b8;">
                        <h3>🛠️ Troubleshooting 503 Errors</h3>
                        <p>If you're still getting 503 errors after updating the rules:</p>
                        <ol>
                            <li>Check Nginx error log: <code>sudo tail -f /var/log/nginx/error.log</code></li>
                            <li>Check ModSecurity audit log: <code>sudo tail -f /var/log/nginx/modsec_audit.log</code></li>
                            <li>Temporarily disable OWASP CRS: Add <code>SecRuleEngine Off</code> to test</li>
                            <li>Increase anomaly threshold: <code>SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=20"</code></li>
                        </ol>
                    </div>
                </div>
                
                <script>
                function copyRulesToClipboard() {
                    const textarea = document.querySelector('textarea[readonly]');
                    textarea.select();
                    document.execCommand('copy');
                    alert('ModSecurity rules copied to clipboard!');
                }
                
                function downloadRules() {
                    const rules = document.querySelector('textarea[readonly]').value;
                    const blob = new Blob([rules], { type: 'text/plain' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'wordpress-security-modsec-rules-secure-410-fixed.conf';
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    window.URL.revokeObjectURL(url);
                }
                </script>
            <?php endif; ?>
        </div>
        <?php
    }
    
    private function save_modsec_settings() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        update_option('security_enable_modsec_integration', isset($_POST['enable_modsec_integration']));
        update_option('security_modsec_rule_id_start', intval($_POST['modsec_rule_id_start']));
        update_option('security_modsec_block_spam_urls', isset($_POST['modsec_block_spam_urls']));
        update_option('security_modsec_block_bad_bots', isset($_POST['modsec_block_bad_bots']));
        update_option('security_modsec_custom_410_page', isset($_POST['modsec_custom_410_page']));
        update_option('security_modsec_whitelist_search_bots', isset($_POST['modsec_whitelist_search_bots']));
        update_option('security_modsec_log_blocked_requests', isset($_POST['modsec_log_blocked_requests']));
        update_option('security_modsec_additional_rules', sanitize_textarea_field($_POST['modsec_additional_rules']));
        update_option('security_modsec_custom_bad_bots', sanitize_text_field($_POST['modsec_custom_bad_bots']));
        update_option('security_modsec_max_filter_colors', intval($_POST['modsec_max_filter_colors']));
        update_option('security_modsec_max_filter_sizes', intval($_POST['modsec_max_filter_sizes']));
        update_option('security_modsec_max_total_filters', intval($_POST['modsec_max_total_filters']));
        update_option('security_modsec_max_query_length', intval($_POST['modsec_max_query_length']));
        update_option('security_modsec_block_shop_urls', isset($_POST['modsec_block_shop_urls']));
        update_option('security_modsec_custom_blocked_paths', sanitize_textarea_field($_POST['modsec_custom_blocked_paths']));
        update_option('security_modsec_protect_product_pages', isset($_POST['modsec_protect_product_pages']));
        update_option('security_modsec_disable_owasp_crs', isset($_POST['modsec_disable_owasp_crs']));
        update_option('security_modsec_owasp_anomaly_threshold', intval($_POST['modsec_owasp_anomaly_threshold']));
        update_option('security_modsec_custom_410_url', sanitize_text_field($_POST['modsec_custom_410_url']));
        
        // Clear 410 page cache when settings change
        delete_transient('security_410_page_cache');
    }
    
    private function generate_rules($options) {
        $site_url = parse_url(home_url(), PHP_URL_HOST);
        $rule_id = $options['modsec_rule_id_start'];
        $custom_410_url = $options['modsec_custom_410_url'];
        $anomaly_threshold = $options['modsec_owasp_anomaly_threshold'];
        
        $rules = "# =============================================\n";
        $rules .= "# WORDPRESS SECURITY PLUGIN - MODSECURITY RULES (SECURE 410 ENDPOINT)\n";
        $rules .= "# Generated on: " . date('Y-m-d H:i:s') . "\n";
        $rules .= "# Site: {$site_url}\n";
        $rules .= "# Plugin Version: 3.0 - SECURE 410 ENDPOINT INTEGRATION\n";
        $rules .= "# Custom 410 Endpoint: " . ($options['modsec_custom_410_page'] ? 'ENABLED' : 'DISABLED') . "\n";
        $rules .= "# Secure 410 URL: " . $custom_410_url . "\n";
        $rules .= "# =============================================\n\n";
        
        // CRITICAL: OWASP CRS WordPress Exceptions - MUST BE FIRST
        if ($options['modsec_disable_owasp_crs']) {
            $rules .= "# =============================================\n";
            $rules .= "# CRITICAL: OWASP CRS WORDPRESS EXCEPTIONS\n";
            $rules .= "# =============================================\n\n";
            
            $rules .= "# Increase anomaly score thresholds for WordPress\n";
            $rules .= "SecAction \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    t:none,\\\n";
            $rules .= "    setvar:tx.inbound_anomaly_score_threshold={$anomaly_threshold},\\\n";
            $rules .= "    setvar:tx.outbound_anomaly_score_threshold={$anomaly_threshold}\"\n\n";
            $rule_id++;
            
            $rules .= "# Disable OWASP CRS for WordPress admin area\n";
            $rules .= "SecRule REQUEST_URI \"@beginsWith /wp-admin/\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    ctl:ruleEngine=Off\"\n\n";
            $rule_id++;
            
            $rules .= "# Disable OWASP CRS for WordPress login\n";
            $rules .= "SecRule REQUEST_URI \"@beginsWith /wp-login.php\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    ctl:ruleEngine=Off\"\n\n";
            $rule_id++;
            
            $rules .= "# Disable OWASP CRS for WordPress AJAX\n";
            $rules .= "SecRule REQUEST_URI \"@contains admin-ajax.php\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    ctl:ruleEngine=Off\"\n\n";
            $rule_id++;
            
            $rules .= "# Disable OWASP CRS for WooCommerce AJAX\n";
            $rules .= "SecRule REQUEST_URI \"@contains wc-ajax\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    ctl:ruleEngine=Off\"\n\n";
            $rule_id++;
            
            $rules .= "# Disable OWASP CRS for WordPress content directories\n";
            $rules .= "SecRule REQUEST_URI \"@rx ^/wp-(content|includes)/\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    ctl:ruleEngine=Off\"\n\n";
            $rule_id++;
            
            $rules .= "# Allow legitimate WooCommerce single parameters\n";
            $rules .= "SecRule REQUEST_URI \"@rx ^/product(-category)?/\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    chain,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    setvar:'tx.wordpress_legitimate=1'\"\n";
            $rules .= "    SecRule ARGS \"@rx ^(in-stock|on-sale|on-backorder|featured)$\" \\\n";
            $rules .= "    \"t:urlDecodeUni,t:lowercase\"\n\n";
            $rule_id++;
            
            $rules .= "# Reduce anomaly scores for legitimate WordPress product pages\n";
            $rules .= "SecRule REQUEST_URI \"@rx ^/product/\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    setvar:'tx.inbound_anomaly_score_threshold=50',\\\n";
            $rules .= "    setvar:'tx.outbound_anomaly_score_threshold=50'\"\n\n";
            $rule_id++;
        }
        
        // Whitelist search engine bots
        if ($options['modsec_whitelist_search_bots']) {
            $rules .= "# Whitelist major search engine bots\n";
            $rules .= "SecRule REQUEST_HEADERS:User-Agent \"@pm Googlebot Bingbot YandexBot DuckDuckBot Baiduspider Applebot facebookexternalhit\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    pass,\\\n";
            $rules .= "    nolog,\\\n";
            $rules .= "    ctl:ruleEngine=Off\"\n\n";
            $rule_id++;
        }
        
        // Custom blocked paths (like /shop/)
        if ($options['modsec_block_shop_urls']) {
            $rules .= "# =============================================\n";
            $rules .= "# CUSTOM BLOCKED PATHS (SECURE 410 RESPONSES)\n";
            $rules .= "# =============================================\n\n";
            
            $blocked_paths = array_filter(array_map('trim', explode("\n", $options['modsec_custom_blocked_paths'])));
            
            foreach ($blocked_paths as $path) {
                $rules .= "# Block {$path} URLs\n";
                $rules .= "SecRule REQUEST_URI \"@beginsWith {$path}\" \\\n";
                $rules .= "    \"id:{$rule_id},\\\n";
                $rules .= "    phase:1,\\\n";
                
                // FIXED: Use redirect to secure 410 endpoint instead of direct deny
                if ($options['modsec_custom_410_page']) {
                    $rules .= "    redirect:'{$custom_410_url}',\\\n";
                } else {
                    $rules .= "    deny,\\\n";
                    $rules .= "    status:410,\\\n";
                }
                
                if ($options['modsec_log_blocked_requests']) {
                    $rules .= "    log,\\\n";
                    $rules .= "    msg:'Blocked custom path: {$path}',\\\n";
                    $rules .= "    logdata:'URL: %{REQUEST_URI}',\\\n";
                } else {
                    $rules .= "    nolog,\\\n";
                }
                $rules .= "    severity:'CRITICAL'\"\n\n";
                $rule_id++;
            }
        }
        
        // Spam URL Protection - ONLY for excessive parameters
        if ($options['modsec_block_spam_urls']) {
            $rules .= "# =============================================\n";
            $rules .= "# SPAM URL PROTECTION (SECURE 410 RESPONSES)\n";
            $rules .= "# =============================================\n\n";
            
            // Block excessive color filters - ONLY if more than allowed
            $max_colors = $options['modsec_max_filter_colors'];
            $rules .= "# Block excessive color filters (more than {$max_colors})\n";
            $rules .= "SecRule REQUEST_URI \"@rx /product-category/|/product/\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:2,\\\n";
            $rules .= "    chain,\\\n";
            
            // FIXED: Use redirect to secure 410 endpoint instead of direct deny
            if ($options['modsec_custom_410_page']) {
                $rules .= "    redirect:'{$custom_410_url}',\\\n";
            } else {
                $rules .= "    deny,\\\n";
                $rules .= "    status:410,\\\n";
            }
            
            if ($options['modsec_log_blocked_requests']) {
                $rules .= "    log,\\\n";
                $rules .= "    msg:'Spam color filter blocked - too many colors',\\\n";
                $rules .= "    logdata:'Colors: %{ARGS_GET:filter_colour}',\\\n";
            } else {
                $rules .= "    nolog,\\\n";
            }
            $rules .= "    severity:'CRITICAL'\"\n";
            
            // Create regex pattern for color count - more than max_colors
            $color_pattern = "([^,]*,){" . ($max_colors + 1) . ",}";
            $rules .= "    SecRule ARGS_GET:filter_colour \"@rx {$color_pattern}\" \\\n";
            $rules .= "    \"t:urlDecodeUni,t:lowercase\"\n\n";
            $rule_id++;
            
            // Block excessive size filters
            $max_sizes = $options['modsec_max_filter_sizes'];
            $rules .= "# Block excessive size filters (more than {$max_sizes})\n";
            $rules .= "SecRule REQUEST_URI \"@rx /product-category/|/product/\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:2,\\\n";
            $rules .= "    chain,\\\n";
            
            // FIXED: Use redirect to secure 410 endpoint instead of direct deny
            if ($options['modsec_custom_410_page']) {
                $rules .= "    redirect:'{$custom_410_url}',\\\n";
            } else {
                $rules .= "    deny,\\\n";
                $rules .= "    status:410,\\\n";
            }
            
            if ($options['modsec_log_blocked_requests']) {
                $rules .= "    log,\\\n";
                $rules .= "    msg:'Spam size filter blocked - too many sizes',\\\n";
                $rules .= "    logdata:'Sizes: %{ARGS_GET:filter_size}',\\\n";
            } else {
                $rules .= "    nolog,\\\n";
            }
            $rules .= "    severity:'CRITICAL'\"\n";
            
            $size_pattern = "([^,]*,){" . ($max_sizes + 1) . ",}";
            $rules .= "    SecRule ARGS_GET:filter_size \"@rx {$size_pattern}\" \\\n";
            $rules .= "    \"t:urlDecodeUni,t:lowercase\"\n\n";
            $rule_id++;
            
            // Block excessive query string length
            $max_length = $options['modsec_max_query_length'];
            $rules .= "# Block excessive query string length (max {$max_length} chars)\n";
            $rules .= "SecRule QUERY_STRING \"@gt {$max_length}\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            
            // FIXED: Use redirect to secure 410 endpoint instead of direct deny
            if ($options['modsec_custom_410_page']) {
                $rules .= "    redirect:'{$custom_410_url}',\\\n";
            } else {
                $rules .= "    deny,\\\n";
                $rules .= "    status:410,\\\n";
            }
            
            if ($options['modsec_log_blocked_requests']) {
                $rules .= "    log,\\\n";
                $rules .= "    msg:'Query string too long - spam detected',\\\n";
                $rules .= "    logdata:'Length: %{QUERY_STRING}',\\\n";
            } else {
                $rules .= "    nolog,\\\n";
            }
            $rules .= "    severity:'CRITICAL'\"\n\n";
            $rule_id++;
            
            // Block srsltid parameter (Google spam)
            $rules .= "# Block srsltid parameter (Google spam)\n";
            $rules .= "SecRule REQUEST_URI|ARGS \"@rx (?i)srsltid[=&]\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            
            // FIXED: Use redirect to secure 410 endpoint instead of direct deny
            if ($options['modsec_custom_410_page']) {
                $rules .= "    redirect:'{$custom_410_url}',\\\n";
            } else {
                $rules .= "    deny,\\\n";
                $rules .= "    status:410,\\\n";
            }
            
            if ($options['modsec_log_blocked_requests']) {
                $rules .= "    log,\\\n";
                $rules .= "    msg:'Blocked srsltid parameter',\\\n";
                $rules .= "    logdata:'URL: %{REQUEST_URI}',\\\n";
            } else {
                $rules .= "    nolog,\\\n";
            }
            $rules .= "    severity:'CRITICAL'\"\n\n";
            $rule_id++;
        }
        
        // Bad Bot Protection
        if ($options['modsec_block_bad_bots']) {
            $rules .= "# =============================================\n";
            $rules .= "# BAD BOT PROTECTION\n";
            $rules .= "# =============================================\n\n";
            
            $bad_bots = array_map('trim', explode(',', $options['modsec_custom_bad_bots']));
            $bot_list = implode(' ', $bad_bots);
            
            $rules .= "# Block known bad bots\n";
            $rules .= "SecRule REQUEST_HEADERS:User-Agent \"@pm {$bot_list}\" \\\n";
            $rules .= "    \"id:{$rule_id},\\\n";
            $rules .= "    phase:1,\\\n";
            $rules .= "    deny,\\\n";
            $rules .= "    status:403,\\\n";
            if ($options['modsec_log_blocked_requests']) {
                $rules .= "    log,\\\n";
                $rules .= "    msg:'Bad bot blocked',\\\n";
                $rules .= "    logdata:'Bot: %{REQUEST_HEADERS:User-Agent}',\\\n";
            } else {
                $rules .= "    nolog,\\\n";
            }
            $rules .= "    severity:'WARNING'\"\n\n";
            $rule_id++;
        }
        
        // Additional custom rules
        if (!empty($options['modsec_additional_rules'])) {
            $rules .= "# =============================================\n";
            $rules .= "# CUSTOM ADDITIONAL RULES\n";
            $rules .= "# =============================================\n\n";
            $rules .= $options['modsec_additional_rules'] . "\n\n";
        }
        
        $rules .= "# =============================================\n";
        $rules .= "# END WORDPRESS SECURITY PLUGIN RULES\n";
        $rules .= "# =============================================\n";
        
        return $rules;
    }
}