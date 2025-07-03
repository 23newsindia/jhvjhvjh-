<?php
// includes/class-bot-blackhole.php

if (!defined('ABSPATH')) {
    exit;
}

class BotBlackhole {
    private $options_cache = array();
    private $blocked_bots_cache = null;
    private $whitelisted_bots_cache = null;
    private $whitelisted_ips_cache = null;
    private $table_name;
    private $is_admin = null;
    private $is_logged_in = null;
    private $whitelist_cache = null;
    private $current_user_can_manage = null;
    
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'security_blocked_bots';
        
        // Always ensure table exists and is up to date
        $this->ensure_table_exists();
        
        // Hook into WordPress init to initialize user checks and protection
        add_action('init', array($this, 'init_protection'), 1);
    }
    
    public function init_protection() {
        // Initialize user checks now that WordPress is loaded
        $this->is_admin = is_admin();
        $this->is_logged_in = is_user_logged_in();
        $this->current_user_can_manage = current_user_can('manage_options');
        
        // Only initialize if bot protection is enabled
        if ($this->get_option('security_enable_bot_protection', true)) {
            $this->init();
        }
    }
    
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }
    
    private function init() {
        // Only add frontend hooks if not in admin and not logged in as admin
        if (!$this->is_admin && !$this->current_user_can_manage) {
            // Create blackhole trap - FIXED: Check stealth mode
            if (!$this->get_option('security_bot_stealth_mode', false)) {
                add_action('wp_footer', array($this, 'add_blackhole_trap'));
                add_action('login_footer', array($this, 'add_blackhole_trap'));
            } else {
                // In stealth mode, use a more subtle approach
                add_action('wp_footer', array($this, 'add_stealth_blackhole_trap'));
                add_action('login_footer', array($this, 'add_stealth_blackhole_trap'));
            }
            
            // Check for bot access - highest priority
            add_action('init', array($this, 'check_bot_access'), 2); // Priority 2 to run after init_protection
        }
        
        // Add to robots.txt
        add_filter('robots_txt', array($this, 'add_robots_disallow'), 11, 2);
        
        // AJAX handlers - Add these for dashboard functionality
        add_action('wp_ajax_bot_blocker_stats', array($this, 'get_bot_stats'));
        add_action('wp_ajax_bot_blocker_unblock', array($this, 'unblock_bot'));
        
        // Schedule cleanup
        add_action('admin_init', array($this, 'schedule_cleanup'));
        add_action('bot_blackhole_cleanup', array($this, 'cleanup_logs'));
        
        // Add live traffic capture (only for non-admin users)
        if (!$this->is_admin && !$this->current_user_can_manage) {
            add_action('wp', array($this, 'capture_live_traffic'), 1);
        }
    }
    
    public function capture_live_traffic() {
        // CRITICAL: Skip for admin users and logged-in users if configured
        if ($this->current_user_can_manage || 
            ($this->is_logged_in && $this->get_option('security_bot_skip_logged_users', true))) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $user_agent = $this->get_user_agent();
        $request_uri = $_SERVER['REQUEST_URI'];
        
        // FIXED: Skip WooCommerce AJAX requests completely - don't track them
        if (strpos($request_uri, 'wc-ajax=') !== false) {
            return;
        }
        
        // Skip WordPress AJAX requests
        if (strpos($request_uri, '/wp-admin/admin-ajax.php') !== false) {
            return;
        }
        
        // Skip other WordPress core requests
        if ($this->is_wordpress_core_request($request_uri)) {
            return;
        }
        
        // Skip common static files and assets
        if (preg_match('/\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$/i', $request_uri)) {
            return;
        }
        
        // Log all other traffic for monitoring
        $this->log_traffic($ip, $user_agent, $request_uri, 'Live Traffic');
    }
    
    private function log_traffic($ip, $user_agent, $request_uri, $reason) {
        global $wpdb;
        
        try {
            // FIXED: Check if this IP already exists (not just in last hour)
            $existing = $wpdb->get_row($wpdb->prepare(
                "SELECT id, hits, request_uri FROM {$this->table_name} 
                 WHERE ip_address = %s AND is_blocked = 0 
                 ORDER BY last_seen DESC LIMIT 1",
                $ip
            ));
            
            if ($existing) {
                // FIXED: Always increment hit count and update URLs
                $existing_urls = explode('|', $existing->request_uri);
                
                // Add new URL if it's not already in the list
                if (!in_array($request_uri, $existing_urls)) {
                    $existing_urls[] = $request_uri;
                    // Keep only last 10 URLs to prevent database bloat
                    $existing_urls = array_slice($existing_urls, -10);
                    $updated_urls = implode('|', $existing_urls);
                } else {
                    $updated_urls = $existing->request_uri;
                }
                
                $wpdb->update(
                    $this->table_name,
                    array(
                        'hits' => $existing->hits + 1, 
                        'timestamp' => current_time('mysql'),
                        'last_seen' => current_time('mysql'),
                        'request_uri' => $updated_urls,
                        'user_agent' => $user_agent // Update user agent in case it changed
                    ),
                    array('id' => $existing->id),
                    array('%d', '%s', '%s', '%s', '%s'),
                    array('%d')
                );
            } else {
                // Insert new traffic entry
                $wpdb->insert(
                    $this->table_name,
                    array(
                        'ip_address' => $ip,
                        'user_agent' => $user_agent,
                        'request_uri' => $request_uri,
                        'referrer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
                        'timestamp' => current_time('mysql'),
                        'first_seen' => current_time('mysql'),
                        'last_seen' => current_time('mysql'),
                        'block_reason' => $reason,
                        'blocked_reason' => $reason,
                        'is_blocked' => 0,
                        'hits' => 1
                    ),
                    array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d')
                );
            }
        } catch (Exception $e) {
            error_log('Bot Blackhole Traffic Log Error: ' . $e->getMessage());
        }
    }
    
    public function ensure_table_exists() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            user_agent text NOT NULL,
            request_uri text NOT NULL,
            referrer text,
            timestamp datetime NOT NULL,
            block_reason varchar(100) NOT NULL,
            hits int(11) DEFAULT 1,
            first_seen datetime DEFAULT NULL,
            last_seen datetime DEFAULT NULL,
            is_blocked tinyint(1) DEFAULT 1,
            blocked_reason varchar(100) DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY ip_timestamp (ip_address, timestamp),
            KEY user_agent_key (user_agent(100)),
            KEY is_blocked (is_blocked),
            KEY last_seen (last_seen)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
        
        // Update existing records to have the new columns
        $this->update_table_structure();
    }
    
    private function update_table_structure() {
        global $wpdb;
        
        // Check if table exists first
        $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$this->table_name}'") === $this->table_name;
        
        if (!$table_exists) {
            // Table doesn't exist, create it
            $this->ensure_table_exists();
            return;
        }
        
        // Get current table structure
        $columns = $wpdb->get_results("SHOW COLUMNS FROM {$this->table_name}");
        $existing_columns = array();
        foreach ($columns as $column) {
            $existing_columns[] = $column->Field;
        }
        
        // Add missing columns if they don't exist
        $columns_to_add = array(
            'hits' => 'ADD COLUMN hits int(11) DEFAULT 1',
            'first_seen' => 'ADD COLUMN first_seen datetime DEFAULT NULL',
            'last_seen' => 'ADD COLUMN last_seen datetime DEFAULT NULL', 
            'is_blocked' => 'ADD COLUMN is_blocked tinyint(1) DEFAULT 1',
            'blocked_reason' => 'ADD COLUMN blocked_reason varchar(100) DEFAULT NULL'
        );
        
        foreach ($columns_to_add as $column => $sql) {
            if (!in_array($column, $existing_columns)) {
                $result = $wpdb->query("ALTER TABLE {$this->table_name} {$sql}");
                if ($result === false) {
                    error_log("Failed to add column {$column} to {$this->table_name}: " . $wpdb->last_error);
                }
            }
        }
        
        // Remove status column if it exists (causing conflicts)
        if (in_array('status', $existing_columns)) {
            $wpdb->query("ALTER TABLE {$this->table_name} DROP COLUMN status");
        }
        
        // Update existing records to populate new columns
        $wpdb->query("UPDATE {$this->table_name} SET first_seen = timestamp WHERE first_seen IS NULL");
        $wpdb->query("UPDATE {$this->table_name} SET last_seen = timestamp WHERE last_seen IS NULL");
        $wpdb->query("UPDATE {$this->table_name} SET blocked_reason = block_reason WHERE blocked_reason IS NULL");
        $wpdb->query("UPDATE {$this->table_name} SET hits = 1 WHERE hits IS NULL OR hits = 0");
        $wpdb->query("UPDATE {$this->table_name} SET is_blocked = 1 WHERE is_blocked IS NULL");
    }
    
    // FIXED: Add stealth mode blackhole trap
    public function add_stealth_blackhole_trap() {
        // Don't show trap to logged-in users or admins
        if ($this->is_logged_in || $this->current_user_can_manage) {
            return;
        }
        
        $trap_url = home_url('/blackhole-trap/');
        $nonce = wp_create_nonce('blackhole_trap');
        
        ?>
        <!-- Stealth Bot Trap - Invisible to security scanners -->
        <script type="text/javascript">
        // Only bots that execute JavaScript and follow programmatic links will trigger this
        if (typeof document !== 'undefined' && document.createElement) {
            var botTrap = document.createElement('div');
            botTrap.style.cssText = 'position:absolute;left:-9999px;top:-9999px;width:1px;height:1px;overflow:hidden;';
            botTrap.innerHTML = '<a href="<?php echo esc_url($trap_url . '?_wpnonce=' . $nonce); ?>" style="display:none;" rel="nofollow"></a>';
            if (document.body) {
                document.body.appendChild(botTrap);
            }
        }
        </script>
        <?php
    }
    
    public function add_blackhole_trap() {
        // Don't show trap to logged-in users or admins
        if ($this->is_logged_in || $this->current_user_can_manage) {
            return;
        }
        
        $trap_url = home_url('/blackhole-trap/');
        $nonce = wp_create_nonce('blackhole_trap');
        
        ?>
        <!-- Blackhole Trap for Bad Bots - Hidden from humans -->
        <div style="position: absolute; left: -9999px; top: -9999px; visibility: hidden; display: none;">
            <a href="<?php echo esc_url($trap_url . '?_wpnonce=' . $nonce); ?>" rel="nofollow">Do not follow this link</a>
        </div>
        <?php
    }
    
    public function add_robots_disallow($output, $public) {
        if ($public) {
            $output .= "\n# Blackhole trap for bad bots\n";
            $output .= "Disallow: /blackhole-trap/\n";
            $output .= "Disallow: /*blackhole*\n";
        }
        return $output;
    }
    
    public function check_bot_access() {
        // CRITICAL: Skip all checks for logged-in users and admins - FIRST CHECK
        if ($this->is_logged_in || $this->current_user_can_manage) {
            return;
        }
        
        // Skip checks for admin area and login page unless specifically enabled
        if (is_admin() && !$this->get_option('security_protect_admin', false)) {
            return;
        }
        
        if ($this->is_login_page() && !$this->get_option('security_protect_login', false)) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $user_agent = $this->get_user_agent();
        $request_uri = $_SERVER['REQUEST_URI'];
        
        // ENHANCED: Check for suspicious Facebook crawler behavior
        if ($this->is_suspicious_facebook_crawler($user_agent, $request_uri)) {
            $this->trap_bot($ip, $user_agent, 'Suspicious Facebook crawler behavior');
        }
        
        // Enhanced whitelist check - FIRST priority
        if ($this->is_whitelisted($ip, $user_agent, $request_uri)) {
            return;
        }
        
        // Skip WooCommerce AJAX requests completely
        if (strpos($request_uri, 'wc-ajax=') !== false) {
            return;
        }
        
        // Skip WordPress AJAX requests
        if (strpos($request_uri, '/wp-admin/admin-ajax.php') !== false) {
            return;
        }
        
        // Fast IP block check using transient cache
        $blocked_transient = 'bot_blocked_' . md5($ip);
        if (get_transient($blocked_transient)) {
            $this->block_bot('IP previously blocked');
        }
        
        // Check if accessing blackhole trap
        if (strpos($request_uri, '/blackhole-trap/') !== false || strpos($request_uri, 'blackhole') !== false) {
            $this->trap_bot($ip, $user_agent, 'Accessed blackhole trap');
        }
        
        // Enhanced bot detection with scoring system
        $bot_score = $this->calculate_bot_score($ip, $user_agent, $request_uri);
        
        if ($bot_score >= 100) {
            $this->trap_bot($ip, $user_agent, 'High bot score: ' . $bot_score);
        } elseif ($bot_score >= 70) {
            // Log suspicious activity but don't block yet
            $this->log_suspicious_activity($ip, $user_agent, $request_uri, 'Suspicious score: ' . $bot_score);
        }
    }
    
    // NEW: Check for suspicious Facebook crawler behavior
    private function is_suspicious_facebook_crawler($user_agent, $request_uri) {
        // Check if it's claiming to be Facebook's crawler
        if (strpos($user_agent, 'meta-externalagent') === false && 
            strpos($user_agent, 'facebookexternalhit') === false) {
            return false;
        }
        
        // If it's accessing filter URLs, it's suspicious
        if (strpos($request_uri, 'filter_') !== false) {
            return true;
        }
        
        // If it's accessing multiple query parameters, it's suspicious
        $parsed_url = parse_url($request_uri);
        if (isset($parsed_url['query'])) {
            parse_str($parsed_url['query'], $query_params);
            if (count($query_params) > 3) {
                return true;
            }
        }
        
        return false;
    }
    
    private function is_login_page() {
        return in_array($GLOBALS['pagenow'], array('wp-login.php', 'wp-register.php'));
    }
    
    private function is_whitelisted($ip, $user_agent, $request_uri) {
        if ($this->whitelist_cache === null) {
            $this->build_whitelist_cache();
        }
        
        // Check whitelisted IPs (including ranges)
        foreach ($this->whitelist_cache['ips'] as $whitelisted_ip) {
            if ($this->ip_in_range($ip, $whitelisted_ip)) {
                return true;
            }
        }
        
        // ENHANCED: More strict user agent checking for Facebook crawler
        $user_agent_lower = strtolower($user_agent);
        
        // If it claims to be Facebook but is accessing filter URLs, don't whitelist
        if ((strpos($user_agent_lower, 'meta-externalagent') !== false || 
             strpos($user_agent_lower, 'facebookexternalhit') !== false) &&
            strpos($request_uri, 'filter_') !== false) {
            return false; // Don't whitelist suspicious Facebook crawler behavior
        }
        
        // Check whitelisted user agents
        foreach ($this->whitelist_cache['agents'] as $whitelisted_agent) {
            if (strpos($user_agent_lower, $whitelisted_agent) !== false) {
                return true;
            }
        }
        
        // Check for legitimate browser patterns
        if ($this->is_legitimate_browser($user_agent)) {
            return true;
        }
        
        // Check for WordPress core requests
        if ($this->is_wordpress_core_request($request_uri)) {
            return true;
        }
        
        return false;
    }
    
    private function build_whitelist_cache() {
        // Get custom whitelisted IPs
        $custom_ips = $this->get_option('security_bot_whitelist_ips', '');
        $whitelist_ips = array_filter(array_map('trim', explode("\n", $custom_ips)));
        
        // Add default safe IPs
        $default_ips = array(
            '127.0.0.1',
            '::1',
            $_SERVER['SERVER_ADDR'] ?? '',
            $_SERVER['REMOTE_ADDR'] ?? ''
        );
        
        $whitelist_ips = array_merge($whitelist_ips, array_filter($default_ips));
        
        // Get custom whitelisted user agents
        $custom_agents = $this->get_option('security_bot_whitelist_agents', $this->get_default_whitelist_bots());
        $whitelist_agents = array_filter(array_map('trim', explode("\n", strtolower($custom_agents))));
        
        $this->whitelist_cache = array(
            'ips' => array_unique($whitelist_ips),
            'agents' => array_unique($whitelist_agents)
        );
    }
    
    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            // Single IP
            return $ip === $range || strpos($ip, $range) === 0;
        }
        
        // CIDR range
        list($subnet, $mask) = explode('/', $range);
        if ((ip2long($ip) & ~((1 << (32 - $mask)) - 1)) == ip2long($subnet)) {
            return true;
        }
        
        return false;
    }
    
    private function is_legitimate_browser($user_agent) {
        $legitimate_patterns = array(
            '/Mozilla\/.*Chrome\/.*Safari/i',
            '/Mozilla\/.*Firefox/i',
            '/Mozilla\/.*Safari.*Version/i',
            '/Mozilla\/.*Edge/i',
            '/Mozilla\/.*Opera/i'
        );
        
        foreach ($legitimate_patterns as $pattern) {
            if (preg_match($pattern, $user_agent)) {
                // Additional check for common browser characteristics
                if (strpos($user_agent, 'Mozilla') !== false && 
                    (strpos($user_agent, 'Chrome') !== false || 
                     strpos($user_agent, 'Firefox') !== false || 
                     strpos($user_agent, 'Safari') !== false)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    private function is_wordpress_core_request($request_uri) {
        $core_paths = array(
            '/wp-admin/',
            '/wp-includes/',
            '/wp-content/',
            '/wp-login.php',
            '/wp-cron.php',
            '/xmlrpc.php',
            'wc-ajax=',
            'admin-ajax.php'
        );
        
        foreach ($core_paths as $path) {
            if (strpos($request_uri, $path) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function calculate_bot_score($ip, $user_agent, $request_uri) {
        $score = 0;
        
        // User agent analysis
        $score += $this->analyze_user_agent($user_agent);
        
        // Request pattern analysis
        $score += $this->analyze_request_pattern($request_uri);
        
        // Behavioral analysis
        $score += $this->analyze_behavior($ip);
        
        return $score;
    }
    
    private function analyze_user_agent($user_agent) {
        $score = 0;
        $ua_lower = strtolower($user_agent);
        
        // Empty or minimal user agent
        if (empty($user_agent) || $user_agent === '-') {
            $score += 50;
        }
        
        // Known bad bot patterns
        $bad_patterns = array(
            'bot', 'crawler', 'spider', 'scraper', 'scanner', 'harvester',
            'extractor', 'libwww', 'curl', 'wget', 'python', 'perl', 'java',
            'php', 'masscan', 'nmap', 'sqlmap', 'nikto'
        );
        
        foreach ($bad_patterns as $pattern) {
            if (strpos($ua_lower, $pattern) !== false) {
                $score += 30;
            }
        }
        
        // Suspicious characteristics
        if (strlen($user_agent) < 20) {
            $score += 20;
        }
        
        if (!preg_match('/Mozilla/i', $user_agent) && !$this->is_known_good_bot($ua_lower)) {
            $score += 25;
        }
        
        return $score;
    }
    
    private function analyze_request_pattern($request_uri) {
        $score = 0;
        
        // Skip WooCommerce AJAX requests
        if (strpos($request_uri, 'wc-ajax=') !== false) {
            return 0;
        }
        
        // Suspicious request patterns
        $suspicious_patterns = array(
            '/wp-config', '/xmlrpc', '/.env', '/phpmyadmin',
            '/admin', '/wp-json/wp/v2/users', '/.git',
            '/backup', '/sql', '/database'
        );
        
        foreach ($suspicious_patterns as $pattern) {
            if (strpos($request_uri, $pattern) !== false) {
                $score += 40;
            }
        }
        
        // ENHANCED: Check for filter spam patterns
        if (strpos($request_uri, 'filter_') !== false) {
            $parsed_url = parse_url($request_uri);
            if (isset($parsed_url['query'])) {
                parse_str($parsed_url['query'], $query_params);
                
                // Count filter parameters
                $filter_count = 0;
                foreach ($query_params as $key => $value) {
                    if (strpos($key, 'filter_') === 0) {
                        $filter_count++;
                        // Count comma-separated values
                        $values = explode(',', $value);
                        if (count($values) > 1) {
                            $score += 20; // Multiple values in single filter
                        }
                    }
                }
                
                if ($filter_count > 2) {
                    $score += 30; // Too many filter types
                }
            }
        }
        
        // IMPROVED: More intelligent rate limiting for legitimate users
        $ip = $this->get_client_ip();
        $request_count = get_transient('bot_requests_' . md5($ip));
        
        // FIXED: Much more lenient rate limiting - 100 requests per minute instead of 50
        if ($request_count && $request_count > 100) {
            $score += 30;
        }
        
        return $score;
    }
    
    private function analyze_behavior($ip) {
        $score = 0;
        
        // Check if IP has been flagged before
        global $wpdb;
        $previous_blocks = $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$this->table_name} 
             WHERE ip_address = %s AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
            $ip
        ));
        
        if ($previous_blocks > 0) {
            $score += ($previous_blocks * 10);
        }
        
        return $score;
    }
    
    private function is_known_good_bot($user_agent) {
        $good_bots = array(
            'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
            'yandexbot', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
            'pinterestbot', 'applebot', 'ia_archiver'
        );
        
        foreach ($good_bots as $bot) {
            if (strpos($user_agent, $bot) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    private function log_suspicious_activity($ip, $user_agent, $request_uri, $reason) {
        global $wpdb;
        
        try {
            // Check if this IP already exists
            $existing = $wpdb->get_row($wpdb->prepare(
                "SELECT * FROM {$this->table_name} WHERE ip_address = %s",
                $ip
            ));
            
            if ($existing) {
                // Update existing record
                $wpdb->update(
                    $this->table_name,
                    array(
                        'hits' => $existing->hits + 1,
                        'last_seen' => current_time('mysql'),
                        'request_uri' => $request_uri,
                        'blocked_reason' => $reason
                    ),
                    array('ip_address' => $ip),
                    array('%d', '%s', '%s', '%s'),
                    array('%s')
                );
            } else {
                // Insert new record
                $wpdb->insert(
                    $this->table_name,
                    array(
                        'ip_address' => $ip,
                        'user_agent' => $user_agent,
                        'request_uri' => $request_uri,
                        'referrer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
                        'timestamp' => current_time('mysql'),
                        'first_seen' => current_time('mysql'),
                        'last_seen' => current_time('mysql'),
                        'block_reason' => $reason,
                        'blocked_reason' => $reason,
                        'is_blocked' => 0,
                        'hits' => 1
                    ),
                    array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d')
                );
            }
        } catch (Exception $e) {
            error_log('Bot Blackhole Log Error: ' . $e->getMessage());
        }
    }
    
    private function trap_bot($ip, $user_agent, $reason) {
        // Final safety check - never block admins or logged-in users
        if ($this->is_logged_in || $this->current_user_can_manage) {
            return;
        }
        
        // Log the bot
        $this->log_blocked_bot($ip, $user_agent, $_SERVER['REQUEST_URI'], $reason);
        
        // Cache the block for 24 hours
        $blocked_transient = 'bot_blocked_' . md5($ip);
        set_transient($blocked_transient, true, 24 * HOUR_IN_SECONDS);
        
        // Send email alert if enabled
        if ($this->get_option('security_bot_email_alerts', false)) {
            $this->send_bot_alert($ip, $user_agent, $reason);
        }
        
        // Block the bot
        $this->block_bot($reason);
    }
    
    private function log_blocked_bot($ip, $user_agent, $request_uri, $reason) {
        global $wpdb;
        
        try {
            // Check if this IP was already blocked recently
            $existing = $wpdb->get_row($wpdb->prepare(
                "SELECT id, hits FROM {$this->table_name} 
                 WHERE ip_address = %s AND is_blocked = 1 
                 AND timestamp > DATE_SUB(NOW(), INTERVAL 1 HOUR)
                 ORDER BY timestamp DESC LIMIT 1",
                $ip
            ));
            
            if ($existing) {
                // Update hit count
                $wpdb->update(
                    $this->table_name,
                    array(
                        'hits' => $existing->hits + 1, 
                        'timestamp' => current_time('mysql'),
                        'last_seen' => current_time('mysql')
                    ),
                    array('id' => $existing->id),
                    array('%d', '%s', '%s'),
                    array('%d')
                );
            } else {
                // Insert new record
                $wpdb->insert(
                    $this->table_name,
                    array(
                        'ip_address' => $ip,
                        'user_agent' => $user_agent,
                        'request_uri' => $request_uri,
                        'referrer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '',
                        'timestamp' => current_time('mysql'),
                        'first_seen' => current_time('mysql'),
                        'last_seen' => current_time('mysql'),
                        'block_reason' => $reason,
                        'blocked_reason' => $reason,
                        'is_blocked' => 1,
                        'hits' => 1
                    ),
                    array('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%d', '%d')
                );
            }
        } catch (Exception $e) {
            error_log('Bot Blackhole Log Error: ' . $e->getMessage());
        }
    }
    
    private function send_bot_alert($ip, $user_agent, $reason) {
        $email = $this->get_option('security_bot_alert_email', get_option('admin_email'));
        $subject = '[' . get_bloginfo('name') . '] Bad Bot Blocked';
        
        $message = "A bad bot has been blocked on your website.\n\n";
        $message .= "IP Address: " . $ip . "\n";
        $message .= "User Agent: " . $user_agent . "\n";
        $message .= "Reason: " . $reason . "\n";
        $message .= "Time: " . current_time('mysql') . "\n";
        $message .= "Site: " . home_url() . "\n\n";
        $message .= "To whitelist this IP, add it to Security Settings > Bot Protection > Whitelisted IPs\n";
        
        wp_mail($email, $subject, $message);
    }
    
    private function block_bot($reason) {
        // Check if headers have already been sent
        if (headers_sent()) {
            // If headers are sent, just exit
            exit;
        }
        
        $status_code = $this->get_option('security_bot_block_status', 403);
        $message = $this->get_option('security_bot_block_message', 'Access Denied');
        
        status_header($status_code);
        nocache_headers();
        
        if ($status_code == 410) {
            header('HTTP/1.1 410 Gone');
            header('Status: 410 Gone');
        } elseif ($status_code == 444) {
            header('HTTP/1.1 444 No Response');
            header('Status: 444 No Response');
        } else {
            header('HTTP/1.1 403 Forbidden');
            header('Status: 403 Forbidden');
        }
        
        header('Content-Type: text/html; charset=utf-8');
        
        if ($status_code == 444) {
            exit;
        }
        
        $custom_message = $this->get_option('security_bot_custom_message', '');
        if (!empty($custom_message)) {
            echo $custom_message;
        } else {
            echo $this->get_default_block_page($message);
        }
        
        exit;
    }
    
    private function get_default_block_page($message) {
        return '<!DOCTYPE html>
<html>
<head>
    <title>Access Denied</title>
    <meta name="robots" content="noindex, nofollow">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .block-container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="block-container">
        <h1>Access Denied</h1>
        <p>' . esc_html($message) . '</p>
        <p>If you believe this is an error, please contact the site administrator.</p>
    </div>
</body>
</html>';
    }
    
    private function get_client_ip() {
        $ip_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
    }
    
    private function get_user_agent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
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
    
    public function schedule_cleanup() {
        if (!wp_next_scheduled('bot_blackhole_cleanup')) {
            wp_schedule_event(time(), 'daily', 'bot_blackhole_cleanup');
        }
    }
    
    public function cleanup_logs() {
        global $wpdb;
        
        // Keep only last 30 days of logs
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
        
        // Keep only 1000 most recent entries
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE id NOT IN (
                SELECT id FROM (
                    SELECT id FROM {$this->table_name} ORDER BY timestamp DESC LIMIT 1000
                ) AS temp
            )"
        );
    }
    
    // AJAX handler for getting bot stats
    public function get_bot_stats() {
        // Verify nonce
        if (!check_ajax_referer('security_bot_stats', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
            return;
        }
        
        try {
            global $wpdb;
            
            // Ensure table exists and is up to date
            $this->ensure_table_exists();
            
            // Check if table exists
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$this->table_name}'") === $this->table_name;
            
            if (!$table_exists) {
                wp_send_json_success(array(
                    'total_blocked' => 0,
                    'today_blocked' => 0,
                    'week_blocked' => 0,
                    'top_blocked_ips' => array()
                ));
                return;
            }
            
            $stats = array(
                'total_blocked' => (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1"),
                'today_blocked' => (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1 AND DATE(last_seen) = CURDATE()"),
                'week_blocked' => (int)$wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1 AND last_seen >= DATE_SUB(NOW(), INTERVAL 7 DAY)"),
                'top_blocked_ips' => $wpdb->get_results("SELECT ip_address, SUM(hits) as hits FROM {$this->table_name} WHERE is_blocked = 1 GROUP BY ip_address ORDER BY hits DESC LIMIT 10", ARRAY_A)
            );
            
            // Ensure top_blocked_ips is an array
            if (!$stats['top_blocked_ips']) {
                $stats['top_blocked_ips'] = array();
            }
            
            wp_send_json_success($stats);
            
        } catch (Exception $e) {
            error_log('Bot Blackhole Stats Error: ' . $e->getMessage());
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }
    
    // AJAX handler for unblocking bots
    public function unblock_bot() {
        // Verify nonce
        if (!check_ajax_referer('security_bot_unblock', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Unauthorized');
            return;
        }
        
        if (!isset($_POST['ip']) || empty($_POST['ip'])) {
            wp_send_json_error('IP address is required');
            return;
        }
        
        $ip = sanitize_text_field($_POST['ip']);
        
        // Validate IP format
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('Invalid IP address format');
            return;
        }
        
        try {
            global $wpdb;
            $result = $wpdb->update(
                $this->table_name,
                array('is_blocked' => 0),
                array('ip_address' => $ip),
                array('%d'),
                array('%s')
            );
            
            // Also remove from transient cache
            $blocked_transient = 'bot_blocked_' . md5($ip);
            delete_transient($blocked_transient);
            
            if ($result !== false) {
                wp_send_json_success('IP unblocked successfully');
            } else {
                wp_send_json_error('Failed to unblock IP - IP may not exist in database');
            }
            
        } catch (Exception $e) {
            error_log('Bot Blackhole Unblock Error: ' . $e->getMessage());
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }
    
    public function get_blocked_bots_stats() {
        global $wpdb;
        
        $stats = array();
        
        // Total blocked bots
        $stats['total'] = $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1");
        
        // Blocked today
        $stats['today'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1 AND DATE(timestamp) = CURDATE()"
        );
        
        // Blocked this week
        $stats['week'] = $wpdb->get_var(
            "SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1 AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        );
        
        // Top blocked IPs
        $stats['top_ips'] = $wpdb->get_results(
            "SELECT ip_address, SUM(hits) as count FROM {$this->table_name} 
             WHERE is_blocked = 1 GROUP BY ip_address ORDER BY count DESC LIMIT 10",
            ARRAY_A
        );
        
        return $stats;
    }
    
    // Dashboard compatibility methods
    public function get_blocked_bots($limit = 20, $offset = 0) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT *, blocked_reason as block_reason FROM {$this->table_name} 
             WHERE is_blocked = 1 ORDER BY last_seen DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ));
    }
    
    public function get_bot_activity($limit = 50, $offset = 0) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT *, blocked_reason as block_reason FROM {$this->table_name} 
             ORDER BY last_seen DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ));
    }
    
    // Admin functions for managing blocked IPs
    public function unblock_ip($ip) {
        if (!current_user_can('manage_options')) {
            return false;
        }
        
        global $wpdb;
        
        // Remove from database
        $wpdb->delete($this->table_name, array('ip_address' => $ip), array('%s'));
        
        // Remove from transient cache
        $blocked_transient = 'bot_blocked_' . md5($ip);
        delete_transient($blocked_transient);
        
        return true;
    }
    
    public function whitelist_ip($ip) {
        if (!current_user_can('manage_options')) {
            return false;
        }
        
        $current_whitelist = get_option('security_bot_whitelist_ips', '');
        $whitelist_array = array_filter(array_map('trim', explode("\n", $current_whitelist)));
        
        if (!in_array($ip, $whitelist_array)) {
            $whitelist_array[] = $ip;
            $new_whitelist = implode("\n", $whitelist_array);
            update_option('security_bot_whitelist_ips', $new_whitelist);
            
            // Clear cache
            $this->whitelist_cache = null;
            
            // Unblock the IP
            $this->unblock_ip($ip);
            
            return true;
        }
        
        return false;
    }
}