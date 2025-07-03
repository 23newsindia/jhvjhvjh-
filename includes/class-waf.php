<?php

class SecurityWAF {
    private static $instance = null;
    private $blocked_ips_cache = array();
    private $request_limit;
    private $blacklist_threshold;
    private $patterns_cache = array();
    private $input_cache = null;
    private $table_name;
    private static $is_logged_in = null;
    private static $current_user_can_manage = null;
    
    public function __construct() {
        if (!get_option('security_enable_waf', true)) {
            return;
        }
        
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'security_waf_logs';
        
        // Initialize static checks once for performance
        if (self::$is_logged_in === null) {
            self::$is_logged_in = is_user_logged_in();
        }
        
        if (self::$current_user_can_manage === null) {
            self::$current_user_can_manage = current_user_can('manage_options');
        }
        
        // Cache settings on instantiation
        $this->request_limit = (int)get_option('security_waf_request_limit', 100);
        $this->blacklist_threshold = (int)get_option('security_waf_blacklist_threshold', 5);
        $this->blocked_ips_cache = get_option('waf_blocked_ips', array());
        
        // WordPress-friendly security patterns
        $this->patterns_cache = array(
            'sql' => array(
                '/union\s+all\s+select.*?from/i',
                '/having\s+[\d\']/i',
                '/sleep\s*\(\s*\d+\s*\)/i',
                '/benchmark\s*\(/i'
            ),
            'xss' => array(
                '/<script\b[^>]*>(.*?)<\/script>/is',
                '/javascript:[^a-z\s]*/i',
                '/on(load|error|click|mouseover|submit)\s*=\s*[^a-z\s]*/i'
            ),
            'file' => array(
                '/\.\.[\/\\\]/i',
                '/etc\/passwd/i',
                '/\/proc\/self\//i'
            )
        );
        
        $this->init();
    }

    private function ensure_table_exists() {
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            violation_type varchar(50) NOT NULL,
            request_uri text NOT NULL,
            timestamp datetime NOT NULL,
            PRIMARY KEY  (id),
            KEY ip_timestamp (ip_address, timestamp)
        ) $charset_collate;";

        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }

    private function init() {
        add_action('init', array($this, 'waf_check'), 1);
        add_action('admin_init', array($this, 'schedule_cleanup'));
    }

    public function waf_check() {
        // CRITICAL: Skip all checks for logged-in users and admins - FIRST CHECK
        if (self::$is_logged_in || self::$current_user_can_manage) {
            return;
        }
        
        // Allow WordPress core functionality
        if ($this->is_wordpress_core_request()) {
            return;
        }

        $ip = $this->get_client_ip();
        
        if ($this->is_ip_blocked($ip)) {
            $this->block_request('IP Blocked');
        }

        if ($this->is_rate_limited($ip)) {
            $this->log_violation($ip, 'Rate Limit Exceeded');
            $this->block_request('Rate Limit Exceeded');
        }

        $this->check_attack_patterns($ip);
    }

    private function is_wordpress_core_request() {
        // Allow WordPress admin actions
        if (is_admin() && current_user_can('edit_posts')) {
            return true;
        }

        // Allow post publishing and autosaves
        if (current_user_can('publish_posts') && 
            (isset($_POST['post_type']) || 
             isset($_POST['action']) || 
             strpos($_SERVER['REQUEST_URI'], 'autosave') !== false)) {
            return true;
        }

        // Allow AJAX actions
        if (wp_doing_ajax() && isset($_POST['action'])) {
            $allowed_actions = array(
                'heartbeat',
                'autosave',
                'save-post',
                'inline-save'
            );
            return in_array($_POST['action'], $allowed_actions);
        }
        
        // Allow WooCommerce AJAX requests
        if (strpos($_SERVER['REQUEST_URI'], 'wc-ajax=') !== false) {
            return true;
        }

        return false;
    }

    private function is_rate_limited($ip) {
        // Skip rate limiting for authenticated users
        if (self::$is_logged_in) {
            return false;
        }
        
        $transient_key = 'waf_rate_limit_' . md5($ip);
        $requests = get_transient($transient_key);
        
        if ($requests === false) {
            set_transient($transient_key, 1, 60);
            return false;
        }
        
        if ($requests >= $this->request_limit) {
            return true;
        }
        
        set_transient($transient_key, $requests + 1, 60);
        return false;
    }

    private function check_attack_patterns($ip) {
        // Skip for WordPress core requests
        if ($this->is_wordpress_core_request()) {
            return;
        }

        if ($this->check_patterns($this->patterns_cache['sql'])) {
            $this->log_violation($ip, 'SQL Injection Attempt');
            $this->block_request('Invalid Request');
        }

        if ($this->check_patterns($this->patterns_cache['xss'])) {
            $this->log_violation($ip, 'XSS Attempt');
            $this->block_request('Invalid Request');
        }

        if ($this->check_patterns($this->patterns_cache['file'])) {
            $this->log_violation($ip, 'File Inclusion Attempt');
            $this->block_request('Invalid Request');
        }
    }

    private function check_patterns($patterns) {
        if ($this->input_cache === null) {
            $this->input_cache = array(
                $_SERVER['REQUEST_URI'],
                file_get_contents('php://input'),
                implode(' ', $_GET),
                implode(' ', $_POST),
                implode(' ', $_COOKIE)
            );
        }
        
        $input_string = implode(' ', $this->input_cache);
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input_string)) {
                return true;
            }
        }
        return false;
    }

    private function log_violation($ip, $type) {
        global $wpdb;
        
        $this->ensure_table_exists();
        
        try {
            $wpdb->insert(
                $this->table_name,
                array(
                    'ip_address' => $ip,
                    'violation_type' => $type,
                    'request_uri' => $_SERVER['REQUEST_URI'],
                    'timestamp' => current_time('mysql')
                ),
                array('%s', '%s', '%s', '%s')
            );

            if ($wpdb->last_error) {
                error_log('WAF Log Error: ' . $wpdb->last_error);
                return;
            }

            $violations = $wpdb->get_var($wpdb->prepare(
                "SELECT COUNT(*) FROM {$this->table_name} 
                WHERE ip_address = %s 
                AND timestamp > DATE_SUB(NOW(), INTERVAL 24 HOUR)",
                $ip
            ));

            if ($violations >= $this->blacklist_threshold) {
                $this->blacklist_ip($ip);
            }
        } catch (Exception $e) {
            error_log('WAF Exception: ' . $e->getMessage());
        }
    }

    private function blacklist_ip($ip) {
        if (!in_array($ip, $this->blocked_ips_cache)) {
            $this->blocked_ips_cache[] = $ip;
            update_option('waf_blocked_ips', $this->blocked_ips_cache);
        }
    }

    public function is_ip_blocked($ip) {
        return in_array($ip, $this->blocked_ips_cache);
    }

    private function block_request($reason) {
        status_header(403);
        die('Access Denied: ' . $reason);
    }

    private function get_client_ip() {
        $ip = '';
        
        // Check for proxy addresses
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else if (!empty($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        
        // Validate IP address
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
        
        return '0.0.0.0';
    }

    public function schedule_cleanup() {
        if (!wp_next_scheduled('waf_cleanup_logs')) {
            wp_schedule_event(time(), 'daily', 'waf_cleanup_logs');
        }
    }

    public function cleanup_logs() {
        global $wpdb;
        $wpdb->query(
            "DELETE FROM {$this->table_name} WHERE timestamp < DATE_SUB(NOW(), INTERVAL 30 DAY)"
        );
    }
}