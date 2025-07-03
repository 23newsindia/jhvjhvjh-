<?php
// includes/class-bot-blocker.php

if (!defined('ABSPATH')) {
    exit;
}

class BotBlocker {
    private $table_name;
    private $options_cache = array();
    
    public function __construct() {
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'security_blocked_bots';
        
        // Only initialize if bot blocking is enabled
        if ($this->get_option('security_enable_bot_blocking', true)) {
            $this->init();
        }
    }
    
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }
    
    public function init() {
        add_action('init', array($this, 'check_bot_request'), 1);
        add_action('wp_ajax_bot_blocker_stats', array($this, 'get_bot_stats'));
        add_action('wp_ajax_bot_blocker_unblock', array($this, 'unblock_bot'));
        
        // Schedule cleanup
        if (!wp_next_scheduled('bot_blocker_cleanup')) {
            wp_schedule_event(time(), 'daily', 'bot_blocker_cleanup');
        }
        add_action('bot_blocker_cleanup', array($this, 'cleanup_old_logs'));
    }
    
    public function create_table() {
        global $wpdb;
        
        $charset_collate = $wpdb->get_charset_collate();
        
        $sql = "CREATE TABLE IF NOT EXISTS {$this->table_name} (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            user_agent text NOT NULL,
            request_uri text NOT NULL,
            blocked_reason varchar(100) NOT NULL,
            hits int(11) DEFAULT 1,
            first_seen datetime NOT NULL,
            last_seen datetime NOT NULL,
            is_blocked tinyint(1) DEFAULT 1,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY is_blocked (is_blocked),
            KEY last_seen (last_seen)
        ) $charset_collate;";
        
        require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
        dbDelta($sql);
    }
    
    public function check_bot_request() {
        // Skip for admin users
        if (is_admin() && current_user_can('manage_options')) {
            return;
        }
        
        // Skip for logged-in users if option is set
        if ($this->get_option('security_bot_skip_logged_users', true) && is_user_logged_in()) {
            return;
        }
        
        $ip = $this->get_client_ip();
        $user_agent = $this->get_user_agent();
        $request_uri = $_SERVER['REQUEST_URI'];
        
        // Check if IP is already blocked
        if ($this->is_ip_blocked($ip)) {
            $this->update_bot_hit($ip);
            $this->block_request('IP Blocked - Bot Activity Detected');
        }
        
        // Check for bot patterns
        $bot_reason = $this->detect_bot_patterns($user_agent, $request_uri);
        if ($bot_reason) {
            $this->log_bot_activity($ip, $user_agent, $request_uri, $bot_reason);
            
            // Check if this IP should be blocked based on hit threshold
            if ($this->should_block_ip($ip)) {
                $this->block_ip($ip);
                $this->block_request('Bot Activity Detected: ' . $bot_reason);
            }
        }
    }
    
    private function detect_bot_patterns($user_agent, $request_uri) {
        // Malicious bot patterns
        $malicious_patterns = array(
            'sqlmap',
            'nikto',
            'nessus',
            'openvas',
            'nmap',
            'masscan',
            'zgrab',
            'shodan',
            'censys',
            'python-requests',
            'curl/',
            'wget/',
            'libwww-perl',
            'scrapy',
            'mechanize',
            'beautifulsoup'
        );
        
        // Check user agent for malicious patterns
        foreach ($malicious_patterns as $pattern) {
            if (stripos($user_agent, $pattern) !== false) {
                return 'Malicious Bot Pattern: ' . $pattern;
            }
        }
        
        // Check for suspicious request patterns
        $suspicious_uri_patterns = array(
            '/wp-config',
            '/wp-admin/install',
            '/.env',
            '/phpinfo',
            '/phpmyadmin',
            '/admin/config',
            '/xmlrpc.php',
            '/.git/',
            '/backup',
            '/sql',
            '/database'
        );
        
        foreach ($suspicious_uri_patterns as $pattern) {
            if (stripos($request_uri, $pattern) !== false) {
                return 'Suspicious URI Pattern: ' . $pattern;
            }
        }
        
        // Check for rapid requests (basic rate limiting)
        if ($this->is_rapid_requests($this->get_client_ip())) {
            return 'Rapid Requests Detected';
        }
        
        return false;
    }
    
    private function is_rapid_requests($ip) {
        $transient_key = 'bot_requests_' . md5($ip);
        $requests = get_transient($transient_key);
        
        if ($requests === false) {
            set_transient($transient_key, 1, 60); // 1 minute window
            return false;
        }
        
        $max_requests = $this->get_option('security_bot_max_requests_per_minute', 30);
        
        if ($requests >= $max_requests) {
            return true;
        }
        
        set_transient($transient_key, $requests + 1, 60);
        return false;
    }
    
    private function log_bot_activity($ip, $user_agent, $request_uri, $reason) {
        global $wpdb;
        
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
                    'blocked_reason' => $reason,
                    'hits' => 1,
                    'first_seen' => current_time('mysql'),
                    'last_seen' => current_time('mysql'),
                    'is_blocked' => 0
                ),
                array('%s', '%s', '%s', '%s', '%d', '%s', '%s', '%d')
            );
        }
    }
    
    private function should_block_ip($ip) {
        global $wpdb;
        
        $threshold = $this->get_option('security_bot_block_threshold', 5);
        
        $hits = $wpdb->get_var($wpdb->prepare(
            "SELECT hits FROM {$this->table_name} WHERE ip_address = %s",
            $ip
        ));
        
        return $hits >= $threshold;
    }
    
    private function block_ip($ip) {
        global $wpdb;
        
        $wpdb->update(
            $this->table_name,
            array('is_blocked' => 1),
            array('ip_address' => $ip),
            array('%d'),
            array('%s')
        );
    }
    
    private function is_ip_blocked($ip) {
        global $wpdb;
        
        $blocked = $wpdb->get_var($wpdb->prepare(
            "SELECT is_blocked FROM {$this->table_name} WHERE ip_address = %s AND is_blocked = 1",
            $ip
        ));
        
        return (bool) $blocked;
    }
    
    private function update_bot_hit($ip) {
        global $wpdb;
        
        $wpdb->query($wpdb->prepare(
            "UPDATE {$this->table_name} SET hits = hits + 1, last_seen = %s WHERE ip_address = %s",
            current_time('mysql'),
            $ip
        ));
    }
    
    private function block_request($reason) {
        status_header(403);
        nocache_headers();
        header('HTTP/1.1 403 Forbidden');
        header('Status: 403 Forbidden');
        header('Content-Type: text/html; charset=utf-8');
        
        $custom_message = $this->get_option('security_bot_block_message', 'Access Denied: Automated requests not allowed.');
        
        echo $this->get_block_page($custom_message, $reason);
        exit;
    }
    
    private function get_block_page($message, $reason) {
        return '<!DOCTYPE html>
<html>
<head>
    <title>403 - Access Denied</title>
    <meta name="robots" content="noindex, nofollow">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: #f5f5f5; }
        .error-container { max-width: 600px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; margin-bottom: 20px; }
        p { color: #666; line-height: 1.6; margin-bottom: 20px; }
        .reason { background: #f8f8f8; padding: 15px; border-radius: 4px; font-size: 14px; color: #555; }
        .back-link { color: #1976d2; text-decoration: none; }
        .back-link:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="error-container">
        <h1>403 - Access Denied</h1>
        <p>' . esc_html($message) . '</p>
        <div class="reason">Reason: ' . esc_html($reason) . '</div>
        <p><a href="' . home_url() . '" class="back-link">← Return to Homepage</a></p>
    </div>
</body>
</html>';
    }
    
    private function get_client_ip() {
        $ip_keys = array(
            'HTTP_CF_CONNECTING_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_FORWARDED',
            'HTTP_X_CLUSTER_CLIENT_IP',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED',
            'REMOTE_ADDR'
        );
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) && !empty($_SERVER[$key])) {
                $ips = explode(',', $_SERVER[$key]);
                $ip = trim($ips[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    private function get_user_agent() {
        return $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
    }
    
    public function get_bot_stats() {
        check_ajax_referer('security_bot_stats', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        global $wpdb;
        
        $stats = array(
            'total_blocked' => $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1"),
            'today_blocked' => $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1 AND DATE(last_seen) = CURDATE()"),
            'week_blocked' => $wpdb->get_var("SELECT COUNT(*) FROM {$this->table_name} WHERE is_blocked = 1 AND last_seen >= DATE_SUB(NOW(), INTERVAL 7 DAY)"),
            'top_blocked_ips' => $wpdb->get_results("SELECT ip_address, hits FROM {$this->table_name} WHERE is_blocked = 1 ORDER BY hits DESC LIMIT 10", ARRAY_A)
        );
        
        wp_send_json_success($stats);
    }
    
    public function unblock_bot() {
        check_ajax_referer('security_bot_unblock', 'nonce');
        
        if (!current_user_can('manage_options')) {
            wp_die('Unauthorized');
        }
        
        $ip = sanitize_text_field($_POST['ip']);
        
        global $wpdb;
        $result = $wpdb->update(
            $this->table_name,
            array('is_blocked' => 0),
            array('ip_address' => $ip),
            array('%d'),
            array('%s')
        );
        
        if ($result !== false) {
            wp_send_json_success('IP unblocked successfully');
        } else {
            wp_send_json_error('Failed to unblock IP');
        }
    }
    
    public function cleanup_old_logs() {
        global $wpdb;
        
        $days_to_keep = $this->get_option('security_bot_log_retention_days', 30);
        
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$this->table_name} WHERE last_seen < DATE_SUB(NOW(), INTERVAL %d DAY) AND is_blocked = 0",
            $days_to_keep
        ));
    }
    
    public function get_blocked_bots($limit = 20, $offset = 0) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT *, blocked_reason as block_reason FROM {$this->table_name} WHERE is_blocked = 1 ORDER BY last_seen DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ));
    }
    
    public function get_bot_activity($limit = 50, $offset = 0) {
        global $wpdb;
        
        return $wpdb->get_results($wpdb->prepare(
            "SELECT *, blocked_reason as block_reason FROM {$this->table_name} ORDER BY last_seen DESC LIMIT %d OFFSET %d",
            $limit,
            $offset
        ));
    }
}