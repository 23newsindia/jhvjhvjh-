<?php
// includes/class-bot-dashboard.php

if (!defined('ABSPATH')) {
    exit;
}

class BotDashboard {
    private $bot_protection;
    private $table_name;
    
    public function __construct($bot_protection) {
        $this->bot_protection = $bot_protection;
        global $wpdb;
        $this->table_name = $wpdb->prefix . 'security_blocked_bots';
    }
    
    public function init() {
        add_action('admin_menu', array($this, 'add_dashboard_page'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_dashboard_scripts'));
        
        // Add AJAX handlers with proper priority
        add_action('wp_ajax_bot_blocker_stats', array($this, 'get_bot_stats'), 10);
        add_action('wp_ajax_bot_blocker_unblock', array($this, 'unblock_bot'), 10);
        add_action('wp_ajax_bot_blocker_activity', array($this, 'get_bot_activity'), 10);
        add_action('wp_ajax_bot_hostlookup', array($this, 'perform_host_lookup'), 10);
        
        // Add bulk actions handler - FIXED action name
        add_action('wp_ajax_bot_blocker_bulk_action', array($this, 'handle_bulk_action'), 10);
        
        // Debug handlers
        add_action('wp_ajax_nopriv_bot_blocker_stats', array($this, 'handle_unauthorized_request'));
        add_action('wp_ajax_nopriv_bot_blocker_unblock', array($this, 'handle_unauthorized_request'));
        add_action('wp_ajax_nopriv_bot_blocker_activity', array($this, 'handle_unauthorized_request'));
        
        // Ensure table exists
        add_action('admin_init', array($this, 'ensure_table_exists'));
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
                $wpdb->query("ALTER TABLE {$this->table_name} {$sql}");
            }
        }
        
        // Remove status column if it exists (causing conflicts)
        if (in_array('status', $existing_columns)) {
            $wpdb->query("ALTER TABLE {$this->table_name} DROP COLUMN status");
        }
        
        // Update existing records
        $wpdb->query("UPDATE {$this->table_name} SET first_seen = timestamp WHERE first_seen IS NULL");
        $wpdb->query("UPDATE {$this->table_name} SET last_seen = timestamp WHERE last_seen IS NULL");
        $wpdb->query("UPDATE {$this->table_name} SET blocked_reason = block_reason WHERE blocked_reason IS NULL");
        $wpdb->query("UPDATE {$this->table_name} SET hits = 1 WHERE hits IS NULL OR hits = 0");
        $wpdb->query("UPDATE {$this->table_name} SET is_blocked = 1 WHERE is_blocked IS NULL");
    }
    
    public function handle_unauthorized_request() {
        wp_send_json_error('Unauthorized access');
    }
    
    public function add_dashboard_page() {
        add_submenu_page(
            'security-settings',
            'Bot Protection Dashboard',
            'Bot Dashboard',
            'manage_options',
            'security-bot-dashboard',
            array($this, 'render_dashboard_page')
        );
    }
    
    public function enqueue_dashboard_scripts($hook) {
        // Only load on our dashboard page
        if ($hook !== 'security-settings_page_security-bot-dashboard') {
            return;
        }
        
        // Enqueue our dashboard script - VANILLA JS VERSION
        wp_enqueue_script(
            'bot-dashboard',
            plugin_dir_url(dirname(__FILE__)) . 'assets/bot-dashboard.js',
            array(), // No jQuery dependency
            '2.0.5', // Increment version to force reload
            true
        );
        
        // Localize script with proper data
        wp_localize_script('bot-dashboard', 'botDashboard', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('security_bot_stats'),
            'unblock_nonce' => wp_create_nonce('security_bot_unblock'),
            'bulk_nonce' => wp_create_nonce('security_bot_bulk'),
            'debug' => defined('WP_DEBUG') && WP_DEBUG
        ));
        
        // Enqueue dashboard styles
        wp_enqueue_style(
            'bot-dashboard',
            plugin_dir_url(dirname(__FILE__)) . 'assets/bot-dashboard.css',
            array(),
            '2.0.2'
        );
    }
    
    public function get_bot_stats() {
        // Verify nonce first
        if (!check_ajax_referer('security_bot_stats', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        try {
            global $wpdb;
            
            // Check if table exists
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '{$this->table_name}'") === $this->table_name;
            
            if (!$table_exists) {
                $this->ensure_table_exists();
                
                // Return default stats if table still doesn't exist
                $stats = array(
                    'total_blocked' => 0,
                    'today_blocked' => 0,
                    'week_blocked' => 0,
                    'top_blocked_ips' => array()
                );
                wp_send_json_success($stats);
                return;
            }
            
            // Get stats from database
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
            error_log('Bot Dashboard Stats Error: ' . $e->getMessage());
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }
    
    public function get_bot_activity() {
        // Verify nonce first
        if (!check_ajax_referer('security_bot_stats', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        try {
            global $wpdb;
            
            // Get parameters
            $limit = intval($_POST['limit']) ?: 10;
            $offset = intval($_POST['offset']) ?: 0;
            $sort = sanitize_text_field($_POST['sort']) ?: 'last_seen';
            $order = sanitize_text_field($_POST['order']) ?: 'desc';
            $search = sanitize_text_field($_POST['search']) ?: '';
            $status = sanitize_text_field($_POST['status']) ?: 'all';
            
            // Build WHERE clause
            $where_conditions = array();
            $where_params = array();
            
            if ($search) {
                $where_conditions[] = "(ip_address LIKE %s OR user_agent LIKE %s OR request_uri LIKE %s)";
                $search_term = '%' . $wpdb->esc_like($search) . '%';
                $where_params[] = $search_term;
                $where_params[] = $search_term;
                $where_params[] = $search_term;
            }
            
            if ($status !== 'all') {
                if ($status === 'blocked') {
                    $where_conditions[] = "is_blocked = 1";
                } elseif ($status === 'monitoring') {
                    $where_conditions[] = "is_blocked = 0";
                }
            }
            
            $where_clause = '';
            if (!empty($where_conditions)) {
                $where_clause = 'WHERE ' . implode(' AND ', $where_conditions);
            }
            
            // FIXED: Get total count of unique IPs, not total entries
            $count_query = "SELECT COUNT(DISTINCT ip_address) FROM {$this->table_name} {$where_clause}";
            if (!empty($where_params)) {
                $total_count = $wpdb->get_var($wpdb->prepare($count_query, $where_params));
            } else {
                $total_count = $wpdb->get_var($count_query);
            }
            
            // FIXED: Get consolidated activity data - group by IP to avoid duplicates
            $activity_query = "SELECT ip_address, 
                                     MAX(user_agent) as user_agent, 
                                     GROUP_CONCAT(DISTINCT request_uri ORDER BY timestamp DESC SEPARATOR '|') as request_uri, 
                                     MAX(referrer) as referrer, 
                                     MAX(timestamp) as timestamp, 
                                     MIN(first_seen) as first_seen, 
                                     MAX(last_seen) as last_seen, 
                                     MAX(block_reason) as block_reason, 
                                     MAX(blocked_reason) as blocked_reason, 
                                     SUM(hits) as hits, 
                                     MAX(is_blocked) as is_blocked,
                                     MAX(id) as id
                              FROM {$this->table_name} {$where_clause} 
                              GROUP BY ip_address 
                              ORDER BY {$sort} {$order} 
                              LIMIT %d OFFSET %d";
            
            $query_params = array_merge($where_params, array($limit, $offset));
            
            if (!empty($where_params)) {
                $activities = $wpdb->get_results($wpdb->prepare($activity_query, $query_params));
            } else {
                $activities = $wpdb->get_results($wpdb->prepare("SELECT ip_address, 
                                                                        MAX(user_agent) as user_agent, 
                                                                        GROUP_CONCAT(DISTINCT request_uri ORDER BY timestamp DESC SEPARATOR '|') as request_uri, 
                                                                        MAX(referrer) as referrer, 
                                                                        MAX(timestamp) as timestamp, 
                                                                        MIN(first_seen) as first_seen, 
                                                                        MAX(last_seen) as last_seen, 
                                                                        MAX(block_reason) as block_reason, 
                                                                        MAX(blocked_reason) as blocked_reason, 
                                                                        SUM(hits) as hits, 
                                                                        MAX(is_blocked) as is_blocked,
                                                                        MAX(id) as id
                                                                 FROM {$this->table_name} 
                                                                 GROUP BY ip_address 
                                                                 ORDER BY {$sort} {$order} 
                                                                 LIMIT %d OFFSET %d", $limit, $offset));
            }
            
            // Generate HTML response
            $html = $this->generate_activity_html($activities, $total_count);
            
            echo $html;
            wp_die();
            
        } catch (Exception $e) {
            error_log('Bot Dashboard Activity Error: ' . $e->getMessage());
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }
    
    private function generate_activity_html($activities, $total_count) {
        ob_start();
        
        // Count data div
        echo '<div class="bot-count-data" data-count="' . $total_count . '">';
        if ($total_count > 0) {
            echo '<div class="bot-count">Showing ' . count($activities) . ' unique IPs of ' . $total_count . ' total unique IPs</div>';
        } else {
            echo '<div class="bot-noresults">No bot activity found</div>';
        }
        echo '</div>';
        
        // Activity rows
        if (!empty($activities)) {
            foreach ($activities as $activity) {
                $status_class = $activity->is_blocked ? 'blocked' : 'monitoring';
                $status_text = $activity->is_blocked ? 'Blocked' : 'Monitoring';
                
                echo '<div class="bot-row bot-status-' . $status_class . '" data-id="' . $activity->id . '">';
                
                // Column 1: IP and basic info
                echo '<div class="bot-col bot-col1">';
                echo '<div class="bot-checkbox">';
                echo '<input type="checkbox" class="bot-id" value="' . $activity->id . '">';
                echo '</div>';
                echo '<div class="bot-date">';
                echo '<strong>' . esc_html($activity->ip_address) . '</strong><br>';
                echo '<small>' . date('M j, Y @ H:i', strtotime($activity->last_seen)) . '</small>';
                echo '</div>';
                echo '</div>';
                
                // Column 2: Status and hits
                echo '<div class="bot-col bot-col2">';
                echo '<div class="bot-meta">';
                echo '<div class="bot-box">';
                echo '<span class="bot-label">Status:</span>';
                echo '<span class="status-badge ' . $status_class . '">' . $status_text . '</span>';
                echo '</div>';
                echo '<div class="bot-box">';
                echo '<span class="bot-label">Hits:</span>';
                echo '<span class="bot-value">' . ($activity->hits ?: 1) . '</span>';
                echo '</div>';
                echo '<div class="bot-box">';
                echo '<span class="bot-label">Reason:</span>';
                echo '<span class="bot-value">' . esc_html($activity->blocked_reason ?: $activity->block_reason ?: 'Unknown') . '</span>';
                echo '</div>';
                echo '</div>';
                echo '</div>';
                
                // Column 3: Actions and details
                echo '<div class="bot-col bot-col3">';
                echo '<div class="bot-actions">';
                
                if (!$activity->is_blocked) {
                    echo '<a href="#" class="bot-action bot-action-ban" data-bot-action="ban" data-id="' . $activity->id . '" data-ip="' . esc_attr($activity->ip_address) . '" title="Ban this IP"></a>';
                    echo '<a href="#" class="bot-action bot-action-warn" data-bot-action="warn" data-id="' . $activity->id . '" data-ip="' . esc_attr($activity->ip_address) . '" title="Warn this IP"></a>';
                } else {
                    echo '<a href="#" class="bot-action bot-action-restore" data-bot-action="restore" data-id="' . $activity->id . '" data-ip="' . esc_attr($activity->ip_address) . '" title="Restore this IP"></a>';
                }
                
                echo '<a href="#" class="bot-action bot-action-whitelist" data-bot-action="whitelist" data-id="' . $activity->id . '" data-ip="' . esc_attr($activity->ip_address) . '" title="Whitelist this IP"></a>';
                echo '<a href="#" class="bot-action bot-action-delete" data-bot-action="delete" data-id="' . $activity->id . '" data-ip="' . esc_attr($activity->ip_address) . '" title="Delete this entry"></a>';
                
                echo '<select class="bot-select-target">';
                echo '<option value="ip">Target IP</option>';
                echo '<option value="ua">Target User Agent</option>';
                echo '<option value="user">Target User</option>';
                echo '</select>';
                
                echo '</div>';
                
                // IMPROVED: Request details with multiple URLs
                echo '<div class="bot-request">';
                echo '<span class="bot-label">Recent URLs:</span><br>';
                
                // Handle multiple URLs separated by |
                $urls = explode('|', $activity->request_uri);
                $urls = array_unique(array_filter($urls)); // Remove duplicates and empty values
                $display_urls = array_slice($urls, 0, 3); // Show first 3 URLs
                
                if (!empty($display_urls)) {
                    foreach ($display_urls as $url) {
                        $clean_url = esc_html($url);
                        if (strlen($clean_url) > 60) {
                            $clean_url = substr($clean_url, 0, 60) . '...';
                        }
                        echo '<div class="url-entry">' . $clean_url . '</div>';
                    }
                    
                    if (count($urls) > 3) {
                        echo '<div class="url-more">+' . (count($urls) - 3) . ' more URLs</div>';
                    }
                } else {
                    echo '<div class="url-entry">No URLs recorded</div>';
                }
                
                echo '</div>';
                
                // User agent
                if (!empty($activity->user_agent)) {
                    echo '<div class="bot-user-agent">';
                    echo esc_html(substr($activity->user_agent, 0, 100)) . '...';
                    echo '</div>';
                }
                
                // Hidden detailed data
                echo '<div class="bot-data">';
                echo '<div class="bot-box">';
                echo '<span class="bot-label">First Seen:</span>';
                echo '<span class="bot-value">' . date('Y-m-d H:i:s', strtotime($activity->first_seen ?: $activity->timestamp)) . '</span>';
                echo '</div>';
                if (!empty($activity->referrer)) {
                    echo '<div class="bot-box">';
                    echo '<span class="bot-label">Referrer:</span>';
                    echo '<span class="bot-value">' . esc_html($activity->referrer) . '</span>';
                    echo '</div>';
                }
                echo '<div class="bot-box">';
                echo '<span class="bot-label">Full User Agent:</span>';
                echo '<span class="bot-value">' . esc_html($activity->user_agent) . '</span>';
                echo '</div>';
                echo '<div class="bot-box">';
                echo '<span class="bot-label">All URLs:</span>';
                echo '<div class="bot-value">';
                foreach ($urls as $url) {
                    echo '<div>' . esc_html($url) . '</div>';
                }
                echo '</div>';
                echo '</div>';
                echo '</div>';
                
                echo '</div>';
                echo '</div>';
            }
        }
        
        return ob_get_clean();
    }
    
    public function handle_bulk_action() {
        // Verify nonce
        if (!check_ajax_referer('security_bot_bulk', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        // FIXED: Use bot_action instead of action to avoid conflicts
        $bot_action = sanitize_text_field($_POST['bot_action']);
        $ip = sanitize_text_field($_POST['ip']);
        $id = intval($_POST['id']);
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            wp_send_json_error('Invalid IP address');
            return;
        }
        
        global $wpdb;
        
        try {
            switch ($bot_action) {
                case 'ban':
                    // Block the IP
                    $result = $wpdb->update(
                        $this->table_name,
                        array('is_blocked' => 1, 'blocked_reason' => 'Manually blocked'),
                        array('ip_address' => $ip),
                        array('%d', '%s'),
                        array('%s')
                    );
                    
                    if ($result !== false) {
                        // Also add to transient cache for immediate blocking
                        $blocked_transient = 'bot_blocked_' . md5($ip);
                        set_transient($blocked_transient, true, 24 * HOUR_IN_SECONDS);
                        
                        wp_send_json_success('IP banned successfully');
                    } else {
                        wp_send_json_error('Failed to ban IP');
                    }
                    break;
                    
                case 'restore':
                    // Unblock the IP
                    $result = $wpdb->update(
                        $this->table_name,
                        array('is_blocked' => 0, 'blocked_reason' => 'Manually restored'),
                        array('ip_address' => $ip),
                        array('%d', '%s'),
                        array('%s')
                    );
                    
                    if ($result !== false) {
                        // Remove from transient cache
                        $blocked_transient = 'bot_blocked_' . md5($ip);
                        delete_transient($blocked_transient);
                        
                        wp_send_json_success('IP restored successfully');
                    } else {
                        wp_send_json_error('Failed to restore IP');
                    }
                    break;
                    
                case 'whitelist':
                    // Add to whitelist
                    $current_whitelist = get_option('security_bot_whitelist_ips', '');
                    $whitelist_array = array_filter(array_map('trim', explode("\n", $current_whitelist)));
                    
                    if (!in_array($ip, $whitelist_array)) {
                        $whitelist_array[] = $ip;
                        $new_whitelist = implode("\n", $whitelist_array);
                        update_option('security_bot_whitelist_ips', $new_whitelist);
                        
                        // Also unblock the IP
                        $wpdb->update(
                            $this->table_name,
                            array('is_blocked' => 0, 'blocked_reason' => 'Whitelisted'),
                            array('ip_address' => $ip),
                            array('%d', '%s'),
                            array('%s')
                        );
                        
                        // Remove from transient cache
                        $blocked_transient = 'bot_blocked_' . md5($ip);
                        delete_transient($blocked_transient);
                        
                        wp_send_json_success('IP whitelisted successfully');
                    } else {
                        wp_send_json_error('IP already whitelisted');
                    }
                    break;
                    
                case 'delete':
                    // FIXED: Delete all entries for this IP, not just by ID
                    $result = $wpdb->delete(
                        $this->table_name,
                        array('ip_address' => $ip),
                        array('%s')
                    );
                    
                    if ($result !== false) {
                        // Remove from transient cache
                        $blocked_transient = 'bot_blocked_' . md5($ip);
                        delete_transient($blocked_transient);
                        
                        wp_send_json_success('IP entries deleted successfully');
                    } else {
                        wp_send_json_error('Failed to delete IP entries');
                    }
                    break;
                    
                default:
                    wp_send_json_error('Invalid action');
            }
            
        } catch (Exception $e) {
            error_log('Bot Dashboard Bulk Action Error: ' . $e->getMessage());
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }
    
    public function unblock_bot() {
        // Verify nonce
        if (!check_ajax_referer('security_bot_unblock', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        // Validate IP parameter
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
            
            // Update database
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
            error_log('Bot Dashboard Unblock Error: ' . $e->getMessage());
            wp_send_json_error('Database error: ' . $e->getMessage());
        }
    }
    
    public function perform_host_lookup() {
        // Verify nonce
        if (!check_ajax_referer('security_bot_stats', 'nonce', false)) {
            wp_send_json_error('Invalid nonce');
            return;
        }
        
        // Check user capabilities
        if (!current_user_can('manage_options')) {
            wp_send_json_error('Insufficient permissions');
            return;
        }
        
        $ip = sanitize_text_field($_POST['ip']);
        
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            echo 'Invalid IP';
            wp_die();
        }
        
        // Perform reverse DNS lookup
        $hostname = gethostbyaddr($ip);
        if ($hostname && $hostname !== $ip) {
            echo esc_html($hostname);
        } else {
            echo 'No hostname found';
        }
        
        wp_die();
    }
    
    public function render_dashboard_page() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        // Get data for initial display
        $blocked_bots = array();
        $recent_activity = array();
        
        try {
            global $wpdb;
            $blocked_bots = $wpdb->get_results("SELECT * FROM {$this->table_name} WHERE is_blocked = 1 ORDER BY last_seen DESC LIMIT 20");
            $recent_activity = $wpdb->get_results("SELECT * FROM {$this->table_name} ORDER BY last_seen DESC LIMIT 30");
        } catch (Exception $e) {
            error_log('Bot Dashboard Render Error: ' . $e->getMessage());
        }
        
        ?>
        <div class="wrap">
            <h1><span class="dashicons dashicons-shield-alt"></span> Bot Protection Dashboard</h1>
            
            <!-- Enhanced Stats Cards -->
            <div class="bot-dashboard-ui">
                <div class="bot-dashboard-stats">
                    <div class="bot-stat-card">
                        <h3>Total Blocked</h3>
                        <div class="stat-number" id="total-blocked">Loading...</div>
                    </div>
                    <div class="bot-stat-card">
                        <h3>Blocked Today</h3>
                        <div class="stat-number" id="today-blocked">Loading...</div>
                    </div>
                    <div class="bot-stat-card">
                        <h3>Blocked This Week</h3>
                        <div class="stat-number" id="week-blocked">Loading...</div>
                    </div>
                </div>
                
                <!-- Enhanced Controls -->
                <div class="bot-header">
                    <div class="bot-items">
                        <div class="bot-item">
                            <a href="#" class="bot-tools-link">Tools</a>
                            <span class="bot-sep">|</span>
                            <a href="#" class="bot-reload-link">Reload</a>
                            <span class="bot-sep">|</span>
                            <a href="#" class="bot-fx-link" data-fx-on="FX: ON" data-fx-off="FX: OFF">FX: ON</a>
                        </div>
                        <div class="bot-item">
                            <a href="#" class="bot-toggle-link" data-view-adv="View Advanced" data-view-bsc="View Basic">View Advanced</a>
                        </div>
                    </div>
                </div>
                
                <!-- Tools Section -->
                <div class="bot-tools">
                    <div class="bot-items">
                        <div class="bot-tools-item">
                            <input type="text" class="bot-action-search" placeholder="Search IPs, User Agents, etc.">
                            <select class="bot-select-filter">
                                <option value="all">All Fields</option>
                                <option value="ip">IP Address</option>
                                <option value="ua">User Agent</option>
                                <option value="uri">Request URI</option>
                            </select>
                        </div>
                        <div class="bot-tools-item">
                            <select class="bot-select-sort">
                                <option value="last_seen">Last Seen</option>
                                <option value="first_seen">First Seen</option>
                                <option value="hits">Hit Count</option>
                                <option value="ip_address">IP Address</option>
                            </select>
                            <select class="bot-select-order">
                                <option value="desc">Descending</option>
                                <option value="asc">Ascending</option>
                            </select>
                            <select class="bot-select-status">
                                <option value="all">All Status</option>
                                <option value="blocked">Blocked Only</option>
                                <option value="monitoring">Monitoring Only</option>
                            </select>
                        </div>
                    </div>
                </div>
                
                <!-- Pagination -->
                <div class="bot-paging">
                    <div class="bot-items">
                        <div class="bot-paging-item">
                            <button class="bot-page-prev">← Prev</button>
                            <input type="number" class="bot-page-jump" value="1" min="1">
                            <span class="bot-paging-of">of</span>
                            <span class="bot-page-total">1</span>
                            <button class="bot-page-next">Next →</button>
                        </div>
                        <div class="bot-paging-item">
                            <span>Items per page:</span>
                            <input type="number" class="bot-page-items" value="10" min="1" max="50">
                            <span class="bot-hover-info">Press Enter to apply</span>
                        </div>
                    </div>
                </div>
                
                <!-- Loading Animation -->
                <div class="bot-loading">
                    <div class="bot-loading-wrap">
                        <div class="bot-loading-message">
                            <span>Loading bot activity</span>
                            <a href="#" class="bot-reload-current">Reload</a>
                        </div>
                    </div>
                </div>
                
                <!-- Activity Response Container -->
                <div class="bot-response"></div>
                
            </div>
            
            <!-- Traditional Tables for Blocked IPs -->
            <div class="bot-dashboard-content">
                <div class="bot-dashboard-section">
                    <h2>Currently Blocked IPs</h2>
                    <div class="bot-table-container">
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th>IP Address</th>
                                    <th>Hits</th>
                                    <th>Reason</th>
                                    <th>Last Seen</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($blocked_bots)): ?>
                                    <tr>
                                        <td colspan="5">No blocked bots found.</td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($blocked_bots as $bot): ?>
                                        <tr>
                                            <td>
                                                <strong><?php echo esc_html($bot->ip_address); ?></strong>
                                                <?php if (!empty($bot->user_agent)): ?>
                                                <div class="bot-user-agent"><?php echo esc_html(substr($bot->user_agent, 0, 100)); ?>...</div>
                                                <?php endif; ?>
                                            </td>
                                            <td><?php echo esc_html($bot->hits ?? 0); ?></td>
                                            <td><?php echo esc_html($bot->block_reason ?? $bot->blocked_reason ?? 'Unknown'); ?></td>
                                            <td><?php echo esc_html(date('Y-m-d H:i:s', strtotime($bot->last_seen ?? $bot->timestamp ?? 'now'))); ?></td>
                                            <td>
                                                <button class="button unblock-bot" data-ip="<?php echo esc_attr($bot->ip_address); ?>">
                                                    Unblock
                                                </button>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <div class="bot-dashboard-section">
                    <h2>Top Blocked IPs</h2>
                    <div id="top-blocked-ips">Loading...</div>
                </div>
            </div>
        </div>
        
        <style>
        .url-entry {
            font-size: 11px;
            color: #666;
            margin: 2px 0;
            padding: 2px 4px;
            background: rgba(0,0,0,0.05);
            border-radius: 2px;
        }
        .url-more {
            font-size: 10px;
            color: #999;
            font-style: italic;
            margin-top: 4px;
        }
        .bot-request {
            margin-top: 10px;
        }
        .bot-request .bot-label {
            display: block;
            margin-bottom: 5px;
        }
        </style>
        <?php
    }
}