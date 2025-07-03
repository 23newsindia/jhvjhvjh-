<?php
/*
Plugin Name: Enhanced Security Plugin
Description: Comprehensive security plugin with URL exclusion, blocking, SEO features, anti-spam protection, bot protection, and ModSecurity integration
Version: 3.0
Author: Your Name
*/

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Load components
require_once plugin_dir_path(__FILE__) . 'includes/class-waf.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-headers.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-cookie-consent.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-sanitization.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-feature-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-seo-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-bot-blackhole.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-bot-blocker.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-bot-dashboard.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-bot-settings.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-modsecurity-manager.php';
require_once plugin_dir_path(__FILE__) . 'includes/class-settings.php';

class CustomSecurityPlugin {
    private $waf;
    private $headers;
    private $cookie_consent;
    private $sanitization;
    private $feature_manager;
    private $seo_manager;
    private $bot_blackhole;
    private $bot_blocker;
    private $bot_dashboard;
    private $bot_settings;
    private $modsecurity_manager;
    private $settings;
    
    // Remove static variables from constructor - they'll be set later
    private $is_admin = null;
    private $is_logged_in = null;
    private $current_user_can_manage = null;
    
    public function __construct() {
        // Don't call WordPress functions here - they're not available yet
        
        // Hook into WordPress initialization - wait for WordPress to load
        add_action('init', array($this, 'init_user_checks'), 1);
        add_action('plugins_loaded', array($this, 'init_components'), 5);
        
        // CRITICAL: Initialize SEO Manager FIRST to catch spam URLs
        add_action('plugins_loaded', array($this, 'init_seo_manager'), 1);
        
        // Add activation hook for database setup
        register_activation_hook(__FILE__, array($this, 'activate_plugin'));
        
        // Add deactivation hook
        register_deactivation_hook(__FILE__, array($this, 'deactivate_plugin'));
        
        // Add cleanup hooks
        add_action('waf_cleanup_logs', array($this, 'cleanup_waf_logs'));
        add_action('bot_blackhole_cleanup', array($this, 'cleanup_bot_logs'));
        add_action('bot_blocker_cleanup', array($this, 'cleanup_bot_logs'));
        
        // Add admin notice for debugging
        add_action('admin_notices', array($this, 'debug_notice'));
        
        // Add database update check
        add_action('admin_init', array($this, 'check_database_updates'));
    }

    public function init_user_checks() {
        // Now WordPress functions are available - initialize user checks
        $this->is_admin = is_admin();
        $this->is_logged_in = is_user_logged_in();
        $this->current_user_can_manage = current_user_can('manage_options');
    }

    public function init_seo_manager() {
        // CRITICAL: Initialize SEO Manager FIRST with highest priority
        if (get_option('security_enable_seo_features', true)) {
            $this->seo_manager = new SEOManager();
            $this->seo_manager->init();
        }
    }

    public function debug_notice() {
        if ($this->current_user_can_manage && isset($_GET['page']) && $_GET['page'] === 'security-bot-dashboard') {
            global $wpdb;
            $table_name = $wpdb->prefix . 'security_blocked_bots';
            $table_exists = $wpdb->get_var("SHOW TABLES LIKE '$table_name'") === $table_name;
            
            if (!$table_exists) {
                echo '<div class="notice notice-warning"><p>Bot protection table does not exist. Creating table...</p></div>';
                $this->force_create_tables();
            } else {
                // Check if hits column exists
                $columns = $wpdb->get_results("SHOW COLUMNS FROM $table_name");
                $has_hits = false;
                foreach ($columns as $column) {
                    if ($column->Field === 'hits') {
                        $has_hits = true;
                        break;
                    }
                }
                
                if (!$has_hits) {
                    echo '<div class="notice notice-warning"><p>Bot protection table is missing required columns. Updating table structure...</p></div>';
                    $this->force_create_tables();
                }
            }
        }
        
        // FIXED: Add stealth mode notice
        if ($this->current_user_can_manage && isset($_GET['page']) && $_GET['page'] === 'security-settings') {
            $stealth_mode = get_option('security_bot_stealth_mode', false);
            if (!$stealth_mode) {
                echo '<div class="notice notice-warning"><p><strong>Security Alert:</strong> Your site may be flagged by security scanners as having malware due to the blackhole trap. <a href="#bot-protection-tab">Enable Stealth Mode</a> to fix this issue.</p></div>';
            }
        }
    }

    public function check_database_updates() {
        $db_version = get_option('security_plugin_db_version', '1.0');
        $current_version = '3.0';
        
        if (version_compare($db_version, $current_version, '<')) {
            $this->force_create_tables();
            update_option('security_plugin_db_version', $current_version);
        }
    }

    private function force_create_tables() {
        // Force create/update bot protection table
        $bot_blackhole = new BotBlackhole();
        $bot_blackhole->ensure_table_exists();
        
        // Force create bot blocker table if enabled
        if (get_option('security_enable_bot_blocking', true)) {
            $bot_blocker = new BotBlocker();
            if (method_exists($bot_blocker, 'create_table')) {
                $bot_blocker->create_table();
            }
        }
    }

    public function activate_plugin() {
        // Set default options on activation - ENHANCED SPAM PROTECTION
        $default_options = array(
            'security_enable_xss' => true,
            'security_enable_waf' => true,
            'security_enable_seo_features' => true,
            'security_enable_bot_protection' => true,
            'security_enable_bot_blocking' => true,
            'security_waf_request_limit' => 100,
            'security_waf_blacklist_threshold' => 5,
            // AGGRESSIVE SPAM PROTECTION - Very strict limits
            'security_max_filter_colours' => 2,  // Max 2 colors
            'security_max_filter_sizes' => 3,    // Max 3 sizes
            'security_max_filter_brands' => 1,   // Max 1 brand
            'security_max_total_filters' => 5,   // Max 5 total filters
            'security_max_query_params' => 8,    // Max 8 query params
            'security_max_query_length' => 300,  // Max 300 chars
            'security_cookie_notice_text' => 'This website uses cookies to ensure you get the best experience. By continuing to use this site, you consent to our use of cookies.',
            'security_bot_skip_logged_users' => true,
            'security_bot_max_requests_per_minute' => 30,
            'security_bot_block_threshold' => 5,
            'security_bot_block_message' => 'Access Denied - Bad Bot Detected',
            'security_bot_log_retention_days' => 30,
            'security_bot_block_status' => 403,
            'security_bot_email_alerts' => false,
            'security_bot_alert_email' => get_option('admin_email'),
            'security_protect_admin' => false,
            'security_protect_login' => false,
            'security_bot_whitelist_ips' => '',
            'security_bot_whitelist_agents' => $this->get_default_whitelist_bots(),
            'security_plugin_db_version' => '3.0',
            // FIXED: Enable stealth mode by default to prevent false malware detection
            'security_bot_stealth_mode' => true,
            // ModSecurity integration defaults
            'security_enable_modsec_integration' => true,
            'security_modsec_rule_id_start' => 20000,
            'security_modsec_block_spam_urls' => true,
            'security_modsec_block_bad_bots' => true,
            'security_modsec_custom_410_page' => true,
            'security_modsec_whitelist_search_bots' => true,
            'security_modsec_log_blocked_requests' => true,
            'security_modsec_custom_bad_bots' => 'BLEXBot,MJ12bot,SemrushBot,AhrefsBot'
        );

        foreach ($default_options as $option => $value) {
            if (get_option($option) === false) {
                update_option($option, $value);
            }
        }
        
        // Force create tables
        $this->force_create_tables();
        
        // Flush rewrite rules
        flush_rewrite_rules();
    }

    public function deactivate_plugin() {
        // Clear scheduled events
        wp_clear_scheduled_hook('waf_cleanup_logs');
        wp_clear_scheduled_hook('bot_blackhole_cleanup');
        wp_clear_scheduled_hook('bot_blocker_cleanup');
        wp_clear_scheduled_hook('bot_protection_cleanup');
        
        // Flush rewrite rules
        flush_rewrite_rules();
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

    public function init_components() {
        // Make sure user checks are initialized
        if ($this->is_admin === null) {
            $this->init_user_checks();
        }
        
        // Initialize components based on context
        if (!$this->is_admin && !$this->current_user_can_manage) {
            // Frontend components - only for non-admin users
            if (get_option('security_enable_xss', true)) {
                $this->headers = new SecurityHeaders();
                add_action('init', array($this->headers, 'add_security_headers'));
            }
            
            if (get_option('security_enable_cookie_banner', false) && !isset($_COOKIE['cookie_consent'])) {
                $this->cookie_consent = new CookieConsent();
            }
            
            if (get_option('security_enable_waf', true)) {
                $this->waf = new SecurityWAF();
            }
            
            // Initialize both bot protection systems
            if (get_option('security_enable_bot_protection', true)) {
                $this->bot_blackhole = new BotBlackhole();
            }
            
            if (get_option('security_enable_bot_blocking', true)) {
                $this->bot_blocker = new BotBlocker();
            }
        }

        // Always load these components
        $this->sanitization = new SecuritySanitization();
        $this->feature_manager = new FeatureManager();
        
        // Admin components
        if ($this->is_admin) {
            $this->settings = new SecuritySettings();
            add_action('admin_menu', array($this->settings, 'add_admin_menu'));
            add_action('admin_init', array($this->settings, 'register_settings'));
            
            // Initialize ModSecurity manager
            $this->modsecurity_manager = new ModSecurityManager();
            
            // Initialize bot dashboard - use BotBlackhole as primary
            if (get_option('security_enable_bot_protection', true)) {
                if (!$this->bot_blackhole) {
                    $this->bot_blackhole = new BotBlackhole();
                }
                $this->bot_dashboard = new BotDashboard($this->bot_blackhole);
                $this->bot_dashboard->init();
            } elseif (get_option('security_enable_bot_blocking', true)) {
                if (!$this->bot_blocker) {
                    $this->bot_blocker = new BotBlocker();
                }
                $this->bot_dashboard = new BotDashboard($this->bot_blocker);
                $this->bot_dashboard->init();
            }
        }
        
        // Initialize feature manager
        add_action('plugins_loaded', array($this->feature_manager, 'init'));
    }

    public function cleanup_waf_logs() {
        if ($this->waf) {
            $this->waf->cleanup_logs();
        }
    }
    
    public function cleanup_bot_logs() {
        if ($this->bot_blackhole) {
            $this->bot_blackhole->cleanup_logs();
        }
        if ($this->bot_blocker) {
            $this->bot_blocker->cleanup_old_logs();
        }
    }
}

// Initialize the plugin
new CustomSecurityPlugin();