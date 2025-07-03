<?php
// templates/410-page.php
// Custom 410 page for ModSecurity integration

// Prevent direct access and handle both WordPress and direct access
if (!defined('ABSPATH')) {
    // If accessed directly (from ModSecurity), try to load WordPress
    $wp_load_paths = array(
        dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php',
        dirname(dirname(dirname(dirname(dirname(__FILE__))))) . '/wp-load.php',
        $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php'
    );
    
    $wp_loaded = false;
    foreach ($wp_load_paths as $wp_load_path) {
        if (file_exists($wp_load_path)) {
            require_once($wp_load_path);
            $wp_loaded = true;
            break;
        }
    }
    
    // If WordPress couldn't be loaded, use fallback values
    if (!$wp_loaded) {
        $site_name = 'Wild Dragon';
        $home_url = 'https://wilddragon.in';
        $custom_410_content = '';
    }
} else {
    $wp_loaded = true;
}

// Set proper headers - CRITICAL for SEO
if (!headers_sent()) {
    status_header(410);
    nocache_headers();
    header('HTTP/1.1 410 Gone');
    header('Status: 410 Gone');
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    // Add additional SEO headers
    header('X-Robots-Tag: noindex, nofollow');
    header('X-Content-Security: blocked');
}

// Get custom 410 content from WordPress options (if available)
if ($wp_loaded && function_exists('get_option')) {
    $custom_410_content = get_option('security_410_page_content', '');
    $site_name = get_bloginfo('name') ?: 'Wild Dragon';
    $home_url = home_url() ?: 'https://wilddragon.in';
    $site_description = get_bloginfo('description');
} else {
    $custom_410_content = '';
    $site_name = 'Wild Dragon';
    $home_url = 'https://wilddragon.in';
    $site_description = '';
}

if (!empty($custom_410_content)) {
    echo $custom_410_content;
} else {
    // Enhanced default 410 page with Wild Dragon branding
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>410 - Content Permanently Removed | <?php echo esc_html($site_name); ?></title>
        <meta name="robots" content="noindex, nofollow">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="description" content="The requested content has been permanently removed from <?php echo esc_attr($site_name); ?>">
        <link rel="canonical" href="<?php echo esc_url($home_url); ?>">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body { 
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
                text-align: center; 
                padding: 20px; 
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                color: #333;
                margin: 0;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                line-height: 1.6;
            }
            
            .error-container { 
                max-width: 700px; 
                margin: 0 auto; 
                background: white; 
                padding: 50px 40px; 
                border-radius: 16px; 
                box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                position: relative;
                overflow: hidden;
            }
            
            .error-container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, #e74c3c, #f39c12, #e74c3c);
            }
            
            .logo-area {
                margin-bottom: 30px;
            }
            
            .site-logo {
                font-size: 2em;
                font-weight: 900;
                color: #1a1a2e;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 2px;
            }
            
            .status-code {
                font-size: 8em;
                font-weight: 900;
                color: #e74c3c;
                margin: 0 0 20px 0;
                line-height: 1;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
            }
            
            h1 { 
                color: #2c3e50; 
                font-size: 2.5em;
                margin: 0 0 30px 0;
                font-weight: 600;
            }
            
            .subtitle {
                font-size: 1.2em;
                color: #7f8c8d;
                margin-bottom: 40px;
                font-weight: 300;
            }
            
            p { 
                color: #555; 
                line-height: 1.8; 
                font-size: 1.1em;
                margin: 20px 0;
            }
            
            .back-link { 
                display: inline-block;
                color: white;
                background: linear-gradient(135deg, #1a1a2e, #16213e);
                text-decoration: none; 
                padding: 15px 30px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 1.1em;
                transition: all 0.3s ease;
                margin: 30px 10px 10px 10px;
                box-shadow: 0 4px 15px rgba(26, 26, 46, 0.3);
            }
            
            .back-link:hover { 
                background: linear-gradient(135deg, #16213e, #0f3460);
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(26, 26, 46, 0.4);
            }
            
            .explanation {
                background: #f8f9fa;
                padding: 30px;
                border-radius: 12px;
                margin: 30px 0;
                border-left: 5px solid #e74c3c;
                text-align: left;
            }
            
            .explanation h3 {
                margin: 0 0 15px 0;
                color: #e74c3c;
                font-size: 1.3em;
            }
            
            .security-notice {
                background: linear-gradient(135deg, #fff3cd, #ffeaa7);
                border: 1px solid #f39c12;
                padding: 25px;
                border-radius: 12px;
                margin: 30px 0;
                border-left: 5px solid #f39c12;
                text-align: left;
            }
            
            .security-notice h3 {
                color: #d68910;
                margin: 0 0 15px 0;
                font-size: 1.2em;
            }
            
            .actions-list {
                text-align: left;
                display: inline-block;
                margin: 20px 0;
            }
            
            .actions-list li {
                margin: 10px 0;
                padding: 5px 0;
                font-size: 1.1em;
            }
            
            .site-info {
                margin-top: 40px;
                padding-top: 30px;
                border-top: 1px solid #ecf0f1;
                color: #7f8c8d;
                font-size: 0.9em;
            }
            
            @media (max-width: 768px) {
                .error-container {
                    padding: 30px 20px;
                    margin: 20px;
                }
                
                .status-code {
                    font-size: 5em;
                }
                
                h1 {
                    font-size: 2em;
                }
                
                .back-link {
                    display: block;
                    margin: 20px 0;
                }
            }
        </style>
    </head>
    <body>
        <div class="error-container">
            <div class="logo-area">
                <div class="site-logo"><?php echo esc_html($site_name); ?></div>
            </div>
            
            <div class="status-code">410</div>
            <h1>Content Permanently Removed</h1>
            <p class="subtitle">The content you are looking for is no longer available</p>
            
            <div class="explanation">
                <h3>🔍 What does this mean?</h3>
                <p>A 410 status indicates that the content has been intentionally removed and will not be available again. This helps search engines understand that this content should be removed from their index.</p>
            </div>
            
            <div class="security-notice">
                <h3>🛡️ Security Protection Active</h3>
                <p>This request was blocked by our security system because it contained excessive filter parameters. Our system protects against:</p>
                <ul style="margin: 10px 0 0 20px;">
                    <li>Spam filter URLs with too many color/size combinations</li>
                    <li>Automated scraping attempts</li>
                    <li>Malicious bot requests</li>
                    <li>Invalid or suspicious URL patterns</li>
                </ul>
                <p style="margin-top: 15px;"><strong>Blocked URL pattern:</strong> Too many filter parameters detected</p>
            </div>
            
            <p><strong>What you can do:</strong></p>
            <ul class="actions-list">
                <li>🏠 Return to our homepage</li>
                <li>👕 Browse our men's collection</li>
                <li>👗 Browse our women's collection</li>
                <li>🔍 Use our search function</li>
                <li>📧 Contact us if you believe this is an error</li>
            </ul>
            
            <a href="<?php echo esc_url($home_url); ?>" class="back-link">← Return to Wild Dragon Homepage</a>
            
            <div class="site-info">
                <strong><?php echo esc_html($site_name); ?></strong><br>
                Premium Fashion & Lifestyle Brand
            </div>
        </div>
        
        <!-- Structured Data for SEO -->
        <script type="application/ld+json">
        {
            "@context": "https://schema.org",
            "@type": "WebPage",
            "name": "410 - Content Permanently Removed",
            "description": "The requested content has been permanently removed",
            "url": "<?php echo esc_url($_SERVER['REQUEST_URI'] ?? ''); ?>",
            "isPartOf": {
                "@type": "WebSite",
                "name": "<?php echo esc_js($site_name); ?>",
                "url": "<?php echo esc_url($home_url); ?>"
            }
        }
        </script>
    </body>
    </html>
    <?php
}

// Log the 410 response for analytics (if WordPress is loaded)
if ($wp_loaded && function_exists('get_option') && get_option('security_enable_seo_features', true)) {
    $log_entry = array(
        'url' => $_SERVER['REQUEST_URI'] ?? '',
        'reason' => 'ModSecurity 410 Block - Custom Page',
        'timestamp' => current_time('mysql'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'referer' => $_SERVER['HTTP_REFERER'] ?? '',
        'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET'
    );
    
    $spam_logs = get_option('security_spam_url_logs', array());
    $spam_logs[] = $log_entry;
    
    // Keep only last 200 entries
    if (count($spam_logs) > 200) {
        $spam_logs = array_slice($spam_logs, -200);
    }
    
    update_option('security_spam_url_logs', $spam_logs);
}

// Clean exit
exit;
?>