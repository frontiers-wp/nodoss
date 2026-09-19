<?php
/**
 * NoDoss Security
 * Advanced engine to manage isolation, content protection, transport security, and Heartbeat performance filters with Eventbrite checkout safety.
 * Author:      Edwin Bekedam
 * License:     GPL2
 * Text Domain: nodoss
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

/**
 *  Register Plugin Settings & Modular Control Options
 */
function nodoss_security_register_settings() {
    // --- Security Header Settings (Explicitly Sanitize Switches as Keys/Binary Strings) ---
    register_setting( 'nodoss_settings_group', 'nodoss_security_enable_headers', array(
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_key',
        'default'           => '0',
    ));
    register_setting( 'nodoss_settings_group', 'nodoss_security_sub_isolation', array(
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_key',
        'default'           => '0',
    ));
    register_setting( 'nodoss_settings_group', 'nodoss_security_sub_privacy', array(
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_key',
        'default'           => '0',
    ));
    register_setting( 'nodoss_settings_group', 'nodoss_security_sub_hsts', array(
        'type'              => 'string',
        'sanitize_callback' => 'sanitize_key',
        'default'           => '0',
    ));

    // --- Performance & API Settings (Explicitly Sanitize Interval Int) ---
    register_setting( 'nodoss_settings_group', 'nodoss_security_aj_heartbeat_interval', array(
        'type'              => 'integer',
        'sanitize_callback' => 'absint',
        'default'           => 360,
    ));

    add_settings_section(
        'nodoss_main_section',
        'Security Headers Configuration',
        '__return_false',
        'nodoss-settings'
    );

    add_settings_section(
        'nodoss_perf_section',
        'Performance & API Controls',
        '__return_false',
        'nodoss-settings'
    );

    // --- Section 1 Fields: Security ---
    add_settings_field(
        'nodoss_enable_headers_field',
        'Global Master Switch',
        'nodoss_master_toggle_html',
        'nodoss-settings',
        'nodoss_main_section'
    );

    add_settings_field(
        'nodoss_sub_isolation_field',
        'Origin & Isolation Rules',
        'nodoss_isolation_toggle_html',
        'nodoss-settings',
        'nodoss_main_section'
    );

    add_settings_field(
        'nodoss_sub_privacy_field',
        'Content & Privacy Filters',
        'nodoss_privacy_toggle_html',
        'nodoss-settings',
        'nodoss_main_section'
    );

    add_settings_field(
        'nodoss_sub_hsts_field',
        'Strict Transport Security (HSTS)',
        'nodoss_hsts_toggle_html',
        'nodoss-settings',
        'nodoss_main_section'
    );

    // --- Section 2 Fields: Performance ---
    add_settings_field(
        'nodoss_aj_heartbeat_interval_field',
        'Heartbeat Interval',
        'nodoss_heartbeat_input_html',
        'nodoss-settings',
        'nodoss_perf_section'
    );
}
add_action( 'admin_init', 'nodoss_security_register_settings' );


/**
 * Add Settings Page to WordPress Menu
 */
function nodoss_security_add_admin_menu() {
    add_options_page(
        'NoDoss Security Settings',
        'NoDoss Security',
        'manage_options',
        'nodoss-settings',
        'nodoss_security_options_page_html'
    );
}
add_action( 'admin_menu', 'nodoss_security_add_admin_menu' );

/**
 * Render Dashboard Toggle & Input Elements
 */
function nodoss_security_render_toggle_element( $option_name, $description, $is_master = false ) {
    $value = get_option( $option_name, '0' );
    $class = $is_master ? 'nodoss-switch nodoss-master-switch' : 'nodoss-switch';
    ?>
    <label class="<?php echo esc_attr( $class ); ?>">
        <input type="checkbox" name="<?php echo esc_attr( $option_name ); ?>" value="1" <?php checked( $value, '1' ); ?>>
        <span class="nodoss-slider"></span>
    </label>
    <span class="nodoss-desc"><?php echo esc_html( $description ); ?></span>
    <?php
}

function nodoss_master_toggle_html() {
    nodoss_security_render_toggle_element( 'nodoss_security_enable_headers', 'Completely turn on/off the entire security injection engine.', true );
}

function nodoss_isolation_toggle_html() {
    nodoss_security_render_toggle_element( 'nodoss_security_sub_isolation', 'Enforces Origin-Agent-Cluster, COOP, and CORP configured to safeguard third-party script integrations.' );
}

function nodoss_privacy_toggle_html() {
    nodoss_security_render_toggle_element( 'nodoss_security_sub_privacy', 'Enforces CSP upgrades, secure Safari Referrer metrics, and X-Content-Type-Options.' );
}

function nodoss_hsts_toggle_html() {
    nodoss_security_render_toggle_element( 'nodoss_security_sub_hsts', 'Enforces max-age=63072000 HSTS protection with subdomains and preload parameters.' );
}

function nodoss_heartbeat_input_html() {
    $interval = get_option( 'nodoss_security_aj_heartbeat_interval', 360 );
    ?>
    <input type="number" name="nodoss_security_aj_heartbeat_interval" value="<?php echo esc_attr( absint( $interval ) ); ?>" min="15" max="360" class="small-text nodoss-num-input" /> 
    <span class="nodoss-desc">seconds. Optimized intervals reduce server CPU overhead from admin AJAX polling loops (Range: 15 to 360s).</span>
    <?php
}

/**
 * 4. Render Main Admin Setting Page with Layout Styles
 */
function nodoss_security_options_page_html() {
    if ( ! current_user_can( 'manage_options' ) ) {
        return;
    }

    $master_on   = ( get_option( 'nodoss_security_enable_headers', '0' ) === '1' );
    $system_live = false;

    if ( $master_on ) {
        $response = wp_remote_head( home_url( '/' ), array( 'sslverify' => false, 'timeout' => 3 ) );
        if ( ! is_wp_error( $response ) ) {
            $headers = wp_remote_retrieve_headers( $response );
            if ( isset( $headers['referrer-policy'] ) || isset( $headers['x-content-type-options'] ) || isset( $headers['origin-agent-cluster'] ) ) {
                $system_live = true;
            }
        }
    }
    ?>
    <div class="wrap">
        <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
        <hr class="wp-header-end">

        <style>
            /* Base Switch Architecture */
            .nodoss-switch { position: relative; display: inline-block; width: 52px; height: 28px; vertical-align: middle; }
            .nodoss-switch input { opacity: 0; width: 0; height: 0; }
            
            /* High-Contrast Inactive State */
            .nodoss-slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #8c8c8c; transition: .25s; border-radius: 28px; box-shadow: inset 0 1px 3px rgba(0,0,0,0.2); }
            .nodoss-slider:before { position: absolute; content: ""; height: 20px; width: 20px; left: 4px; bottom: 4px; background-color: #ffffff; transition: .25s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.3); }
            
            /* Vibrant Sub-Header Toggle (Electric Blue) */
            input:checked + .nodoss-slider { background-color: #0066cc; }
            input:checked + .nodoss-slider:before { transform: translateX(24px); }
            
            /* High-Visibility Master Toggle (Emerald Green) */
            .nodoss-master-switch input:checked + .nodoss-slider { background-color: #00a32a; }
            
            /* Inputs and Elements */
            .nodoss-num-input { padding: 4px 8px; font-size: 14px; border: 1px solid #8c8c8c; border-radius: 4px; line-height: 1.5; height: 28px; width: 70px !important; text-align: center; font-weight: 600; vertical-align: middle; }
            .nodoss-desc { display: inline-block; margin-left: 14px; vertical-align: middle; color: #1d2327; font-weight: 500; font-size: 13px; }
            .form-table th { width: 240px; font-weight: 600; color: #1d2327; padding: 20px 10px 20px 0; }
            .form-table td { padding: 15px 10px; }
            
            /* Titles & Sections */
            .wp-core-ui .wrap h2 { font-size: 1.3em; margin: 1.5em 0 0.5em; border-bottom: 1px solid #ccd0d4; padding-bottom: 8px; color: #1d2327; }

            /* Layout Containers */
            .nodoss-status-card { background: #fff; padding: 15px 20px; margin: 20px 0 10px; border-left: 4px solid #ccd0d4; border-radius: 4px; max-width: 800px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); display: flex; align-items: center; }
            .nodoss-status-card.active { border-left-color: #00a32a; }
            .nodoss-status-card.inactive { border-left-color: #d63638; }
            .nodoss-badge { display: inline-block; padding: 5px 12px; font-weight: bold; border-radius: 12px; font-size: 11px; text-transform: uppercase; margin-right: 15px; color: #fff; }
            .nodoss-badge.active { background: #00a32a; }
            .nodoss-badge.inactive { background: #d63638; }
            .nodoss-notice-box { margin-top: 15px; max-width: 800px; background: #fff8e5; border-left: 4px solid #dba617; padding: 12px 18px; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); font-size: 13px; color: #3c434a; }
        </style>

        <div class="nodoss-status-card <?php echo $system_live ? 'active' : 'inactive'; ?>">
            <?php if ( $system_live ) : ?>
                <span class="nodoss-badge active">Active</span>
                <div><strong>NoDoss engine is operational.</strong> Security, transport isolation, and performance rules are filtering traffic loops safely.</div>
            <?php else : ?>
                <span class="nodoss-badge inactive">Inactive</span>
                <div><strong>Headers are offline.</strong> Toggle the switches below and save options to run security filters.</div>
            <?php endif; ?>
        </div>

        <div class="nodoss-notice-box">
            ℹ️ <strong>Checkout Compatibility Engaged:</strong> Privacy and Isolation rules are calibrated explicitly to allow cross-origin script calls for <strong>Eventbrite Embedded Checkouts</strong> and Safari cookie validation tokens.
        </div>
        
        <form action="options.php" method="post" style="background: #fff; padding: 10px 25px 25px; border: 1px solid #ccd0d4; border-radius: 4px; max-width: 800px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); margin-top: 15px;">
            <?php
            settings_fields( 'nodoss_settings_group' );
            do_settings_sections( 'nodoss-settings' );
            submit_button( 'Save Security Options' );
            ?>
        </form>
    </div>
    <?php
}

/**
 * Inject Security Headers with intentional Checkout Compatibility Filters
 */
function nodoss_apply_security_headers() {
    if ( headers_sent() || get_option( 'nodoss_security_enable_headers', '0' ) !== '1' ) {
        return;
    }

    // --- Sub-Header Category 1: Origin & Isolation Controls ---
    if ( get_option( 'nodoss_security_sub_isolation', '0' ) === '1' ) {
        header( 'Origin-Agent-Cluster: ?1' );
        header( 'Cross-Origin-Opener-Policy: same-origin-allow-popups' );
        header( 'Cross-Origin-Resource-Policy: cross-origin' );  
    }

    // --- Sub-Header Category 2: Content Safeguards & Privacy Rules ---
    if ( get_option( 'nodoss_security_sub_privacy', '0' ) === '1' ) {
        header( 'Content-Security-Policy: upgrade-insecure-requests' );
        header( 'Referrer-Policy: strict-origin-when-cross-origin' );
        header( 'X-Content-Type-Options: nosniff' );
        header( 'X-Permitted-Cross-Domain-Policies: master-only' );
    }

    // --- Sub-Header Category 3: Strict Transport Security (HSTS) ---
    if ( get_option( 'nodoss_security_sub_hsts', '0' ) === '1' ) {
        header( 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' );
    }
}
add_action( 'template_redirect', 'nodoss_apply_security_headers' );

/**
 * Apply the saved setting to the WordPress Heartbeat API
 */
add_filter( 'heartbeat_settings', function ( array $settings ): array {
    $interval = get_option( 'nodoss_security_aj_heartbeat_interval', 360 );
    
    // Validate setting is inside legal WordPress boundary constraints (15 to 360 seconds).
    $settings['interval'] = max( 15, min( 360, absint( $interval ) ) );
    
    return $settings;
} );

