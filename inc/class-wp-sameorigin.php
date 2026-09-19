<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
/**
 * NoDoss Same-Origin Frame Protection
 *
 * Prevents clickjacking and iframe embedding from different origins
 */
class NoDossSameOriginFrame
{
    /**
     * Initialize the class
     */
    public function __construct()
    {
        $this->setup_hooks();
    }

    /**
     * Setup WordPress hooks
     */
    private function setup_hooks()
    {
        // Send X-Frame-Options header
        add_action('template_redirect', [$this, 'send_frame_options_header']);

        // nodoss_blank_target_vulnerability
        add_action('wp_enqueue_scripts', [$this, 'blank_target_vulnerability'], 10);
    }

    /**
     * Send X-Frame-Options header to prevent clickjacking
     */
    public function send_frame_options_header()
    {
        header('X-Frame-Options: SAMEORIGIN');
        header("Content-Security-Policy: frame-ancestors 'self';");
    }
    
    /**
     * Register and enqueue the prevent iframe embed script
     */
    public function blank_target_vulnerability()
    {
        // Register the script with dependencies and set to load in the footer
        wp_register_script(
            'blank-target-vulnerability',
            plugins_url('/assets/js/blank.target.vulnerability.js', __FILE__),
            array(),
            '1.1',
            true
        );

        // Enqueue the script
        wp_enqueue_script('blank-target-vulnerability');
    }

}

// Initialize the class
new NoDossSameOriginFrame();
