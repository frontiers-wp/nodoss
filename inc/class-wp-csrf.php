<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly

class WPFtNoDossCsrf {

    /**
     * Initialize the class and set up hooks
     */
    public function __construct() {
        // Remove URL field from comment form
        add_filter('comment_form_field_url', '__return_false');

        // Set up comment form modifications
        $this->setup_comment_form_modifications();

        // Add CSRF protection
        add_action('comment_form_after_fields', [$this, 'nodoss_add_comment_form_csrf']);
        add_filter('preprocess_comment', [$this, 'nodoss_verify_comment_csrf']);
    }

    /**
     * Set up comment form modifications
     */
    private function setup_comment_form_modifications() {
        $comment_form_modifications = [
            // Remove URL field using WordPress filter
            'comment_form_field_url' => '__return_false',

            // Custom filter to remove website field
            'comment_form_default_fields' => function(array $fields): array {
                if (isset($fields['url'])) {
                    unset($fields['url']);
                }
                return $fields;
            }
        ];

        foreach ($comment_form_modifications as $filter => $callback) {
            add_filter($filter, $callback);
        }
    }

    /**
     * Generate and add CSRF tokens to the comment form
     */
    public function nodoss_add_comment_form_csrf() {
        $wp_nonce = wp_create_nonce('comment_form_csrf');
        $random_bytes = bin2hex(random_bytes(16));
        $build_id = 'comment-form-csrf-' . $random_bytes;

        $key = defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : '';
        $data = $build_id . $wp_nonce;
        $signature = hash_hmac('sha256', $data, $key);
        $csrf_token = $signature;

        echo sprintf(
            '<input type="hidden" name="build_id" value="%s">',
            esc_attr($build_id)
        );
        echo sprintf(
            '<input type="hidden" name="wp_nonce" value="%s">',
            esc_attr($wp_nonce)
        );
        echo sprintf(
            '<input type="hidden" name="csrf_token" value="%s">',
            esc_attr($csrf_token)
        );
    }

    /**
     * Validates the CSRF tokens for comment submission.
     *
     * @param array $form_data The form data containing CSRF tokens.
     * @return bool True if the tokens are valid, false otherwise.
     */
    public function nodoss_verify_comment_csrf(array $form_data) {
        // Skip check for background API requests (like XML-RPC or REST API)
        if (defined('XMLRPC_REQUEST') || defined('REST_REQUEST')) {
            return $commentdata;
        }

        // Define required fields as constant for reusability
        $required_fields = ['build_id', 'wp_nonce', 'csrf_token'];

        // Check if the required tokens are present
        if (!isset($form_data['wp_nonce']) || !isset($form_data['csrf_token'])) {
            return false;
        }

        // Verify the WordPress nonce
        if (!wp_verify_nonce($form_data['wp_nonce'], 'comment_nonce')) {
            return false;
        }

        // Verify the custom CSRF token (assuming it's stored in the session)
        if (!isset($_SESSION['csrf_token']) || $_SESSION['csrf_token'] !== $form_data['csrf_token']) {
            return false;
        }

        return true;
    }
}

// Initialize the class
new WPFtNoDossCsrf();