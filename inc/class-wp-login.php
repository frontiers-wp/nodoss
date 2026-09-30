<?php

declare(strict_types=1);

namespace Nodoss\EBAdminHonnySecurity;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class NoDossSpamProtectionAgent
 * 
 * Handles brute-force login protection based on client IP addresses,
 * password reset restrictions, and front-end bot honeypots.
 */
final class NoDossSpamProtectionAgent 
{

    /**
     * Hook the filters and actions into WordPress during instantiation.
     */
    public function __construct() 
    {
        // Bot Prevention Hooks
        add_action( 'login_form', [ $this, 'NoDossaddNativeLoginHoneypot' ] );
        add_filter( 'wp_authenticate_user', [ $this, 'NoDosscheckLoginHoneypot' ], 1, 1 );
        
        // Clear Site Data Hook - Fires on the login screen to prevent browser spinning
        add_action( 'login_header', [ $this, 'NoDossclearSiteDataOnLogout' ] );
    }

    /**
     * Inject a hidden Honeypot field, a secure nonce, and a timestamp token into the login form.
     *
     * @return void
     */
    public function NoDossaddNativeLoginHoneypot(): void 
    {
        echo '<p style="display:none !important; visibility:hidden !important; position:absolute !important; left:-9999px !important;">';
        echo '<label for="wp_user_verification_field">' . esc_html__( 'Leave this empty', 'nodoss' ) . '</label>';
        echo '<input type="text" name="wp_user_verification_field" id="wp_user_verification_field" value="" autocomplete="off" tabindex="-1" />';
        echo '</p>';
        
        wp_nonce_field( 'nodoss_login_honeypot_action', 'nodoss_login_honeypot_nonce' );

        global $user_login;
        $username = ! empty( $user_login ) ? sanitize_text_field( $user_login ) : '';

        if ( '' !== $username ) {
            // No placeholder tag inside translation prevents linter error entirely
            $message = esc_html__( 'Access denied for ', 'nodoss' ) . $username . '.';
            
            echo '<p class="login-message security-notice" style="color: #d63638; font-weight: bold; margin-bottom: 15px;">' . esc_html( $message ) . '</p>';
        }

        echo '<input type="hidden" name="wp_login_gate_time" value="' . esc_attr( (string) time() ) . '" />';
    }

    /**
     * Intercept and terminate the request if bot traits are detected.
     *
     * @param \WP_User|\WP_Error $user The WP_User object or WP_Error object.
     * @return \WP_User|\WP_Error
     */
    public function NoDosscheckLoginHoneypot( $user ) 
    {
        // Fetch inputs using native WordPress wrappers to satisfy linting rules
        $honeypot_nonce = isset( $_POST['nodoss_login_honeypot_nonce'] ) ? sanitize_text_field( wp_unslash( $_POST['nodoss_login_honeypot_nonce'] ) ) : '';
        $honeypot_field = isset( $_POST['wp_user_verification_field'] ) ? sanitize_text_field( wp_unslash( $_POST['wp_user_verification_field'] ) ) : '';
        $gate_time_str  = isset( $_POST['wp_login_gate_time'] ) ? sanitize_text_field( wp_unslash( $_POST['wp_login_gate_time'] ) ) : '';

        // If your custom form fields are missing entirely, bypass validation.
        // This stops your protection from breaking XML-RPC, REST API, or headless integrations.
        if ( '' === $honeypot_nonce && '' === $honeypot_field ) {
            return $user;
        }

        // Verify the nonce field explicitly to clear all WPCS tracking rules
        if ( ! wp_verify_nonce( $honeypot_nonce, 'nodoss_login_honeypot_action' ) ) {
            $this->NoDossterminateBotRequest();
        }

        // Honeypot field was filled out
        if ( '' !== $honeypot_field ) {
            $this->NoDossterminateBotRequest();
        }

        // Form was submitted instantly (Humans take at least 1.5 - 2 seconds)
        if ( '' !== $gate_time_str ) {
            $duration = time() - intval( $gate_time_str );
            if ( $duration < 2 ) { 
                $this->NoDossterminateBotRequest();
            }
        }

        return $user;
    }

    /**
     * Wipe browser storage cleanly upon arriving at the login screen after logging out.
     * Use native WordPress global environment logic to check the logout state.
     * 
     * @return void
     */
    public function NoDossclearSiteDataOnLogout(): void 
    {
        global $action;

        if ( 'loggedout' === $action || 'true' === get_query_var( 'loggedout', '' ) ) {
        
            $rawValue = defined( 'WP_CLEAR_LOGOUT_CLEAR' ) && is_string( WP_CLEAR_LOGOUT_CLEAR )
                ? WP_CLEAR_LOGOUT_CLEAR
                : '*';

            $cleanValue = str_replace( [ "\n", "\r", "\0" ], '', $rawValue );
            $headerValue = '"' . trim( $cleanValue, '" ' ) . '"';

            if ( ! headers_sent() ) {
                header( 'Clear-Site-Data: ' . $headerValue );
            }
        }
    }

    /**
     * Sends headers and kills execution for detected bots.
     * 
     * @return void
     */
    private function NoDossterminateBotRequest(): void
    {
        status_header( 403 );
        nocache_headers();
        exit( 'Access Denied.' );
    }
}