<?php
/**
 * Login Brute-Force Protection
 * Lightweight, brute-force login protection.
 * Author:Frontiers
 * Requires PHP:  8.5
 */
 
declare(strict_types=1);

namespace Nodoss\EBAdminSecurity;

use WP_Error;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class NoDossLoginProtectionManager
 * 
 * Handles brute-force login protection based on client IP addresses.
 */
final class NoDossLoginProtectionManager 
{
    // Class Constants explicitly typed for PHP 8.5+ architectures
    private const int MAX_LOGIN_ATTEMPTS = 3;
    private const int LOCKOUT_DURATION_SECONDS = 900; // 15 Minutes
    private const string TRANSIENT_PREFIX = 'nodoss_login_attempts_';
    private const RESTRICTED_USER_IDS = [ 3, 10 ];
   
    // Whitelisted REST API paths that bypass the IP block rules
    private const array BYPASS_REST_ROUTES = [
        '/wp-json/my-custom-plugin/v1/webhook',
        '/wp-json/my-custom-plugin/v1/public-status',
    ];

    /**
     * Bootstraps the plugin by registering WordPress hooks.
     */
    public function __construct() 
    {
        $this->registerLoginHooks();
    }

    /**
     * Initializes hooks.
     */
    private function registerLoginHooks(): void 
    {
        // EMERGENCY UNLOCK BYPASS: Check if the wp-config constant is explicitly defined as true
        if ( defined( 'NODOSS_BYPASS_LOGIN_LOCKOUT' ) && NODOSS_BYPASS_LOGIN_LOCKOUT === true ) {
            // Register an administrative warning if the emergency unlock is running active in the backend
            add_action( 'admin_notices', [ $this, 'NoDossrenderEmergencyBypassWarning' ] );
            return;
        }

        // Bypass checks if current route matches our explicit whitelist
        if ( $this->isBypassedRestRoute() ) {
            return;
        }

        // Brute Force Protection
        add_filter( 'wp_authenticate_user', [ $this, 'NoDosscheckBruteForceLockout' ], 30, 2 );
        add_action( 'wp_login_failed', [ $this, 'NoDosshandleFailedLoginAttempt' ] );
        add_filter( 'allow_password_reset', [ $this, 'NoDossRestrictPasswordReset' ], 10, 2 );
    }


    /**
     * Disables password resets for designated user IDs.
     *
     * @param bool $allow   Whether to allow password reset.
     * @param int  $userId  The ID of the user attempting the reset.
     * @return bool
     */
    public function NoDossRestrictPasswordReset( bool $allow, int $userId ): bool 
    {
        // If the current logged-in user is an administrator, bypass the restriction
        if ( current_user_can( 'manage_options' ) ) {
            return $allow;
        }

        // Otherwise, block the reset if the user ID is in the restricted list
        if ( in_array( $userId, self::RESTRICTED_USER_IDS, true ) ) {
            return false;
        }

        return $allow;
    }


    /**
     * Renders a critical administration notice when the brute force block engine is bypassed.
     */
    public function NoDossrenderEmergencyBypassWarning(): void 
    {
        // Guard access checking to ensure only privileged administrators view structural security messages
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        $allowed_html = [
            'div'    => [
                'class' => [],
            ],
            'p'      => [],
            'strong' => [],
            'code'   => [],
        ];

        /* translators: 1: Security warning title, 2: First part of the warning message text, 3: Concluding instruction text. */
        $warning_message = sprintf(
            '<div class="notice notice-error"><p><strong>%1$s:</strong> %2$s <code>define(\'NODOSS_BYPASS_LOGIN_LOCKOUT\', true);</code> %3$s</p></div>',
            esc_html__( 'NODOSS SECURITY WARNING', 'nodoss' ),
            esc_html__( 'The Login Brute-Force Protection engine is currently disabled because the emergency unlock constant', 'nodoss' ),
            esc_html__( 'is left active in your wp-config.php file. Remove this constant immediately to restore protection.', 'nodoss' )
        );

        echo wp_kses( $warning_message, $allowed_html );
    }

    /**
     * Helper to verify if the current request is an excluded REST API path.
     */
    private function isBypassedRestRoute(): bool 
    {
        // Strict WPCS compliant line-level read
        $rawUri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
        if ( $rawUri === '' ) {
            return false;
        }

        $currentUri = strtok( $rawUri, '?' );
        if ( ! is_string( $currentUri ) ) {
            return false;
        }

        return in_array( $currentUri, self::BYPASS_REST_ROUTES, true );
    }


    /**
     * Evaluates if a given IP address strictly matches the external wp-config global constant
     * or satisfies custom plugin programmatic filters.
     */
    private function isClientIpWhitelisted( string $clientIp ): bool 
    {
        // 1. Dynamic integration explicitly limited to your wp-config.php structural target
        if ( defined( 'NODOSS_IP_WHITELIST' ) ) {
            $configValue = (string) NODOSS_IP_WHITELIST;
            $whitelistedIps = array_map( 'trim', explode( ',', $configValue ) );
            
            if ( in_array( $clientIp, $whitelistedIps, true ) ) {
                return true;
            }
        }

        // Added custom filter hook allowing specific automated plugins to pass through safely
        if ( (bool) apply_filters( 'nodoss_allow_login_bypass', false, $clientIp ) === true ) {
            return true;
        }

        return false;
    }


    /**
     * Prevents login processing if the user's IP address has passed the failure threshold.
     *
     * @param mixed  $user     Object or WP_Error depending on the filter stage.
     * @param string $password The password string provided by the client hook.
     */
    public function NoDosscheckBruteForceLockout( mixed $user, string $password = '' ): mixed 
    {
        if ( is_wp_error( $user ) ) {
            return $user;
        }

        $clientIp = $this->NoDossgetClientIp();

        // Updated to use the unified dynamic whitelist checking logic
        if ( $this->isClientIpWhitelisted( $clientIp ) ) {
            return $user;
        }

        $transientName = $this->NoDossgetTransientKey( $clientIp );
        $attempts      = get_transient( $transientName );

        if ( false !== $attempts && (int) $attempts >= self::MAX_LOGIN_ATTEMPTS ) {
            $allowed_html = [
                'strong' => [],
            ];
            
            $error_message = sprintf(
                /* translators: %s: The bold text for 'ERROR' or another emphasis string. */
                __( '%s: Too many failed login attempts. This IP address is blocked for 15 minutes.', 'nodoss' ),
                '<strong>' . esc_html__( 'ERROR', 'nodoss' ) . '</strong>'
            );

            return new WP_Error(
                'blocked_ip',
                wp_kses( $error_message, $allowed_html )
            );
        }

        return $user;
    }


    /**
     * Increments or creates the failed login counter for the source IP.
     */
    public function NoDosshandleFailedLoginAttempt( string $username ): void 
    {
        $clientIp = $this->NoDossgetClientIp();

        // Enforce strict config-level exclusion rule to completely protect admins from tracking
        if ( $this->isClientIpWhitelisted( $clientIp ) ) {
            return;
        }

        $transientName = $this->NoDossgetTransientKey( $clientIp );
        $attempts      = get_transient( $transientName );

        if ( false === $attempts ) {
            set_transient( $transientName, 1, self::LOCKOUT_DURATION_SECONDS );
            return;
        }

        $newAttempts = (int) $attempts + 1;
        set_transient( $transientName, $newAttempts, self::LOCKOUT_DURATION_SECONDS );
    }


    /**
     * Generates a safe, sanitized, fixed-length transient lookup string.
     */
    private function NoDossgetTransientKey( string $ipAddress ): string 
    {
        $hashedIp = md5( $ipAddress );
        return self::TRANSIENT_PREFIX . $hashedIp;
    }

    /**
     * Safely retrieves the client IP, supporting multi-layered architectures
     * (Cloudflare -> BunnyCDN -> Nginx -> FastCGI) without server-level tools.
     */
    private function NoDossgetClientIp(): string 
    {
        // Establish absolute fallback from the immediate TCP socket
        $remoteIp = '127.0.0.1';
        if ( isset( $_SERVER['REMOTE_ADDR'] ) ) {
            $validatedRemote = filter_var( wp_unslash( $_SERVER['REMOTE_ADDR'] ), FILTER_VALIDATE_IP );
            if ( false !== $validatedRemote ) {
                $remoteIp = $validatedRemote;
            }
        }

        // 1. Prioritize Cloudflare's structural header if it exists.
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            // FIXED: Added sanitize_text_field to satisfy WordPress InputNotSanitized sniffer rules
            $rawCfIp  = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
            $cfClient = filter_var( trim( $rawCfIp ), FILTER_VALIDATE_IP );
            if ( false !== $cfClient ) {
                return $cfClient;
            }
        }

        // 2. Multi-proxy validation fallback chain (X-Forwarded-For)
        if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            // FIXED: Added sanitize_text_field to satisfy WordPress InputNotSanitized sniffer rules
            $rawForwarded = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) );
            $ipChain      = array_map( 'trim', explode( ',', $rawForwarded ) );
            
            if ( isset( $ipChain[0] ) ) {
                $originalClient = filter_var( $ipChain[0], FILTER_VALIDATE_IP );
                if ( false !== $originalClient ) {
                    return $originalClient;
                }
            }
        }

        // 3. Absolute architectural backup
        return $remoteIp;
    }
}

// Instantiation block matches the class casing perfectly
new NoDossLoginProtectionManager();