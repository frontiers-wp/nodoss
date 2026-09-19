<?php

declare(strict_types=1);

namespace Nodoss\NoDossPreSecurity;

use PhpAttribute;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * DEFAULT CONFIGURATION
 * This fallback runs when the constant is missing from wp-config.php.
 * 
 * true  = ENABLED  (Default status)
 * false = DISABLED (Will override when set in wp-config.php for debug)
 */
if (!defined('NODOSS_ENABLE_HTTPS_CHECK')) {
    define('NODOSS_ENABLE_HTTPS_CHECK', true);
}

/**
 * Class NoDossSecurityUtilities
 * 
 * Handles modern HTTP response headers, structural redirects, payload security, 
 * and procedural escaping utility suites.
 */
class NoDossSecurityUtilities
{
    /**
     * Check if the connection is secure and redirect if needed
     *
     * @param string $host   The host name
     * @param string $uri    The request URI
     * @param bool   $secure Whether the connection is secure
     */
    public static function nodosscheckconfig(string $host, string $uri, bool $secure): void
    {
        // Skip entirely if disabled (false)
        if (!NODOSS_ENABLE_HTTPS_CHECK) {
            return;
        }

        if ($secure) {
            // Set Content-Security-Policy header for secure connections
            header('Content-Security-Policy: upgrade-insecure-requests');
        } else {
            // Redirect to HTTPS if not secure
            $redirect = 'https://' . $host . $uri;
            header('HTTP/1.1 301 Moved Permanently');
            header('Location: ' . $redirect);
            exit();
        }
    }

    /**
     * Force a target string resource to resolve over TLS/HTTPS.
     * 
     * @param string $url The URL string to mutate.
     * @return string Modified HTTPS URL string.
     */
    public static function convertToHttps( string $url ): string
    {
        return (string) preg_replace( '/^http(?=:\/\/)/i', 'https', $url );
    }

    /**
     * check current headers for secure content
     *
     * @param array $headers Current headers array
     * @return array Modified headers with security headers
     */
    public static function NodossConfermCheckHeaders(array $headers = []): array
    {
        return array_merge($headers, [
            'Content-Security-Policy'   => 'upgrade-insecure-requests',
            'X-Content-Type-Options'    => 'nosniff',
            'X-Frame-Options'           => 'SAMEORIGIN',
            'Permissions-Policy'        => 'geolocation=(), microphone=(), camera=()'
        ]);
    }

    /**
     * Add security headers (XSS protection and IE compatibility)
     * 
     * Marked as deprecated via native attribute to comply with PHP 8.5 metadata standards.
     */
    #[\Deprecated(message: "Use NodossConfermCheckHeaders instead", since: "2.1.0")]
    public static function modifyXSSHeaders(): void
    {
        if (is_admin()) {
            header('X-XSS-Protection: 0');
            header('X-UA-Compatible: IE=edge');
        }
    }

    /**
     * Pre-processes, unslashes, and sanitizes dangerous input variations.
     */
    public static function sanitizeStringInput( string $input ): string
    {
        return trim( sanitize_text_field( wp_unslash( $input ) ) );
    }

    /**
     * Verify form arrays specifically to block header splitting / injection vectors.
     */
    public static function NodossNoHeaderInjection( array $fields ): bool  
    {
        foreach ( $fields as $field ) {
            if ( is_string( $field ) && preg_match( '/%0A|%0D|\r|\n/i', $field ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Structural scanner to determine if URL parameter strings mirror directory traversal paths.
     */
    public static function NodossdetectTraversalDirectory( string $input ): bool
    {
        if ( empty( $input ) ) {
            return false;
        }
        // Clean context string to avoid simple obfuscation bypasses
        $clean_input = rawurldecode( str_replace( '\\', '/', $input ) );
        return (bool) preg_match( '#\.\./|\bvar/|\betc/passwd\b|\bwini\.ini\b#i', $clean_input );
    }

    /**
     * Get the type of attack detected.
     *
     * @param bool $sqli SQL injection flag
     * @param bool $cmd Command injection flag
     * @param bool $dir Directory traversal flag
     * @return string The type of attack detected
     */
    public static function getTextFromBlocked( bool $sqli, bool $cmd, bool $dir ): string
    {
        if ( $sqli ) {
            return 'SQL Injection Attempt';
        }
        if ( $cmd ) {
            return 'OS Command Injection';
        }
        if ( $dir ) {
            return 'Directory Traversal Attempt';
        }
        return 'Malicious Payload Blocked';
    }
}

/**
 * Floating Point DoS Protection Class
 */
class FrontiersFloatingPointNoDosProtection
{
    /**
     * Recursively serialize data for pattern checking
     */
    private static function serializeData(mixed $data): string
    {
        if (is_array($data) || $data instanceof \Traversable) {
            $result = '';
            foreach ($data as $key => $value) {
                // PHP 8.5 Deprecation Fix: Prevent null or unassigned keys from mutating as loose array offset lookups
                $safeKey = ($key === null) ? '' : (string)$key; 
                $result .= $safeKey . self::serializeData($value);
            }
            return $result;
        }
        return (string)$data;
    }

    /**
     * Check for floating point DoS attack pattern
     */
    public static function nodossprotect(): void
    {
        $allVars = '';

        // Check all superglobals safely without implicit variable conversions
        foreach (['_GET', '_POST', '_COOKIE'] as $global) {
            if (!empty($GLOBALS[$global])) {
                $allVars .= '|' . self::serializeData($GLOBALS[$global]);
            }
        }

        // Check for the attack pattern
        if ($allVars !== '' && str_contains(str_replace('.', '', $allVars), '22250738585072011')) {
            self::handleAttack();
        }
    }

    /**
     * Handle the attack by terminating execution
     */
    private static function handleAttack(): void
    {
        http_response_code(422);
        header('Content-Type: text/html; charset=UTF-8');
        die('<h1>422 Unprocessable Entity</h1><p>Script interrupted due to floating point DoS attack.</p>');
    }
}

// Initialize protection
FrontiersFloatingPointNoDosProtection::nodossprotect();
