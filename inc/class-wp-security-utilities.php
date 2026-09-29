<?php

declare(strict_types=1);

namespace Nodoss\NoDossPreSecurity;

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Class NoDossSecurityUtilities
 * 
 * Single-class security architecture handling modern HTTP response headers, redirects, 
 * payload sanitation, floating-point DoS mitigation, and conflict-aware runtime hooks.
 */
class NoDossSecurityUtilities
{
    public static function NoDossescapeHtml(string $string): string {
        return htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    public static function NoDossescapeAttr(string $string): string {
        return htmlspecialchars($string, ENT_QUOTES | ENT_SUBSTITUTE | ENT_HTML5, 'UTF-8');
    }

    public static function NoDossescapeJs(mixed $data): string {
        return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
    }

    public static function nodosscheckconfig(string $host, string $uri, bool $secure): void
    {
        /**
         * RESILIENT CONFIGURATION CHECK:
         * Protection operates fully functional by default. It only bypasses execution 
         * if the administrator explicitly defined the bypass constant as FALSE in wp-config.php.
         */
        if (defined('NODOSS_ENABLE_HTTPS_CHECK') && NODOSS_ENABLE_HTTPS_CHECK === false) {
            return; 
        }

        if ($secure) {
            header('Content-Security-Policy: upgrade-insecure-requests');
        } else {
            $redirect = 'https://' . $host . $uri;
            header('HTTP/1.1 301 Moved Permanently');
            header('Location: ' . $redirect);
            exit();
        }
    }

    public static function convertToHttps( string $url ): string
    {
        return (string) preg_replace( '/^http(?=:\/\/)/i', 'https', $url );
    }

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
     * Injects legacy headers that cannot be safely processed via array filters.
     */
    public static function NodossInjectLegacyHeader(): void
    {
        if (is_admin()) {
            header('X-XSS-Protection: 0');
            header('X-UA-Compatible: IE=edge');
        }
    }

    public static function sanitizeStringInput( string $input ): string
    {
        $cleaned = wp_unslash( $input );
        $cleaned = (string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $cleaned);
        $cleaned = sanitize_text_field( $cleaned );
        $cleaned = (string) preg_replace('/(--|\/\*|\*\/|#\s*$)/', '', $cleaned);
        $cleaned = (string) preg_replace('/\b(OR|AND)\s+\d+\s*=\s*\d+/i', '', $cleaned);
        return trim( $cleaned );
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
        $clean_input = rawurldecode( str_replace( '\\', '/', $input ) );
        return (bool) preg_match( '#\.\./|\bvar/|\betc/passwd\b|\bwini\.ini\b#i', $clean_input );
    }

    public static function NodossgetTextFromBlocked( bool $sqli, bool $cmd, bool $dir ): string
    {
        if ( $sqli ) { return 'SQL Injection Attempt'; }
        if ( $cmd ) { return 'OS Command Injection'; }
        if ( $dir ) { return 'Directory Traversal Attempt'; }
        return 'Malicious Payload Blocked';
    }

    private static function NodossserializeData(mixed $data): string
    {
        if (is_array($data) || $data instanceof \Traversable) {
            $result = '';
            foreach ($data as $key => $value) {
                $safeKey = ($key === null) ? '' : (string)$key; 
                $result .= $safeKey . self::NodossserializeData($value);
            }
            return $result;
        }
        return (string)$data;
    }

    public static function nodossprotect(): void
    {
        $allVars = '';
        foreach (['_GET', '_POST', '_COOKIE'] as $global) {
            if (!empty($GLOBALS[$global])) {
                $allVars .= '|' . self::NodossserializeData($GLOBALS[$global]);
            }
        }

        if ($allVars !== '' && str_contains(str_replace('.', '', $allVars), '22250738585072011')) {
            self::NodosshandleAttack();
        }
    }

    private static function NodosshandleAttack(): void
    {
        http_response_code(422);
        header('Content-Type: text/html; charset=UTF-8');
        die('<h1>422 Unprocessable Entity</h1><p>Script interrupted due to floating point DoS attack.</p>');
    }

    /**
     * Initialize Protection and Bind Hooks with Conflict Mitigations
     */
    public static function init(): void {
        // Run immediate mitigation before WordPress lifecycle completely mounts
        self::nodossprotect();

        // Register platform-wide filter adjustments and asset wrappers
        add_filter('wp_headers', [self::class, 'NodossConfermCheckHeaders']);
        // Inject legacy headers safely without array filter limitations
        add_action('send_headers', [self::class, 'NodossInjectLegacyHeader']);
        
        // Conflict Mitigation: Prevent client script injections inside the interactive theme customizer preview
        if ( ! is_customize_preview() ) {
            add_action('wp_enqueue_scripts', [self::class, 'NodossinjectSecureClientEngine']);
        }
        add_action('admin_enqueue_scripts', [self::class, 'NodossinjectSecureClientEngine']);
        add_filter('rest_pre_dispatch', [self::class, 'NodosssanitizeRestPayloads'], 10, 3);
    }

    /**
     * Intercepts and recursively neutralizes active elements from dynamic REST API data requests
     * with context-aware conflict bypasses.
     */
    public static function NodosssanitizeRestPayloads($result, $server, $request) {
        // Ensure we are working with a valid request object structure
        if ( ! is_a( $request, 'WP_REST_Request' ) ) {
            return $result;
        }

        $route = $request->get_route();

        /**
         * PLUGIN CONFLICT MITIGATION MATRIX
         * Bypasses structural layout APIs and endpoints that natively handle rich blocks or code snippets.
         */
        $excluded_routes = [
            '#/wp/v2/posts#',       // Gutenberg block-editor backend structures
            '#/wp/v2/pages#',       // Core native builder adjustments
            '#/elementor/v1#',      // Elementor visual asset manager
            '#/wc/v3#'              // WooCommerce store tracking pipelines
        ];

        foreach ($excluded_routes as $pattern) {
            if (preg_match($pattern, $route)) {
                return $result; // Safely bypass strict formatting rules for verified layout tools
            }
        }

        // Conflict Mitigation: Safely verify user capability only if user environment is loaded
        if (function_exists('get_current_user_id') && get_current_user_id() !== 0) {
            if (current_user_can('manage_options')) {
                return $result;
            }
        }

        // Processing individual REST parameter pools explicitly to persist data safely
        foreach (['body_params', 'query_params', 'default_params'] as $param_type) {
            $getter = 'get_' . $param_type;
            $setter = 'set_' . $param_type;

            if (method_exists($request, $getter) && method_exists($request, $setter)) {
                $params = $request->$getter();
                if (!empty($params) && is_array($params)) {
                    array_walk_recursive($params, function(&$value) {
                        if (is_string($value)) {
                            $value = self::sanitizeStringInput($value);
                        }
                    });
                    $request->$setter($params);
                }
            }
        }
        
        return $result;
    }

    public static function NodossinjectSecureClientEngine(): void {
        ?>
        <script id="nodoss-securedom-engine">
            (function() {
                if (typeof window.SecureDOM !== 'undefined') return;

                const SecureDOMEngine = {
                    setText: function(elementId, rawString) {
                        const el = document.getElementById(elementId);
                        if (el) { el.textContent = rawString; }
                    },
                    setAttribute: function(elementId, attributeName, rawString) {
                        const el = document.getElementById(elementId);
                        if (el) { el.setAttribute(attributeName, rawString); }
                    },
                    escapeHTML: function(str) {
                        return str.replace(/[&<>"']/g, function(match) {
                            const escapeMap = {
                                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;'
                            };
                            return escapeMap[match];
                        });
                    }
                };

                Object.defineProperty(window, 'SecureDOM', {
                    value: Object.freeze(SecureDOMEngine),
                    writable: false,
                    configurable: false
                });
            })();
        </script>
        <?php
    }
}

// Instantiate single-class orchestration hooks immediately
NoDossSecurityUtilities::init();