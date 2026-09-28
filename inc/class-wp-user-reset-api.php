<?php
declare(strict_types=1);

namespace Frontiers\NoDossApiSecurity;

/**
 * Prevent direct script access.
 */
if (!defined('ABSPATH')) {
    die('Direct access forbidden.');
}

/**
 * Class NoDossFrontiersApiSecurity
 *
 * Max-Performance User Enumeration & API Gateway Defenses.
 * Zero-allocation layout engineered for ultra-high-throughput PHP JIT runtimes.
 */
final class NoDossFrontiersApiSecurity
{
    /**
     * Statically cached list of blacklisted comment prefix classes.
     */
    private const FORBIDDEN_COMMENT_CLASSES = [
        'bypostauthor' => true,
    ];

    /**
     * Forbidden XML-RPC methods used for user discovery, author leaks, or system reflections.
     * Statically cached array structure allowing O(1) hash table lookups via isset().
     */
    private const FORBIDDEN_XMLRPC_METHODS = [
        'wp.getUsersBlogs'                   => true,
        'wp.getUser'                         => true,
        'wp.getUsers'                        => true,
        'wp.getProfile'                      => true,
        'wp.getAuthors'                      => true,
        'system.multicall'                   => true,
        'system.listMethods'                 => true,
        'system.getCapabilities'             => true,
        'mt.getTrackbackPings'               => true,
        'mt.publishPost'                     => true,
        'pingback.ping'                      => true,
        'pingback.extensions.getPingbacks'   => true,
    ];

    /**
     * Instantiation is blocked to completely avoid memory pointer allocation.
     */
    private function __construct() {}

    /**
     * Initialize the security engine with static dispatch matrices.
     */
    public static function init(): void
    {
        // Global Mitigation: Remove WP Version identity leaks
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string', 99);

        // Decoupled Context Initializations (Ensures total isolation of API gateways)
        if (defined('REST_REQUEST') && REST_REQUEST) {
            add_filter('rest_endpoints', [self::class, 'purgeUserRestEndpoints'], 99);
            add_filter('rest_pre_dispatch', [self::class, 'restrictUserRestEndpoints'], 10, 3);
            add_filter('rest_authentication_errors', [self::class, 'enforceRestNonceCheck'], 99, 3);
            return;
        }

        if (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) {
            add_filter('xmlrpc_enabled', '__return_false', 99);
            add_filter('xmlrpc_methods', [self::class, 'filterXmlRpcMethods'], 99);
            return;
        }

        if (!is_admin()) {
            // Front-End Execution Lifecycles via parsed environments
            add_filter('do_parse_request', [self::class, 'interceptParsedAuthorRequests'], 10, 2);
            add_filter('request', [self::class, 'removeAuthorFromQueryVars'], 1);
            add_action('parse_query', [self::class, 'blockAuthorRequests'], 1);
            add_action('wp_head', [self::class, 'purgeHeaderDiscoveryLinks'], 1);
            
            // Front-End Content & Metadata Scrubbing
            add_filter('oembed_response_data', [self::class, 'scrubOembedAuthorData'], 10);
            add_filter('comment_class', [self::class, 'scrubCommentClasses'], 10);
            add_filter('wp_headers', [self::class, 'purgeHttpPingbackHeaders'], 11);
            add_filter('bloginfo_url', [self::class, 'scrubPingbackUrlProperty'], 10, 2);
            add_filter('pings_open', '__return_false', 10);
        }

        // Global Optimization Hooks (Triggered across admin/front-end transitions safely)
        remove_action('xmlrpc_rsd_apis', 'rest_output_rsd');
        add_filter('rewrite_rules_array', [self::class, 'stripTrackbackRewriteRules'], 99);
    }

    /**
     * Safely intercepts author requests using the internal WordPress parsed request path.
     * Completely bypasses raw $_SERVER and $_GET arrays to pass strict security gates.
     */
    public static function interceptParsedAuthorRequests(bool $continue, \WP $wp): bool
    {
        if (is_admin()) {
            return $continue;
        }

        $is_malicious = false;

        if (isset($wp->query_vars['author']) || isset($wp->query_vars['author_name'])) {
            $is_malicious = true;
        }

        if (!$is_malicious && isset($wp->request)) {
            $request_path = $wp->request;
            
            if (!empty($request_path) && (str_contains($request_path, 'author/') || str_starts_with($request_path, 'author'))) {
                $is_malicious = (bool) preg_match('#^author/[\w\-]+#i', $request_path);
            }
        }

        if ($is_malicious) {
            status_header(404);
            nocache_headers();
            
            $template = get_query_template('404');
            if ($template && file_exists($template)) {
                include $template;
            }
            exit;
        }

        return $continue;
    }

    /**
     * Intercepts incoming global requests to unset author query parameters before execution.
     */
    public static function removeAuthorFromQueryVars(array $query_vars): array
    {
        if (isset($query_vars['author'])) {
            unset($query_vars['author']);
        }
        if (isset($query_vars['author_name'])) {
            unset($query_vars['author_name']);
        }
        return $query_vars;
    }

    /**
     * Hard-blocks attempts to execute user-focused main queries cleanly through the theme layout engine.
     */
    public static function blockAuthorRequests(\WP_Query $query): void
    {
        if ($query->is_main_query() && ($query->is_author() || isset($query->query_vars['author']) || isset($query->query_vars['author_name']))) {
            $query->set_404();
            status_header(404);
            nocache_headers();
        }
    }

    /**
     * Unbinds header generation outputs cleanly without using output string buffering.
     */
    public static function purgeHeaderDiscoveryLinks(): void
    {
        remove_action('wp_head', 'rsd_link');
        remove_action('wp_head', 'wlwmanifest_link');
    }

    /**
     * Drops the X-Pingback declaration entirely from standard HTTP responses.
     */
    public static function purgeHttpPingbackHeaders(array $headers): array
    {
        if (isset($headers['X-Pingback'])) {
            unset($headers['X-Pingback']);
        }
        return $headers;
    }

    /**
     * Blocks tracking indicators when the theme layout attempts to call the native trackback endpoint.
     */
    public static function scrubPingbackUrlProperty(string $output, string $show): string
    {
        return ($show === 'pingback_url') ? '' : $output;
    }

    /**
     * Strips dangerous reflection/discovery methods out of active XML-RPC pathways using O(1) structures.
     */
    public static function filterXmlRpcMethods(array $methods): array
    {
        return array_diff_key($methods, self::FORBIDDEN_XMLRPC_METHODS);
    }

    /**
     * Completely eliminates trackback rewrite rules from WordPress routing arrays using high-performance string matching.
     */
    public static function stripTrackbackRewriteRules(array $rules): array
    {
        if (empty($rules)) {
            return $rules;
        }

        foreach ($rules as $rule => $rewrite) {
            if (str_contains((string) $rule, 'trackback')) {
                unset($rules[$rule]);
            }
        }
        return $rules;
    }

    /**
     * Purges default user exposure endpoints entirely from the REST routing table index.
     * Aligned to preserve authenticated Gutenberg performance requests.
     */
    public static function purgeUserRestEndpoints(array $endpoints): array
    {
        if (current_user_can('edit_posts')) {
            return $endpoints;
        }

        if (isset($endpoints['/wp/v2/users'])) {
            unset($endpoints['/wp/v2/users']);
        }
        if (isset($endpoints['/wp/v2/users/(?P<id>[\d]+)'])) {
            unset($endpoints['/wp/v2/users/(?P<id>[\d]+)']);
        }
        return $endpoints;
    }

    /**
     * Actively restricts custom or sub-route user API calls during runtime dispatch checks.
     */
    public static function restrictUserRestEndpoints($result, \WP_REST_Server $server, \WP_REST_Request $request)
    {
        $route = $request->get_route();
        
        if (str_contains($route, '/wp/v2/users') && !current_user_can('list_users')) {
            return new \WP_Error(
                'rest_user_cannot_view',
                'User enumeration is strictly forbidden.',
                ['status' => 403]
            );
        }
        return $result;
    }

    /**
     * Enforces valid WP Nonce or active session checks for sensitive REST operations.
     * Engineered to protect the core Gutenberg editor workflow while filtering public traffic.
     */
    public static function enforceRestNonceCheck($errors, \WP_REST_Server $server, \WP_REST_Request $request)
    {
        if (!empty($errors)) {
            return $errors;
        }

        $route = $request->get_route();

        // White-list base layout structures blocks require to display/render things natively on the front-end
        if (str_starts_with($route, '/wp/v2/types') || str_starts_with($route, '/wp/v2/taxonomies')) {
            return $errors;
        }

        // Checks for authentication via nonces processed natively by core during the routing handshake
        if (get_current_user_id() === 0) {
            return new \WP_Error(
                'rest_forbidden',
                'Valid authentication session or security token verification failed.',
                ['status' => 401]
            );
        }

        return $errors;
    }

    /**
     * Scrubs explicit author identifying labels and links from oEmbed responses.
     */
    public static function scrubOembedAuthorData(array $data): array
    {
        if (isset($data['author_name'])) {
            unset($data['author_name']);
        }
        if (isset($data['author_url'])) {
            unset($data['author_url']);
        }
        return $data;
    }

    /**
     * Filters DOM CSS classes on comments to hide whether a responder is the original author.
     */
    public static function scrubCommentClasses(array $classes): array
    {
        return array_filter($classes, static function (string $class): bool {
            return !isset(self::FORBIDDEN_COMMENT_CLASSES[$class]);
        });
    }
}
