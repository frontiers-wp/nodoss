<?php 
namespace Nodoss\NosdossWpMapHandler;

defined('ABSPATH') or die("you do not have access to this page!");

/**
 * WordPress Sitemap Security and Redirection Handler
 */
class NosdossWpMapHandler
{
    /**
     * Constructor - initializes the handler and sets up redirection
     */
    public function __construct()
    {
        $this->handleSitemapRedirection();
    }

    /**
     * Checks for legacy sitemap URL patterns and performs 301 redirect to standard format
     */
    protected function handleSitemapRedirection() 
    {
        // Check if REDIRECT_URL server variable exists (typically set by Apache)
        if (!isset($_SERVER['REDIRECT_URL'])) {
            return;
        }

        $url = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_URL']));
        // Match patterns like /anything-sitemap.html, /sitemap.xml.gz, etc.
        if (preg_match('%(?i)(?<!^)\/(.*)?sitemap(.*)?\.(htm|html|xml)(\\.gz)?%', $url, $matches)) {
            $gzSuffix = $matches[4] ?? '';
            $this->sendPermanentRedirect('/sitemap.xml' . $gzSuffix);
        }
    }

    /**
     * Sends HTTP 301 permanent redirect headers and terminates execution
     *
     * @param string $location The target URL for redirection
     */
    protected function sendPermanentRedirect(string $location): void
    {
        // Ensure no output has been sent before headers
        if (headers_sent()) {
            return;
        }

        wp_safe_redirect(home_url($location), 301);
        exit;
    }

    /**
     * Blocks WordPress user enumeration attempts via sitemap
     *
     * @param string|null $redirect Original redirect URL
     * @param string $request Requested URL path
     * @return string|null Returns null to terminate if enumeration detected
     */
    public function blockUserEnumeration(?string $redirect, string $request): ?string
    {
        if (preg_match('%(?i)(wp-sitemap-users-[0-9]+\\.xml)%', $request)) {
            // Return 403 Forbidden for user enumeration attempts
            if (!headers_sent()) {
                status_header(403);
                nocache_headers();
            }
            wp_die('', 403);
        }

        return $redirect;
    }
}

// Initialize the handler
$NodossMapHandler = new NosdossWpMapHandler();

// Hook into WordPress canonical redirect filter
add_filter('redirect_canonical', [$NodossMapHandler, 'blockUserEnumeration'], 10, 2);