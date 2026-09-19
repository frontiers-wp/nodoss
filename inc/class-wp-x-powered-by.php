<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly
}

class NoDossXPoweredBy
{
    /**
     * Constructor - Hooks into WordPress to clear headers.
     */
    public function __construct()
    {
        // Hook into send_headers to remove X-Powered-By before output is sent
        add_action( 'send_headers', array( $this, 'remove_x_powered_by' ), 0 );
    }

    /**
     * Removes the X-Powered-By header.
     */
    public function remove_x_powered_by()
    {
        if ( function_exists( 'header_remove' ) ) {
            header_remove( 'X-Powered-By' );
        } else {
            // Alternative approach when header_remove is not available
            $this->setPhpIniDirectives();
        }
    }

    /**
     * Sets PHP ini directives for security when header_remove is unavailable
     */
    private function setPhpIniDirectives()
    {
        // Disable PHP version exposure
        if (!defined('NODOSS_EXPOSE_PHP_FALLBACK')) {
            define('NODOSS_EXPOSE_PHP_FALLBACK', '0');
        }
        
    }

    /**
     * Hides FastCGI headers if the function exists
     */
    public function hideFastcgiHeader()
    {
        if (function_exists('fastcgi_hide_header')) {
            fastcgi_hide_header(0);
        }
    }
}