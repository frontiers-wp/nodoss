<?php
/**
 * Removes WordPress version footprints safely.
 *
 * @package Nodoss\Frontiers\Security
 */
namespace Nodoss\Frontiers\Security;

if (!defined('ABSPATH')) {
    die();
}

/**
 * Clean up version strings from scripts and styles query parameters.
 * 
 * Dynamically keeps version parameters for all external assets, plugins, 
 * and CDNs, while removing them from local internal assets.
 *
 * @param string $src The source URL of the asset.
 * @return string The cleaned source URL.
 */
function nodoss_remove_asset_version(string $src): string
{
    // Handle relative URLs (e.g., /wp-includes/js/wp-embed.js)
    // If it doesn't start with a protocol or domain, it is local.
    if (str_starts_with($src, '/') && !str_starts_with($src, '//')) {
        return remove_query_arg('ver', $src);
    }

    // Fetch the host domain of the current WordPress site
    $site_url = wp_parse_url(home_url(), PHP_URL_HOST);

    // Automatically bypass stripping for ANY external script or CDN
    // If the asset URL does not contain your site's domain, leave it alone.
    if ($site_url && !str_contains($src, $site_url)) {
        return $src;
    }

    /**
     * Optional: Exclude specific local plugin files from stripping
     * 
     * If a specific local plugin breaks without its version string (like your iframe buster),
     * developers can add its filename to this filter.
     */
    $excluded_keywords = apply_filters('nodoss_frontiers_security_version_removal_exclusions', array(
        'frontiers-iframe-buster'
    ));

    if (is_array($excluded_keywords)) {
        foreach ($excluded_keywords as $keyword) {
            if (str_contains($src, $keyword)) {
                return $src;
            }
        }
    }

    // 5. Remove the 'ver' query argument safely from local assets
    return remove_query_arg('ver', $src);
}

