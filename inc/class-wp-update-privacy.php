<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
/**
 * Filters the WordPress core version check query to enhance privacy
 * by removing sensitive data from being sent to WordPress.org.
 * Update Privacy sending anything but essential data during the update check.
 *
 * @param array $query The query arguments for the core version check.
 * @return array The filtered query arguments with sensitive data removed.
 */
function nodoss_wp_update_privacy(array $query): array
{
    // List of sensitive keys to remove from the version check query
    $sensitive_keys = [
        'php',               // PHP version
        'mysql',             // MySQL version
        'local_package',     // Local package info
        'blogs',             // Number of blogs (multisite)
        'users',             // Number of users
        'multisite_enabled', // Whether multisite is enabled
        'initial_db_version' // Initial database version
    ];

    // Remove each sensitive key from the query
    foreach ($sensitive_keys as $key) {
        unset($query[$key]);
    }

    return $query;
}

// Hook into WordPress to filter the version check query
add_filter('core_version_check_query_args', 'nodoss_wp_update_privacy');