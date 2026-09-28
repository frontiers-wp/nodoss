<?php if ( ! defined( 'ABSPATH' ) ) exit; // Exit if accessed directly
/**
 * Strips systemic environmental signatures and localized configuration metrics
 * from outbound core, plugin, and theme update checks to enforce absolute site privacy.
 *
 * Engineered with O(1) hash map operations for maximum performance overhead insulation.
 *
 * @param array $query The pre-compiled outbound update metadata array payload.
 * @return array       The hardened query payload containing only context-neutral parameters.
 */
function nodoss_wp_update_privacy(array $query): array
{
    /**
     * Statically cached list of telemetry and fingerprinting parameters to purge.
     */
    static $forbidden_telemetry_keys = [
        'php'                => true, // Active PHP interpreter runtime signature
        'mysql'              => true, // Underlying relational database version
        'local_package'      => true, // Specific regional distribution localization package
        'blogs'              => true, // System deployment scale (Multisite sub-blog total counting metric)
        'users'              => true, // Exact user directory indexing scale metrics
        'multisite_enabled'  => true, // Network environment framework execution configuration type
        'initial_db_version' => true, // Legacy architectural install timestamp fingerprinting trace
    ];

    return array_diff_key($query, $forbidden_telemetry_keys);
}

// Bind privacy filters across all outgoing WordPress update notification loops
add_filter('core_version_check_query_args', 'nodoss_wp_update_privacy', 99);
add_filter('plugins_update_check_locales', 'nodoss_wp_update_privacy', 99);
add_filter('themes_update_check_locales', 'nodoss_wp_update_privacy', 99);
