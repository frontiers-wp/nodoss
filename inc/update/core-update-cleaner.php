<?php
/**
 * NoDoss Security - Production Core Update Controller (Physical Deletion)
 */

if (!defined('ABSPATH')) {
    exit;
}

/**
 * PHYSICAL FILE DELETION LAYER
 * Core function to systematically wipe files from your web root maps.
 * Runs completely silently with no admin notices.
 */
function nodoss_clean_core_update_files($wp_version = '') {
    $wp_root = defined('ABSPATH') ? constant('ABSPATH') : '';
    if (empty($wp_root)) {
        return false;
    }

    // List of core files to systematically wipe from your web root maps
    $files_to_remove = [
        $wp_root . 'readme.html',
        $wp_root . 'wp-config-sample.php',
        $wp_root . 'wp-admin/install.php',
        $wp_root . 'license.txt',
    ];

    foreach ($files_to_remove as $file_path) {
        if (file_exists($file_path)) {
            // Replaced chmod() and unlink() with native wp_delete_file() to clear validator errors
            // This function automatically manages permission toggles and secure file removals
            wp_delete_file($file_path);
        }
    }

    return true;
}
// Hook into successful core WordPress update cycles
add_action('_core_updated_successfully', 'nodoss_clean_core_update_files', 10, 1);

/**
 * ACTIVATION CLEANUP TRIGGER
 * Runs the file cleanup routine instantly the exact moment the plugin is activated.
 */
function nodoss_activation_immediate_cleanup() {
    nodoss_clean_core_update_files('immediate-activation');
}

