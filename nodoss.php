<?php
/**
 * @package       NoDoss
 * @author        Edwin Bekedam
 * @license       gplv2
 * @version       1.1.5
 *
 * @wordpress-plugin
 * Plugin Name: NoDoss
 * Plugin URI:  https://wordpress.org/plugins/nodoss
 * Description: Lightweight Security plugin againts attacks, incl mordern securty headers.
 * Version:     1.1.5
 * Author:      Edwin Bekedam
 * Author URI:  https://github.com/frontiers-wp/nodoss
 * Text Domain: nodoss
 * Domain Path: /languages
 * License:     GPLv2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 *
 * You should have received a copy of the GNU General Public License
 * along with NoDoss. If not, see <https://www.gnu.org/licenses/gpl-2.0.html/>.
 */

// If this file is called directly, abort.
if (! defined('WPINC')) {
    die;
}

define( 'NODOSS_DIR_URL', plugin_dir_url( __FILE__ ) );
define( 'NODOSS_PLUGIN_FILE', __FILE__ );
define( 'NODOSS_PLUGIN_BASE_NAME', basename(__DIR__));

// Admin Force SSL
add_action( 'admin_init', 'nodoss_force_ssl' );
function nodoss_force_ssl() {
    if ( current_user_can( 'FORCE_SSL_ADMIN' ) )
        define( 'FORCE_SSL_ADMIN', 1 );
}

// Define constant with current version
if (! defined( 'NODOSS_VERSION' ) ) {
    define( 'NODOSS_VERSION', '1.1.5' );
}

/** Load Nodoss */
require_once plugin_dir_path(__FILE__) . 'classes/plugin.php';

// Bail early if attempting to run on non-supported PHP versions.
if (version_compare(PHP_VERSION, '8.2', '<')) {
    /**
     * Displays an admin notice for incompatible PHP versions.
     */
    function nodoss_incompatible_admin_notice(): void {
        echo wp_kses_post(
            sprintf(
                '<div class="notice notice-error"><p>%s</p></div>',
                esc_html__(
                    'Nodoss requires PHP 8.2 (or higher) to function properly. Please upgrade PHP. The plugin has been auto-deactivated.',
                    'nodoss'
                )
            )
        );

    // Verify nonce if 'activate' parameter is set
    if (isset($_GET['activate'])) {
        // Sanitize and verify the nonce
        $nonce = sanitize_text_field(wp_unslash($_GET['activate']));
        if (!wp_verify_nonce($nonce, 'activate')) {
        // Handle invalid nonce (e.g., redirect or show error)
            wp_die('Invalid nonce. Please try again.');
        }
        // Prevent activation redirect by unsetting the 'activate' parameter
        unset($_GET['activate']);}
    }

    /**
     * Deactivates the plugin if PHP version is insufficient.
     */
    function nodoss_deactivate_self(): void {
        if (function_exists('deactivate_plugins')) {
            deactivate_plugins(plugin_basename(NODOSS_PLUGIN_FILE));
        }
    }

    // Hook into WordPress admin actions.
    add_action('admin_notices', 'nodoss_incompatible_admin_notice');
    add_action('admin_init', 'nodoss_deactivate_self');

    return;
}

/**
 * Print admin notice if plugin installed with incorrect slug.
 */
function nodoss_incorrect_plugin_slug_admin_notice() {
    $actual_slug = basename(NODOSS_PLUGIN_DIR);

    if (empty($actual_slug)) {
        return;
    }

    $message = sprintf(
        /* translators: 1: Current plugin directory name, 2: Correct plugin directory name */
        __('You appear to have installed the NoDoss plugin incorrectly. It is currently installed in the <code>%1$s</code> directory, but it needs to be placed in a directory named <code>%2$s</code>. Please rename the directory. This is important for WordPress plugin auto-updates.', 'nodoss'),
        esc_html($actual_slug),
        'nodoss'
    );

    printf(
        '<div class="notice notice-warning is-dismissible"><p>%s</p></div>',
        wp_kses_post($message)
    );
}

// Check if the plugin directory is incorrectly named
if (defined('NODOSS_PLUGIN_DIR') && basename(NODOSS_PLUGIN_DIR) !== 'nodoss') {
    add_action('admin_notices', 'nodoss_incorrect_plugin_slug_admin_notice');
}


// Check if the admin notice transient exists
if (get_transient('nodoss_admin_notice')) {
    // Add admin notice hook
    add_action('admin_notices', 'nodoss_admin_notice');

    // Delete the transient after displaying the notice
    delete_transient('nodoss_admin_notice');
}

/**
 * Display the admin notice
 */
function nodoss_admin_notice() {
    ?>
    <div class="notice notice-success is-dismissible">
        <p>
            <?php
            echo wp_kses(
                __('NoDoss Security has been <strong>enabled</strong>.<br>Please flush your browser and server cache', 'nodoss'),
                [
                    'strong' => [],
                    'br'     => []
                ]
            );
            ?>
        </p>
    </div>
    <?php
}


/**
 * WordPress transient-based admin notice system
 */
function nodoss_admin_notice_activation_hook() {
    /**
     * Sets a temporary transient value (similar to WordPress set_transient)
     * Uses WordPress transient API which automatically handles expiration
     */
    set_transient('nodoss_admin_notice', true, 5); // 5 seconds expiration

    // @todo flush cache implementation would go here
    // Might involve WP_Cache, object cache, or similar
}

/**
 * Activation Message
 */
register_activation_hook( __FILE__, 'nodoss_admin_notice_activation_hook' ); 
