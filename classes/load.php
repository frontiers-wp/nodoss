<?php defined('ABSPATH') or die('Sorry dude!');
/**
 * @package       NoDoss
 * @author        Edwin Bekedam
 * @license       gplv2
 * @version       1.1.5
 *
 * @wordpress-plugin
 */

/** Nodoss Security headers */
require_once plugin_dir_path(dirname(__FILE__)) . '/inc/init/http-headers.php'; 
/** Bullet proof sitemaps */
require_once plugin_dir_path(dirname(__FILE__)) . '/inc/class-wp-bulletproof-sitemaps.php';
/** Load csrf protection  */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-csrf.php';
/** Load Secure Protocol */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-security-utilities.php';
/** Load Sameorigin Iframe-buster */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-sameorigin.php';
/** Load NoDoss AntiClick Jack */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-anti-clickjack.php';
/** WP Update Privacy */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-update-privacy.php';
/** User agent DarknetSpam */
require_once plugin_dir_path(dirname(__FILE__)) . '/inc/class-wp-user-agent.php';
/** Stop from modifying WordPress */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-user-edits.php';
/** Limit wp user reset api */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-user-reset-api.php';
/** Load Xpowered-by */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-x-powered-by.php';
/** Hide WordPress Version */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-version.php';
/** Limited WP Login */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-limited-admin.php';
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/class-wp-login.php';

/** Nodoss Core Update Cleaner  */
require_once plugin_dir_path(dirname(__FILE__)) . 'inc/update/core-update-cleaner.php';

