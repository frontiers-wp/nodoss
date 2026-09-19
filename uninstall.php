<?php
/**
 * @package       NoDoss
 * @author        Edwin Bekedam
 * @license       gplv2
 * @version       1.1.4
 *
 * @wordpress-plugin
 */
if(!defined('WP_UNINSTALL_PLUGIN')) {
	exit;
}

/**
 * Remove Option on uninstalling/deleting the Plugin.
 */
function nodoss_plugin_uninstall() {
	delete_option( 'nodoss_plugin_version' );
}
/**
 * Remove Fields on uninstalling/deleting the Plugin.
 */
delete_option('nodoss_fields');