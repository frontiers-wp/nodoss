<?php defined('ABSPATH') or die('Sorry dude!');
/**
 * @package       NoDoss
 * @author        Edwin Bekedam
 * @license       gplv2
 * @version       1.1.5
 *
 * @wordpress-plugin
 */
require_once plugin_dir_path(dirname(__FILE__)) . 'classes/base.php';

class nodoss_Setup extends nodoss_Base {

	/**
	 * Specify all codes required for plugin activation here.
	 */
	public function activate() {
		// Initialize custom things on plugin activation
		$this->install();
        // register uninstall
        register_uninstall_hook(__FILE__,'nodoss_uninstall');        
	}

	/**
	 * Specify all codes required for plugin deactivation here.
	 */
	public function deactivate() {
	}

	/**
	 * Specify all codes required for plugin uninstall here.
	 *
	 */
	public function uninstall() {
        // delete plugin options
        delete_option('nodoss_options');
        // delete plugin transient
        delete_transient('nodoss_transient');
    }

	public function install() {
		
		// Initialize plugin options
		$this->initOptions();
	}

	/**
	 * Storing custom options
	 */
	public function initOptions() {
	}

}