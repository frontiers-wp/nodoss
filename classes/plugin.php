<?php defined('ABSPATH') or die('Sorry dude!');
/**
 * @package       NoDoss
 * @author        Edwin Bekedam
 * @license       GPLv3
 * @version       1.1.6
 *
 * @wordpress-plugin
 */
require_once plugin_dir_path(dirname(__FILE__)) . 'classes/setup.php';
require_once plugin_dir_path(dirname(__FILE__)) . 'classes/load.php';

class nodoss_Plugin extends nodoss_Setup {
	public $config;
	
	public function __construct($config) {
		$this->config = $config;
		add_action('init', array(&$this, 'init'));
	}

	public function init() {

	}

}
