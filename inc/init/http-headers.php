<?php
/**
 * @package       NoDoss
 * @author        Edwin Bekedam
 * @license       GPLv3
 * @version       1.1.6
 *
 * @wordpress-plugin
 */
if (!defined('ABSPATH')) die();


foreach( glob( plugin_dir_path( __FILE__ )."http/*.php" ) as $nodoss_file ){
	include_once $nodoss_file;
}

require_once plugin_dir_path(dirname(__FILE__)) . 'http/nodoss-security--preformance-header.php';
