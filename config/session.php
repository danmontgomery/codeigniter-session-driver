<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/*
|--------------------------------------------------------------------------
| Session Variables
|--------------------------------------------------------------------------
| 'sess_driver'				= session driver to use (cookie, database, native, cache)
| 'sess_cache_driver'		= driver to use for cache
|
*/
$config['sess_driver']			= 'cache';
$config['sess_cache_driver']	= 'apc';