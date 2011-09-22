#CodeIgniter Session Driver

##Requirements
* CodeIgniter 2.0+

This is a replacement for CodeIgniter's session library which utilizes drivers. Currently, supported drivers are:

* Cookie (default)
* Database
* Native
* Cache

There are a couple of new config options in config/session.php, and the 'sess_use_database' option is no longer used.

	$this->load->spark('session-driver/0.0.1');