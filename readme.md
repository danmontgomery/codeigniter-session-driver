#CodeIgniter Session Driver

##Requirements
* CodeIgniter 2.0+

This is a replacement for CodeIgniter's session library which utilizes drivers. Currently, supported drivers are:

* Cookie (default)
* Database
* Native
* Cache

There are a few new config options, other than that the only thing that changes in the usage of the session library is the way it's loaded:

	$this->load->driver('session');