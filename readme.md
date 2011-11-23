#CodeIgniter Session Driver

##Requirements
* CodeIgniter 2.0+

This is a replacement for CodeIgniter's session library which utilizes drivers. Currently, supported drivers are:

* Cookie (default)
* Database
* Native
* Cache

There are a couple of new config options in config/session.php, and the 'sess_use_database' option is no longer used.

	$this->load->spark('session-driver/X.X.X');

(Replace X.X.X with the appropriate version)

###NOTE
I moved sess_write() to __destruct(), which means that session writes will only happen once per request (useful for database sessions), it also means that these queries won't show up in the profiler, because they happen after the profiler has finished running.