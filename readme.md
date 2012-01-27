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
I suggest adding a call to sess_write() in the _output function of the controller, which will write the session before output and avoid issues with setting the cookie. If you don't do this, the library will try to write in __destruct(), which may or may not cause you issues.

	class MY_Controller extends CI_Controller {
		public function _output($output)
		{
			if(isset($this->session))
			{
				$this->session->sess_write();
			}

			echo $output;
		}
	}