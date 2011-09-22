<?php

session_start();

class Session_native extends CI_Driver {

	protected $CI;

	public function __construct()
	{
		$this->CI = get_instance();
	}

	// --------------------------------------------------------------------

	/**
	 * Fetch the current session data if it exists
	 *
	 * @access	public
	 * @return	bool
	 */
	public function sess_read()
	{
		$session = $_SESSION;

		// Is the session data we unserialized an array with the correct format?
		if ( ! is_array($session) OR ! isset($session['session_id']) OR ! isset($session['ip_address']) OR ! isset($session['user_agent']) OR ! isset($session['last_activity']))
		{
			log_message('debug', 'A session was not found.');
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Is the session current?
		if (($session['last_activity'] + $this->parent->sess_expiration) < $this->parent->now)
		{
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Does the IP Match?
		if ($this->parent->sess_match_ip == TRUE AND $session['ip_address'] != $this->CI->input->ip_address())
		{
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Does the User Agent Match?
		if ($this->parent->sess_match_useragent == TRUE AND trim($session['user_agent']) != trim(substr($this->CI->input->user_agent(), 0, 120)))
		{
			$this->sess_destroy(FALSE);
			return FALSE;
		}

		// Session is valid!
		$this->parent->userdata = $session;
		unset($session);

		return TRUE;
	}

	// --------------------------------------------------------------------

	/**
	 * Write the session data
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_write()
	{
		$_SESSION = array();
		foreach($this->parent->userdata as $key => $val)
		{
			$_SESSION[$key] = $val;
		}
	}

	// --------------------------------------------------------------------

	/**
	 * Create a new session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_create()
	{
		if(session_id() == '') {
			session_start();
		}

		$_SESSION['session_id']		= session_id();
		$_SESSION['ip_address']		= $this->CI->input->ip_address();
		$_SESSION['user_agent']		= substr($this->CI->input->user_agent(), 0, 120);
		$_SESSION['last_activity']	= $this->parent->now;

		$this->parent->userdata = $_SESSION;
	}

	// --------------------------------------------------------------------

	/**
	 * Update an existing session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_update()
	{
		// We only update the session every five minutes by default
		if (($this->parent->userdata['last_activity'] + $this->parent->sess_time_to_update) >= $this->parent->now)
		{
			return;
		}

		// Regenerate session id
		session_regenerate_id();

		// Update the session data in the session data array
		$this->parent->userdata['session_id'] = session_id();
		$this->parent->userdata['last_activity'] = $this->parent->now;
	}

	// --------------------------------------------------------------------

	/**
	 * Destroy the current session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_destroy($destroy = TRUE)
	{
		session_unset();
		session_regenerate_id();

		if($destroy)
			session_destroy();
	}

	// --------------------------------------------------------------------
	
	/**
	 * Does nothing for cookie sessions
	 *
	 * @access private
	 * @return void
	 */
	public function _sess_gc(){}

}