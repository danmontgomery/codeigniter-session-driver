<?php

class Session_cookie extends CI_Driver {

	protected $CI;

	protected $sess_cookie_name;
	protected $cookie_prefix;
	protected $cookie_path;
	protected $cookie_domain;
	protected $cookie_secure;

	/**
	 * Set necessary config options
	 *
	 * @access public
	 * @return void
	 */
	public function __construct()
	{
		$this->CI = get_instance();

		foreach (array('sess_encrypt_cookie', 'sess_cookie_name', 'cookie_prefix', 'cookie_path', 'cookie_domain', 'cookie_secure') as $key)
		{
			$this->$key = $this->CI->config->item($key);
		}

		// Do we need encryption? If so, load the encryption class
		if ($this->sess_encrypt_cookie == TRUE)
		{
			$this->CI->load->library('encrypt');
		}
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
		// Fetch the cookie
		$session = $this->CI->input->cookie($this->sess_cookie_name);

		// No cookie?  Goodbye cruel world!...
		if ($session === FALSE)
		{
			log_message('debug', 'A session cookie was not found.');
			return FALSE;
		}

		// Decrypt the cookie data
		if ($this->sess_encrypt_cookie == TRUE)
		{
			$session = $this->CI->encrypt->decode($session);
		}
		else
		{
			// encryption was not used, so we need to check the md5 hash
			$hash	 = substr($session, strlen($session)-32); // get last 32 chars
			$session = substr($session, 0, strlen($session)-32);

			// Does the md5 hash match?  This is to prevent manipulation of session data in userspace
			if ($hash !==  md5($session.$this->encryption_key))
			{
				log_message('error', 'The session cookie data did not match what was expected. This could be a possible hacking attempt.');
				$this->sess_destroy();
				return FALSE;
			}
		}

		// Unserialize the session array
		$session = $this->parent->_unserialize($session);

		// Is the session data we unserialized an array with the correct format?
		if ( ! is_array($session) OR ! isset($session['session_id']) OR ! isset($session['ip_address']) OR ! isset($session['user_agent']) OR ! isset($session['last_activity']))
		{
			$this->sess_destroy();
			return FALSE;
		}

		// Is the session current?
		if (($session['last_activity'] + $this->parent->sess_expiration) < $this->parent->now)
		{
			$this->sess_destroy();
			return FALSE;
		}

		// Does the IP Match?
		if ($this->parent->sess_match_ip == TRUE AND $session['ip_address'] != $this->CI->input->ip_address())
		{
			$this->sess_destroy();
			return FALSE;
		}

		// Does the User Agent Match?
		if ($this->parent->sess_match_useragent == TRUE AND trim($session['user_agent']) != trim(substr($this->CI->input->user_agent(), 0, 120)))
		{
			$this->sess_destroy();
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
		$this->_set_cookie();
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
		$sessid = '';
		while (strlen($sessid) < 32)
		{
			$sessid .= mt_rand(0, mt_getrandmax());
		}

		// To make the session ID even more secure we'll combine it with the user's IP
		$sessid .= $this->CI->input->ip_address();

		$this->parent->userdata = array(
			'session_id'	=> md5(uniqid($sessid, TRUE)),
			'ip_address'	=> $this->CI->input->ip_address(),
			'user_agent'	=> substr($this->CI->input->user_agent(), 0, 120),
			'last_activity'	=> $this->parent->now
		);


		// Write the cookie
		$this->_set_cookie();
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

		// Save the old session id so we know which record to
		// update in the database if we need it
		$old_sessid = $this->parent->userdata['session_id'];
		$new_sessid = '';
		while (strlen($new_sessid) < 32)
		{
			$new_sessid .= mt_rand(0, mt_getrandmax());
		}

		// To make the session ID even more secure we'll combine it with the user's IP
		$new_sessid .= $this->CI->input->ip_address();

		// Turn it into a hash
		$new_sessid = md5(uniqid($new_sessid, TRUE));

		// Update the session data in the session data array
		$this->parent->userdata['session_id'] = $new_sessid;
		$this->parent->userdata['last_activity'] = $this->parent->now;

		// Write the cookie
		$this->_set_cookie();
	}

	// --------------------------------------------------------------------

	/**
	 * Destroy the current session
	 *
	 * @access	public
	 * @return	void
	 */
	public function sess_destroy()
	{
		$this->parent->userdata = array();

		// Kill the cookie
		setcookie(
					$this->sess_cookie_name,
					addslashes(serialize(array())),
					($this->parent->now - 31500000),
					$this->cookie_path,
					$this->cookie_domain,
					0
				);
	}

	// --------------------------------------------------------------------

	/**
	 * Write the session cookie
	 *
	 * @access	private
	 * @return	void
	 */
	protected function _set_cookie()
	{
		$cookie_data = $this->parent->userdata;

		// Serialize the userdata for the cookie
		$cookie_data = $this->parent->_serialize($cookie_data);

		if ($this->sess_encrypt_cookie == TRUE)
		{
			$cookie_data = $this->CI->encrypt->encode($cookie_data);
		}
		else
		{
			// if encryption is not used, we provide an md5 hash to prevent userside tampering
			$cookie_data = $cookie_data.md5($cookie_data.$this->parent->encryption_key);
		}

		$expire = ($this->parent->sess_expire_on_close === TRUE) ? 0 : $this->parent->sess_expiration + time();

		// Set the cookie
		setcookie(
					$this->sess_cookie_name,
					$cookie_data,
					$expire,
					$this->cookie_path,
					$this->cookie_domain,
					$this->cookie_secure
				);
	}
	
	// --------------------------------------------------------------------
	
	/**
	 * Does nothing for cookie sessions
	 *
	 * @access private
	 * @return void
	 */
	public function _sess_gc(){}

	// --------------------------------------------------------------------

}