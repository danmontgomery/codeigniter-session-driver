<?php

class Session_database extends CI_Driver {

	protected $CI;

	protected $sess_cookie_name;
	protected $sess_encrypt_cookie;
	protected $cookie_prefix;
	protected $cookie_path;
	protected $cookie_domain;
	protected $cookie_secure;
	protected $sess_table_name;

	/**
	 * Set necessary config options
	 *
	 * @access public
	 * @return void
	 */
	public function __construct()
	{
		$this->CI = get_instance();

		foreach (array('sess_encrypt_cookie','sess_table_name','sess_cookie_name','cookie_prefix','cookie_path','cookie_domain','cookie_secure') as $key)
		{
			$this->$key = $this->CI->config->item($key);
		}

		// Do we need encryption? If so, load the encryption class
		if ($this->sess_encrypt_cookie == TRUE)
		{
			$this->CI->load->library('encrypt');
		}

		$this->CI->load->database();
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
			if ($hash !==  md5($session.$this->parent->encryption_key))
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

		// Is there a corresponding session in the DB?
		$this->CI->db->where('session_id', $session['session_id']);

		if ($this->parent->sess_match_ip == TRUE)
		{
			$this->CI->db->where('ip_address', $session['ip_address']);
		}

		if ($this->parent->sess_match_useragent == TRUE)
		{
			$this->CI->db->where('user_agent', $session['user_agent']);
		}

		$query = $this->CI->db->get($this->sess_table_name);

		// No result?  Kill it!
		if ($query->num_rows() == 0)
		{
			$this->sess_destroy();
			return FALSE;
		}

		// Is there custom data?  If so, add it to the main session array
		$row = $query->row();
		if (isset($row->user_data) AND $row->user_data != '')
		{
			$custom_data = $this->parent->_unserialize($row->user_data);

			if (is_array($custom_data))
			{
				foreach ($custom_data as $key => $val)
				{
					$session[$key] = $val;
				}
			}
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
		// set the custom userdata, the session data we will set in a second
		$custom_userdata = $this->parent->userdata;
		$cookie_userdata = array();

		// Before continuing, we need to determine if there is any custom data to deal with.
		// Let's determine this by removing the default indexes to see if there's anything left in the array
		// and set the session data while we're at it
		foreach (array('session_id','ip_address','user_agent','last_activity') as $val)
		{
			unset($custom_userdata[$val]);
			$cookie_userdata[$val] = $this->parent->userdata[$val];
		}

		// Did we find any custom data?  If not, we turn the empty array into a string
		// since there's no reason to serialize and store an empty array in the DB
		if (count($custom_userdata) === 0)
		{
			$custom_userdata = '';
		}
		else
		{
			// Serialize the custom data array so we can store it
			$custom_userdata = $this->parent->_serialize($custom_userdata);
		}

		// Run the update query
		$this->CI->db->where('session_id', $this->parent->userdata['session_id']);
		$this->CI->db->update($this->sess_table_name, array('last_activity' => $this->parent->userdata['last_activity'], 'user_data' => $custom_userdata));

		// Write the cookie.  Notice that we manually pass the cookie data array to the
		// _set_cookie() function. Normally that function will store $this->userdata, but
		// in this case that array contains custom data, which we do not want in the cookie.
		$this->_set_cookie($cookie_userdata);
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

		$custom_userdata = array('user_data' => '');


		// Save the data to the DB
		$this->CI->db->query($this->CI->db->insert_string($this->sess_table_name, $this->parent->userdata+$custom_userdata));

		// Write the cookie
		$this->_set_cookie($this->parent->userdata);
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
		$this->parent->userdata['last_activity'] = $this->now;

		// set cookie explicitly to only have our session data
		$cookie_data = array();
		foreach (array('session_id','ip_address','user_agent','last_activity') as $val)
		{
			$cookie_data[$val] = $this->parent->userdata[$val];
		}

		$this->CI->db->query($this->CI->db->update_string($this->sess_table_name, array('last_activity' => $this->parent->now, 'session_id' => $new_sessid), array('session_id' => $old_sessid)));

		// Write the cookie
		$this->_set_cookie($cookie_data);
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
		// Kill the session DB row
		if (isset($this->parent->userdata['session_id']))
		{
			$this->CI->db->where('session_id', $this->parent->userdata['session_id']);
			$this->CI->db->delete($this->sess_table_name);
		}

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
	 * Clean up old session records
	 *
	 * @access private
	 * @return void
	 */
	public function _sess_gc()
	{
		srand(time());
		if ((rand() % 100) < $this->gc_probability)
		{
			$expire = $this->parent->now - $this->parent->sess_expiration;

			$this->CI->db->where("last_activity < {$expire}");
			$this->CI->db->delete($this->sess_table_name);

			log_message('debug', 'Session garbage collection performed.');
		}
	}

	// --------------------------------------------------------------------

	/**
	 * Write the session cookie
	 *
	 * @access	private
	 * @return	void
	 */
	protected function _set_cookie($cookie_data)
	{
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

}