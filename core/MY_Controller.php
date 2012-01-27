<?php

class MY_Controller extends CI_Controller {

    public function _output($output)
    {
    	if(isset($this->session) && method_exists($this->session, 'sess_write'))
    	{
        	$this->session->sess_write();
        }
        echo $output;
    }

}