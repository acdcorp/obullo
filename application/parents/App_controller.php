<?php
defined('BASE') or exit('Access Denied!');
                                  
/**
* Global Application Controller
*/
Class App_controller 
{
    public $base, $base_url, $base_img;
    public $title, $head, $meta, $body;
    public $body_attributes = ''; 
    
    /**
    * Global Autoloader
    */
    function __autoloader()
    {         
        $this->config->auto_base_url(true);
        
        $this->base     = $this->config->base_url();
        $this->base_url = $this->config->site_url();
        $this->base_img = $this->config->source_url() . 'images/';   
    } 
}

/* End of file App_controller.php */
/* Location: ./application/parents/App_controller.php */
?>