<?php
defined('BASE') or exit('Access Denied!');

/**
 * Obullo Framework (c) 2009.
 *
 * PHP5 MVC Based Minimalist Software.
 *
 * @package         obullo
 * @subpackage      Libraries
 * @category        Libraries      
 * @author          obullo.com
 * @copyright       Ersin Güvenç (c) 2009.
 * @since           Version 1.0
 * @filesource
 * @license 
 */
 
Abstract Class Obullo_Registry
{
    abstract protected function get($key);
    //get stored object.
    abstract protected function set($key,$val);
    //set (store) object.
} 
 
Class OB_Registry extends Obullo_Registry {
    
    /** 
    * Registry array of objects 
    * @access private 
    */  
    private static $objs = array();
    
    /** 
    * The instance of the registry 
    * @access private 
    */  
    private static $instance;
    
    //prevent directly access.
    private function __construct(){}
    
    //prevent clone. 
    public function __clone(){}
    
    /** 
    * singleton method used to access the object 
    * @access public 
    */  
    public static function singleton() 
    {
        if( ! isset(self::$instance))
        {
            self::$instance = new self();
        } 
        return self::$instance;
    }
    
    protected function get($key)
    {
        if(isset(self::$objs[$key]))
        {
            return self::$objs[$key];
        }
        return NULL;
    }


    protected function set($key,$val)
    {
        self::$objs[$key] = $val;
    }

    //static get request handle
    public static function getObject($key)
    {
        return self::singleton()->get($key);
    }

    //store object
    public static function storeObject($key, $instance)
    {
        return self::singleton()->set($key,$instance);
    }

}

// END Registry Class

/* End of file Registry.php */
/* Location: ./base/obullo/Registry.php */

?>
