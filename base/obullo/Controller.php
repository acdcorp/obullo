<?php
defined('BASE') or exit('Access Denied!');

/**
 * Obullo Framework (c) 2009.
 *
 * PHP5 MVC Based Minimalist Software.
 *
 * @package         obullo    
 * @author          obullo.com
 * @copyright       Ersin Güvenç (c) 2009.
 * @since           Version 1.0
 * @filesource
 * @license
 */

 /**
 * Obullo Controller
 * 
 * @package         Obullo 
 * @subpackage      Base.libraries     
 * @category        Libraries
 * @version         1.0
 * @version         1.1 renamed Register as base_register
 * @version         1.2 added 'extends to ob'
 * @version         1.3 added __autoloader()
 * @version         1.4 removed __autoloader()
 * @version         1.5 added loader::shortcut()
 * @version         1.6 added base class public variables, @deprecated      self::__autoloader()
 * @version         1.7 removed obullo style writing func because of we added spl_autoload_register func.
 * 
 */   
 
Class Controller extends ob {
    
    /**
    * Base class public
    * variables
    * @var mixed
    */
    public $config;
    public $input;
    public $benchmark;
    public $lang;
    public $router;
    public $uri;
    public $output;
    
    public function __construct()       
    {   
        // Be carefull. parent::__construct() must be at the top otherwise
        // __autoloader functionality does not work.
        parent::__construct();
           
        $this->_ob_init();
        
        log_message('debug', "Controller Class Initialized");
    }

    /**
    * Initialize to default base libraries.
    * 
    * @author   Ersin Güvenç
    * @return   void
    */
    private function _ob_init()
    {
        $Classes = array(                         
                            'config'    => 'Config',
                            'input'     => 'Input',
                            'benchmark' => 'Benchmark',
                            'lang'      => 'Lang',
                            'router'    => 'Router',
                            'uri'       => 'URI', 
                            'output'    => 'Output' 
                        );
                        

        foreach ($Classes as $public_var => $Class)
        {
            $this->$public_var = base_register($Class);
        }

    } 
    
}

// END Controller Class

/* End of file Controller.php */
/* Location: ./base/obullo/Controller.php */

?>
