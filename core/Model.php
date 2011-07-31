<?php
defined('BASE') or exit('Access Denied!');

/**
 * Obullo Framework (c) 2009.
 *
 * PHP5 MVC Based Minimalist Software.
 *
 * @package         Obullo
 * @author          Obullo.com
 * @subpackage      Base.libraries
 * @copyright       Copyright (c) 2009 Ersin Guvenc.
 * @license
 * @since           Version 1.0
 * @filesource
 */

/**
 * Model Class.
 *
 * Main model class.
 *
 * @package         Obullo
 * @subpackage      Obullo.core
 * @category        Core Model
 * @version         0.1
 * @version         0.2 added extend to ob
 * @version         0.3 depreciated get_object_vars, added _assing_db_objects
 * @version         0.4 added profiler_get('databases'); func.
 */

Class Model {

    public function __construct()
    {
        $this->_assign_db_objects();

        log_me('debug', "Model Class Initialized");
    }

    /**
    * Assign all db objects to all Models.
    *
    * Very bad idea assign all library objects to model !!!
    * We assign just db objects. -- Ersin
    */
    public function _assign_db_objects()
    {
        $OB = this();

        foreach(profiler_get('databases') as $db_name => $db_var)
        {
            if(method_exists($this, '__get') OR method_exists($this, '__set'))
            {
                if(isset($OB->$db_var) AND is_object($OB->$db_var))
                {
                    $this->$db_var = $OB->$db_var;  // to prevent some reference errors
                }
            }
            else
            {
                if(isset($OB->$db_var) AND is_object($OB->$db_var))
                {
                    $this->$db_var = &$OB->$db_var;  // to prevent some reference errors
                }
            }
        }
    }
}

// END Model Class

/* End of file Model.php */
/* Location: ./obullo/core/Model.php */
