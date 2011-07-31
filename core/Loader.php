<?php
defined('BASE') or exit('Access Denied!');

/**
 * Obullo Framework (c) 2009 - 2010.
 *
 * PHP5 MVC Based Minimalist Software.
 *
 * @package         Obullo
 * @author          Obullo.com
 * @subpackage      Obullo.core
 * @copyright       Copyright (c) 2009 Ersin Guvenc.
 * @license
 * @filesource
 */

/**
 * Loader Class (Obullo Loader) (c) 2009 - 2010
 * Load Obullo library, model, config, lang and any other files ...
 */

Class LoaderException extends CommonException {}

Class OB_Loader {

    /**
    * Track "local" helper files.
    * @var array
    */
    public static $_helpers      = array();

    /**
    * Track "base" helper files.
    * @var array
    */
    public static $_base_helpers = array();

    /**
    * Track "application" helper files.
    * @var array
    */
    public static $_app_helpers  = array();

    /**
    * Track "external" files.
    * @var array
    */
    public static $_files        = array();

    /**
    * loader::lib();
    *
    * load libraries from /module folder. (current module)
    *
    * @param    mixed $class
    * @param    mixed $params_or_no_ins array | null | false
    * @param    string $object_name
    * @param    boolean $new_instance create new instance
    * @return   self::_library()
    */
    public static function lib($class = '', $params_or_no_ins = '', $object_name = '', $new_instance = FALSE)
    {
        if(strpos($class, 'ob/') === 0)
        {
            return lib(substr($class, 3), $params_or_no_ins, $new_instance);
        }

        if(strpos($class, 'app/') === 0)
        {
            return self::app_lib(substr($class, 4), $params_or_no_ins, $object_name, $new_instance);
        }

        if(strpos($class, 'ext/') === 0)
        {
            return self::ext(substr($class, 4), $params_or_no_ins, $object_name, $new_instance);
        }

        self::_library($class, $params_or_no_ins, $object_name, $new_instance);
    }

    // --------------------------------------------------------------------

    /**
    * loader::app_lib();
    *
    * load libraries from /application folder.
    *
    * @param    mixed $class
    * @param    mixed $params_or_no_ins array | null | false
    * @param    string $object_name
    * @param    boolean $new_instance create new instance
    * @return   self::_library()
    */
    public static function app_lib($class = '', $params_or_no_ins = '', $object_name = '', $new_instance = FALSE)
    {
        self::_library($class, $params_or_no_ins, $object_name, $new_instance, TRUE);
    }

    // --------------------------------------------------------------------

    /**
    * loader::ext();
    *
    * load extension library from /modules folder.
    *
    * @param    mixed $class
    * @param    mixed $params_or_no_ins array | null | false
    * @param    string $object_name
    * @param    boolean $new_instance create new instance
    * @return   self::_library()
    */
    public static function ext($class = '', $params_or_no_ins = '', $object_name = '', $new_instance = FALSE)
    {
        self::_library($class, $params_or_no_ins, $object_name, $new_instance, FALSE, $extension = TRUE);
    }

    // --------------------------------------------------------------------

    /**
    * Obullo Library Loader.
    *
    * @author   Ersin Guvenc
    * @param    string $class class name
    * @param    array | boolean $params_or_no_ins __construct() params  | or | No Instantiate
    * @param    boolean $new_instance create new instance
    *
    * @return   void
    */
    private static function _library($class, $params_or_no_ins = '', $object_name = '', $new_instance = FALSE, $app_folder = FALSE, $ext = FALSE)
    {
        if($class == '') return FALSE;

        if($params_or_no_ins === TRUE AND $ext == TRUE)  // extension helper file.
        {
            self::helper($class, 'helpers', TRUE);

            return;  // If file helper extension return.
        }

        $OB = this();  // Grab the Super Object.

        $profiler_type  = ($ext) ? 'extensions' : 'libraries';
        $case_sensitive = ($params_or_no_ins == FALSE) ? TRUE : FALSE;

        $data = self::_load_file($class, $folder = 'libraries', $app_folder, $ext, $case_sensitive);

        $class_var = '';

        if( file_exists($data['file']))
        {
            require_once($data['file']);

            $class_var = strtolower($data['file_name']);

            if($object_name != '') $class_var = $object_name;

            if(is_array($params_or_no_ins))
            {
                // HMVC CRAZY BUG !!
                // If someone use HMVC we need to create new instance() foreach Library
                if(core_register('Router')->hmvc == FALSE AND $new_instance == FALSE)
                {
                    if (isset($OB->$class_var) AND is_object($OB->$class_var)) { return; }
                }

                if(class_exists($data['file_name']))
                {
                    $OB->$class_var = new $data['file_name']($params_or_no_ins);
                }

                profiler_set($profiler_type, $class_var, $class_var);

                return;
            }
            elseif($params_or_no_ins === FALSE)
            {
                profiler_set($profiler_type, $class_var, $class_var);

                return;
            }
            else
            {
                if (isset($OB->$class_var) AND is_object($OB->$class_var)) { return; }

                if(class_exists($data['file_name']))
                {
                    $OB->$class_var = new $data['file_name']();
                }

                profiler_set($profiler_type, $class_var, $class_var);

                return;
            }
        }

        $type = ($ext) ? 'extension' : 'library';

        throw new LoaderException('Unable to locate the '.$type.' file: '. $data['file']);
    }

    // --------------------------------------------------------------------

    /**
    * loader::app_model();
    *
    * @author   Ersin Guvenc
    * @param    string $model
    * @param    string $object_name
    * @param    array | boolean $params_or_no_ins (construct params) | or | No Instantiate just include file
    * @param    boolean $new_instance create new instance
    * @return   void
    */
    public static function app_model($model, $object_name = '', $params_or_no_ins = '', $new_instance = FALSE)
    {
        $data = self::_load_file($model, $folder = 'models', $app_folder = TRUE);

        self::_model($data['file'], $data['file_name'], $object_name, $params_or_no_ins, $new_instance);
    }

    // --------------------------------------------------------------------

    /**
    * loader::model();
    * loader::model('subfolder/model_name')  local sub folder load
    * loader::model('../outside_folder/model_name')  outside directory load
    *
    * @author    Ersin Guvenc
    * @param     string $model
    * @param     string $object_name
    * @param     array | boolean $params (construct params) | or | Not Instantiate just include file
    * @return    void
    */
    public static function model($model, $object_name = '', $params_or_no_ins = '', $new_instance = FALSE)
    {
        if(strpos($model, 'app/') === 0)
        {
            return loader::app_model(substr($model, 4), $object_name, $params_or_no_ins, $new_instance);
        }

        $data = self::_load_file($model, $folder = 'models', FALSE);

        self::_model($data['file'], $data['file_name'], $object_name, $params_or_no_ins, $new_instance);
    }

    // --------------------------------------------------------------------

    /**
    * Load _model
    *
    * @access    private
    * @param     string $file
    * @param     string $model_name
    * @param     string $object_name
    * @param     array | boolean  $params_or_no_ins
    * @param     boolean $new_instance  create new instance
    * @version   0.1
    * @version   0.2 added params_or_no_ins instantiate switch ,added Ssc::instance()->_profiler_mods
    * @version   0.3 added profiler_set function
    * @version   0.4 HMVC bug fixed.
    */
    private static function _model($file, $model_name, $object_name = '', $params_or_no_ins = '', $new_instance = FALSE)
    {
        if ( ! file_exists($file))
        {
            throw new LoaderException('Unable to locate the model: '.$file);
        }

        $model_var = $model_name;
        if($object_name != '' OR $object_name != NULL) $model_var = $object_name;

        $OB = this();

        // HMVC CRAZY BUG !!
        // If someone use HMVC we need to create new instance() foreach Model
        if(core_register('Router')->hmvc == FALSE AND $new_instance == FALSE)
        {
            if (isset($OB->$model_var) AND is_object($OB->$model_var)) { return; }
        }

        require_once($file);
        $model = ucfirst($model_name);

        if($params_or_no_ins === FALSE)
        {
            profiler_set('models', $model_var.'_no_instantiate', $model_name);
            return;
        }

        if( ! class_exists($model, false)) // autoload false.
        {
            throw new LoaderException('You have a small problem, model name isn\'t right in here: '.$model);
        }

        // store loaded obullo models
        profiler_set('models', $model_var, $model_var);     // should be above the new model();

        $OB->$model_var = new $model($params_or_no_ins);    // register($class); we don't need it

        // assign all loaded db objects inside to current model
        // loader::database() support for Model_x { function __construct() { loader::database() }}
        $OB->$model_var->_assign_db_objects();

    }

    // --------------------------------------------------------------------

    /**
    * loader::database();
    *
    * Database load.
    * This function loads the database for controllers
    * and model files.
    *
    * @author   Ersin Guvenc
    * @param    mixed $db_name for manual connection
    * @param    boolean $return_object return to db object switch
    * @param    boolean $use_active_record active record switch
    * @return   void
    */
    public static function database($db_name = 'db', $return_object = FALSE, $use_active_record = TRUE)
    {
        $OB = this();

        $db_var = (empty($db_name)) ? 'db' : $db_name;

        if(is_array($db_name) AND isset($db_name['variable']))
        {
            $db_var = $db_name['variable'];
        }

        if (isset($OB->{$db_var}) AND is_object($OB->{$db_var}))
        {
            if($return_object)
              return $OB->{$db_var};

            return;
        }

        if(!isset($GLOBALS['__DATABASE__'.$db_name]))
        {
          $GLOBALS['__DATABASE__'.$db_name] = OB_DBFactory::Connect($db_name, $db_var, $use_active_record);   // Connect to Database
          profiler_set('databases', $db_name, $db_var);  // Store db variables
          if(!$return_object) self::_assign_db_objects($db_var);
        }

        if($return_object) return $GLOBALS['__DATABASE__'.$db_name];
        $OB->{$db_var}= $GLOBALS['__DATABASE__'.$db_name];
    }

    // --------------------------------------------------------------------

    /**
    * About App_ prefix we need to use it because of
    * it prevent filename collisions in some loader functions.
    */

    /**
    * loader::app_helper();
    *
    * loader::app_helper('subfolder/helper_name')  local sub folder load
    * loader::app_helper('../outside_folder/helper_name')  outside directory load
    *
    * @param    string $helper
    */
    public static function app_helper($helper)
    {
        if( isset(self::$_app_helpers[$helper]) )
        {
            return;
        }

        $data = self::_load_file($helper, $folder = 'helpers', $app_folder = TRUE);

        if(file_exists($data['file']))
        {
            include($data['file']);

            self::$_app_helpers[$helper] = $helper;

            return;
        }

        throw new LoaderException('Unable to locate the application helper: ' .$data['file']);
    }

    // --------------------------------------------------------------------

    /**
    * loader::helper();
    *
    * loader::helper('subfolder/helper_name')  local sub folder load
    * loader::helper('../outside_folder/helper_name')  outside directory load
    *
    * We have three helper directories
    *   o Base/helpers  : /base helpers
    *   o App/helpers   : /application helpers
    *   o Local/helpers : /directiories/$directory/ helpers
    *
    * @author   Ersin Guvenc
    * @param    string $helper
    * @return   void
    */
    public static function helper($helper, $func = 'helper', $is_extension = FALSE)
    {
        if(strpos($helper, 'ob/') === 0)
        {
            return loader::base_helper(substr($helper, 3));
        }

        if(strpos($helper, 'app/') === 0)
        {
            return loader::app_helper(substr($helper, 4));
        }

        if( isset(self::$_helpers[$helper]) )
        {
            return;
        }

        if($is_extension)
        {
             $data = self::_load_file($helper, $folder = 'helpers', FALSE, TRUE);
        }
        else
        {
             $data = self::_load_file($helper, $folder = 'helpers');
        }

        if(file_exists($data['file']))
        {
            include($data['file']);

            self::$_helpers[$helper] = $helper;

            return;
        }

        throw new LoaderException('Unable to locate the helper: '.$data['file']);
    }

    // --------------------------------------------------------------------

    /**
    * loader::core_helper();
    *
    * Load the Obullo core helpers
    *
    * @access   private
    * @param    string $helper
    */
    public static function core_helper($helper)
    {
        self::base_helper($helper, TRUE);
    }

    // --------------------------------------------------------------------

    /**
    * loader::base_helper();
    *
    * @author   Ersin Guvenc
    * @param    string $helper
    * @return   void
    */
    public static function base_helper($helper, $core = FALSE)
    {
        if( isset(self::$_base_helpers[$helper]) )
        {
            return;
        }

        $core_path = ($core) ? 'core'. DS : '';

        if(file_exists(BASE .'helpers'. DS . $core_path . $helper. EXT))
        {
            $prefix = config_item('subhelper_prefix');

            $extensions = get_config('extensions');
            $extension_helper_override = FALSE;

            if(is_array($extensions))
            {
                foreach($extensions as $name => $array)   // Extension Override Support
                {
                    foreach($array as $ext_name => $options)           // Parse values.
                    {
                        if(isset($options['helper_override']) AND is_array($options['helper_override']))
                        {
                            foreach($options['helper_override'] as $helper_override)
                            {
                                if($helper_override == $helper)
                                {
                                    $extension_helper_override = TRUE;
                                    $extension = $ext_name;
                                }
                            }
                        }
                    }
                }
            }

            $module = (isset($GLOBALS['d'])) ? $GLOBALS['d'] : core_register('Router')->fetch_directory();

            if($extension_helper_override)
            {
                if(is_extension($extension, $module))  // if extension enabled ..
                {
                    $module = $extension;
                }
            }

            if(file_exists(MODULES .$module. DS .'helpers'. DS .$prefix. $helper. EXT))  // module extend support.
            {
                include(MODULES .$module. DS .'helpers'. DS .$prefix. $helper. EXT);

                self::$_base_helpers[$prefix . $helper] = $prefix . $helper;
            }
            elseif(file_exists(APP .'helpers'. DS .$prefix. $helper. EXT))  // If app helper my_file exist.
            {
                include(APP .'helpers'. DS .$prefix. $helper. EXT);

                self::$_base_helpers[$prefix . $helper] = $prefix . $helper;
            }

            include(BASE .'helpers'. DS .$core_path . $helper. EXT);

            self::$_base_helpers[$helper] = $helper;

            return;
        }

        $type = ($core) ? 'core' : 'base';

        throw new LoaderException('Unable to locate the '.$type.' helper: ' .$helper. EXT);
    }

    // --------------------------------------------------------------------

    /**
    * Just alias of base_helper()
    *
    * @param string $helper
    * @return void
    */
    public static function ob_helper($helper)
    {
        return self::base_helper($helper);
    }

    // --------------------------------------------------------------------

    public static function lang($file, $folder = '', $return = FALSE)
    {
        if(strpos($file, 'ob/') === 0)
        {
            return self::base_lang(substr($file, 3), $folder, $return);
        }

        lang_load($file, $folder, NULL, $return);
    }

    // ------------------------------------------------------------------

    public static function base_lang($file = '', $folder = '', $return = FALSE)
    {
        lang_load($file, $folder, 'base' ,$return);
    }

    // ------------------------------------------------------------------

    public static function ob_lang($file = '', $folder = '', $return = FALSE)
    {
        return self::base_lang($file, $folder, 'base' ,$return);
    }

    // --------------------------------------------------------------------

    public static function config($file, $use_sections = FALSE, $fail_gracefully = FALSE)
    {
        core_register('Config')->load($file, $use_sections, $fail_gracefully);
    }

    // --------------------------------------------------------------------

    /**
    * Load a file from ROOT directory.
    *
    * @access   public
    * @param    string $file filename
    * @return   void
    */
    public static function file($path, $string = FALSE, $ROOT = APP)
    {
        if( isset(self::$_files[$path]) )
        return;

        if(file_exists($ROOT .$path))
        {
            self::$_files[$path] = $path;

            log_me('debug', 'External file loaded: '.$path);

            profiler_set('files', $path, $ROOT . $path);  // store into profiler

            if($string === TRUE)
            {
                ob_start();
                include_once($ROOT .$path);

                $content = ob_get_contents();
                @ob_end_clean();

                return $content;
            }

            require_once($ROOT .$path);
            return;
        }

        throw new LoaderException('Unable to locate the external file: ' .$path);
    }


    // --------------------------------------------------------------------

    /**
    * Common file loader for models and
    * helpers functions.
    *
    * @author  Ersin Guvenc
    *
    * @param string $filename
    * @param string $folder
    * @param string $loader_func
    *
    * return array  file_name | file
    */
    private static function _load_file($filename, $folder = 'helpers', $app_folder = FALSE, $extension = FALSE, $case_sensitive = FALSE)
    {
        $real_name  = ($case_sensitive) ? $filename : strtolower($filename);
        $root       = rtrim(MODULES, DS);

        if($extension)  // main extension library or helper file.
        {
            $return['file_name'] = $real_name;
            $return['file']      = MODULES . $real_name . DS . $real_name. EXT;

            return $return;
        }

        $sub_root   = $GLOBALS['d']. DS .$folder. DS;
        if($app_folder)
        {
            $root     = APP . $folder;
            $sub_root = '';
        }

        if(strpos($real_name, '../') === 0)   // ../module folder request
        {
            $paths      = explode('/', substr($real_name, 3));
            $file_name  = array_pop($paths);         // get file name
            $modulename = array_shift($paths);       // get module name

            $sub_path   = '';
            if( count($paths) > 0)
            {
                $sub_path = implode(DS, $paths) . DS;      // .public/css/sub/welcome.css  sub dir support
            }

            $file = MODULES . $modulename . DS . $folder . DS . $sub_path . $file_name. EXT;

            $return['file_name'] = $file_name;
            $return['file']      = $file;

            return $return;
        }

        if(strpos($real_name, '/') > 0)         //  inside folder request
        {
            $paths      = explode('/',$real_name);   // paths[0] = path , [1] file name
            $file_name  = array_pop($paths);          // get file name
            $path       = implode(DS, $paths);

            $return['file_name'] = $file_name;
            $return['file']      = $root. DS .$sub_root. $path. DS .$file_name. EXT;

            return $return;
        }


        return array('file_name' => $real_name, 'file' => $root. DS .$sub_root. $real_name. EXT);
    }

    // --------------------------------------------------------------------

    public static function req($file = '')
    {
        if($file == '') return;

        self::_library($file, FALSE, '', FALSE);
    }

    // @todo
    public static function inc($file = '')
    {

    }

    // --------------------------------------------------------------------

    /**
    * Assign db objects to all Models
    *
    * @author  Ersin Guvenc
    * @param   string $db_var
    * @return  void
    */
    private static function _assign_db_objects($db_var = '')
    {
        $models = profiler_get('models');

        $OB = this();

        if (count($models) == 0) return;

        foreach ($models as $model_name)
        {
          if( ! isset($OB->$model_name) ) return;
          if(is_object($OB->$model_name->$db_var))
          {
            return;
          }
          if(is_object($OB->$db_var))
          {
              $OB->$model_name->$db_var = $OB->$db_var;
          }
        }

    }

}

// END Loader Class

/* End of file Loader.php */
/* Location: ./obullo/core/Loader.php */
