<?php
defined('BASE') or exit('Access Denied!');

/**
 * Obullo Framework (c) 2009.
 *
 * PHP5 MVC Based Minimalist Software.
 * 
 * @package         obullo       
 * @author          obullo.com
 * @copyright       Ersin Guvenc (c) 2009.
 * @filesource
 * @license
 */
 
Class LangException extends CommonException {}

/**
 * Obullo Language Helper
 *
 * @package     Obullo
 * @subpackage  Helpers
 * @category    Language
 * @author      Ersin Guvenc
 * @link        
 */
 
$_la = ssc::instance();
$_la->_ng = new stdClass();

$_la->_ng->language  = array();
$_la->_ng->is_loaded = array();

log_message('debug', "Language Helper Initialized");

// --------------------------------------------------------------------

/**
* Load a language file
*
* @access   public
* @param    mixed    the name of the language file to be loaded. Can be an array
* @param    string   the language (english, etc.)
* @return   mixed
*/
function lang_load($langfile = '', $idiom = '', $dir = 'base', $return = FALSE)
{     
    $_la = ssc::instance();
    
    if (in_array($langfile, $_la->_ng->is_loaded, TRUE))
    return;  
    
    if ($idiom == '')
    {
        $deft_lang = ob::instance()->config->item('language');
        $idiom = ($deft_lang == '') ? 'english' : $deft_lang;
    }
    
    switch ($dir)
    {
        case 'local':
         $folder = DIR .$GLOBALS['d']. DS .'lang'. DS;                            
         break;
        
        case 'global':
         $folder = APP .'lang'. DS .$idiom. DS;
         break;
         
        case 'base':
         $folder = BASE.'lang'. DS .$idiom. DS;  
         break;
    }

    if( ! is_dir($folder))
    return;
    
    $lang = get_static($langfile, 'lang', $folder);
    
    if ( ! isset($lang))
    {
        log_message('error', 'Language file contains no data: lang/' .$idiom. '/'. $langfile. EXT);
        return;
    }

    if ($return)
    return $lang;

    $_la->_ng->is_loaded[] = $langfile;
    $_la->_ng->language    = array_merge($_la->_ng->language, $lang);
    unset($lang);

    log_message('debug', 'Language file loaded: lang/' .$idiom. '/' .$langfile. EXT);
    return TRUE;
}

/**
* Fetch a item of text from the language array
*
* @access   public
* @param    string  $item the language item
* @return   string
*/
function lang_item($item = '')
{
    $_la = ssc::instance();
    
    $item = ($item == '' OR ! isset($_la->_ng->language[$item])) ? FALSE : $_la->_ng->language[$item];
    return $item;
}

/* End of file lang.php */
/* Location: ./base/helpers/lang.php */
?>