<?php
        
/**
 * Obullo Framework (c) 2009.
 *
 * PHP5 MVC-min Software for PHP 5.2.4 or newer
 * Derived from Code Igniter.
 * 
 * @package         obullo
 * @filesource      index.php        
 * @author          obullo.com
 * @copyright       Ersin Güvenç (c) 2009.
 * @since           Version 1.0 @alpha
 * @license         http://www.opensource.org/licenses/gpl-3.0.html GPL 
 */
 
/* ---------------------------------------------------------------------------*/                               

// This function just for memory testing..
function OB_memory_usage() {
$usage = '';
 
        $mem_usage = memory_get_usage(true); 
        
        if ($mem_usage < 1024) 
            $usage =  $mem_usage." bytes"; 
        elseif ($mem_usage < 1048576) 
            $usage = round($mem_usage/1024,2)." kilobytes"; 
        else 
            $usage = round($mem_usage/1048576,2)." megabytes"; 
            
        return $usage;
} 

// start memory test
//$start = OB_memory_usage();
$start = memory_get_usage();

header('Content-type: text/html;charset=UTF-8'); 
/* 
try 
{
*/
$controller = "test";    
$class  = ucfirst(strtolower($controller));
$method = "run"; 

$GLOBALS['controller'] = strtolower($controller);
$GLOBALS['method'] = strtolower($method);

// Base paths
define('BASE', 'base'.DIRECTORY_SEPARATOR);            
define('APP',  'application'.DIRECTORY_SEPARATOR);   
define('EXT',  '.php');                                
define('MODEL', 'application'.DIRECTORY_SEPARATOR.'controllers'.DIRECTORY_SEPARATOR.$GLOBALS['controller'].DIRECTORY_SEPARATOR);
define('VIEW', 'application'.DIRECTORY_SEPARATOR.'controllers'.DIRECTORY_SEPARATOR.$GLOBALS['controller'].DIRECTORY_SEPARATOR);
define('CONTROLLER', 'application'.DIRECTORY_SEPARATOR.'controllers'.DIRECTORY_SEPARATOR.$GLOBALS['controller'].DIRECTORY_SEPARATOR);
define('CONTROLLER_PATH', 'application'.DIRECTORY_SEPARATOR.'controllers'.DIRECTORY_SEPARATOR);

// Very Important Base Libraries
// Don't change classes order.
require (BASE.DIRECTORY_SEPARATOR.'Common'.EXT);    
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Errors'.EXT); 
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Library_factory'.EXT); 
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Registry'.EXT); 
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Loader'.EXT);
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Controller'.EXT); 
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Library'.EXT); 
require (BASE.'libraries'.DIRECTORY_SEPARATOR.'Model'.EXT);



// call the controller.
require (CONTROLLER.$GLOBALS['controller'].EXT);


/*
*  Super Class (Our called controller class)
*
* */
             
$OB = new $class();
//You can also set a var from outside of the class like this.
//$OB->name = "My Name"; but this not useful from here.


$objects = array_keys(get_object_vars($OB)); 
//print_r($objects);

$arg_array = array(); //write your arguments here...
call_user_func_array(array($OB, $method), $arg_array);

// end memory test
//$end = OB_memory_usage();
$end = memory_get_usage();

echo '<b>Started memory:</b> '.$start.'<br />';
echo '<b>Total consumed memory: </b>'.$end.'<br />';

/*
// We Don't need try/catch blocks because of we use
// set_exception_handler(); function look at libraries
// Errors.php

//catch all errors.
} catch (CommonException $e) {

    echo $e;

    echo Common_ErrorTemplate(
    $e->getCode(),
    $e->getMessage(),
    $e->getFile(),
    $e->getLine(),
    'General');
    
} catch (PDOException $e) {

    echo $e;
    
   // echo Common_ErrorTemplate(
   // $e->getCode(),
   // $e->getMessage(),
   // $e->getFile(),
   // $e->getLine(),
   // 'Database');
    
}   

*/
?>
