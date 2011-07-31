<?php
defined('BASE') or exit('Access Denied!');

/**
 * Obullo Framework (c) 2009.
 *
 * PHP5 MVC Based Minimalist Software.
 *
 * @package         obullo
 * @author          obullo.com
 * @license         public
 * @since           Version 1.0
 * @filesource
 * @license
 */

// ------------------------------------------------------------------------

/**
 * Obullo Hmvc Helpers
 *
 * @package     Obullo
 * @subpackage  Helpers
 * @category    Helpers
 * @author      Ersin Guvenc
 * @link
 */

// ------------------------------------------------------------------------

/**
* Call HMVC Request using HMVC Class.
*
* @author   Ersin Guvenc
* @author   CJ Lazell
* @access   public
* @param    string method
* @param    string  $request
* @param    integer | bool | array  $cache_time_or_config
* @return   string response | object of HMVC class
*/
if( ! function_exists('request') )
{
    function request($method = 'get', $request_uri = '', $params = array(), $cache_time_or_config = 0)
    {
        // Supported request methods
        $methods = array('GET' => '', 'POST' => '', 'PUT' => '', 'DELETE' => '');

        if( ! isset($methods[strtoupper($method)]))
        {
            throw new Exception('HMVC only supports GET, POST, PUT and DELETE methods !');
        }

        // Quick access who like to less coding.
        // ------------------------------------------------------------------------

        if($cache_time_or_config === TRUE)
        {
            $hmvc = base_register('HMVC', true);   // Every hmvc request must create new instance
            $hmvc->clear();                        // clear variables for each request.
            $hmvc->hmvc_request($request_uri, 0);
            $hmvc->set_method($method, $params);

            return $hmvc->exec()->response();
        }

        // Quick access with config parameters.
        // ------------------------------------------------------------------------

        if(is_array($cache_time_or_config))
        {
            $config = $cache_time_or_config;

            $hmvc = base_register('HMVC', true);
            $hmvc->clear();

            $cache_time = (isset($config['cache_time'])) ? $config['cache_time'] : 0;
            $no_loop    = (isset($config['no_loop']) AND $config['no_loop'] == TRUE) ? TRUE : FALSE;

            $hmvc->hmvc_request($request_uri, $cache_time);
            $hmvc->no_loop($no_loop);
            $hmvc->set_method($method, $params);

            return $hmvc->exec()->response();
        }

        // Long access but flexible way.
        // ------------------------------------------------------------------------

        $hmvc = base_register('HMVC', true);
        $hmvc->clear();
        $hmvc->hmvc_request($request_uri, $cache_time_or_config);
        $hmvc->set_method($method, $params);

        return $hmvc;   // return to hmvc object
    }

}

/* End of file request.php */
/* Location: ./obullo/helpers/request.php */
