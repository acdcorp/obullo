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
* @access   public
* @param    string  $request
* @param    integer $cache_time
* @return   object of HMVC class
*/
if( ! function_exists('hmvc_request') )
{
    function hmvc_request($method = 'GET', $request_uri = '', $params = array(), $cache_time = 0, $extension= 'php')
    {
        $hmvc = base_register('HMVC', true);  // Every hmvc request must create new instance
        $hmvc->clear();                       // clear variables for each request.
        $hmvc->hmvc_request($request_uri, $cache_time, $extension);
        $hmvc->set_method($method, $params);

        return $hmvc;   // return hmvc_object
    }

}

/* End of file hmvc.php */
/* Location: ./obullo/helpers/hmvc.php */
