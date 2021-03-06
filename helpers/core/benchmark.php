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

// ------------------------------------------------------------------------

/**
 * Obullo Benchmark Helper
 *
 * This helper enables you to mark points and calculate the time difference
 * between them.  Memory consumption can also be displayed.
 *
 * @package       Obullo
 * @subpackage    Helpers
 * @category      Test
 * @author        Ersin Guvenc
 * @link          
 */
 
if( ! isset($_ob->benchmark))  // Helper Constructor
{
    $_ob = base_register('Storage');
    
    $_ob->benchmark = new stdClass();
    $_ob->benchmark->marker = array();

    log_me('debug', "Benchmark Helper Initialized");
}
// --------------------------------------------------------------------

/**
* Set a benchmark marker
*
* Multiple calls to this function can be made so that several
* execution points can be timed
*
* @access    public
* @param     string    $name    name of the marker
* @return    void
*/
if( ! function_exists('benchmark_mark') ) 
{
    function benchmark_mark($name)
    {
        $_ob = base_register('Storage'); 
        
        $_ob->benchmark->marker[$name] = microtime();
    }
}

// -------------------------------------------------------------------- 

/**
* Calculates the time difference between two marked points.
*
* @access   public
* @param    string    a particular marked point
* @param    string    a particular marked point
* @param    integer   the number of decimal places
* @return   mixed
*/
if( ! function_exists('benchmark_elapsed_time') ) 
{
    function benchmark_elapsed_time($point1 = '', $point2 = '', $decimals = 4)
    {
        $_ob = base_register('Storage'); 
        
        if ($point1 == '')
        {
            return '{elapsed_time}';
        }

        if ( ! isset($_ob->benchmark->marker[$point1]))
        {
            return '';
        }

        if ( ! isset($_ob->benchmark->marker[$point2]))
        {
            $_ob->benchmark->marker[$point2] = microtime();
        }

        list($sm, $ss) = explode(' ', $_ob->benchmark->marker[$point1]);
        list($em, $es) = explode(' ', $_ob->benchmark->marker[$point2]);

        return number_format(($em + $es) - ($sm + $ss), $decimals);
    }
}
// -------------------------------------------------------------------- 

/**
* Memory Usage
*
* @access    public
* @return    string
*/
if( ! function_exists('benchmark_memory_usage') ) 
{
    function benchmark_memory_usage()
    {
        return '{memory_usage}';
    }
}

/* End of file benchmark.php */
/* Location: ./obullo/helpers/core/benchmark.php */