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
 * Obullo Pager Html Widgets
 *
 *
 * @package       Obullo
 * @subpackage    Libraries.drivers.Pager_html_widgets
 * @category      Libraries
 * @author        Ersin Guvenc
 * @author        Derived from PEAR Pager package.
 * @see           Original package http://pear.php.net/package/Pager
 * @link          
 */

Class Pager_html_widgets
{
    public $pager = NULL;

    /**
    * Constructor
    *
    * @param object &$pager Pager instance
    */
    function __construct(&$pager)
    {
        $this->pager =& $pager;
    }
    
    /**
     * Returns a string with a XHTML SELECT menu,
     * useful for letting the user choose how many items per page should be
     * displayed. If parameter useSessions is TRUE, this value is stored in
     * a session var. The string isn't echoed right now so you can use it
     * with template engines.
     *
     * @param integer $start       starting value for the select menu
     * @param integer $end         ending value for the select menu
     * @param integer $step        step between values in the select menu
     * @param boolean $showAllData If true, perPage is set equal to totalItems.
     * @param array   $extraParams (or string $optionText for BC reasons)
     *                - 'optionText': text to show in each option.
     *                  Use '%d' where you want to see the number of pages selected.
     *                - 'attributes': (html attributes) Tag attributes or
     *                  HTML attributes (id="foo" pairs), will be inserted in the
     *                  <select> tag
     *                - 'checkMaxLimit': if true, Pager checks if $end is bigger
     *                  than $totalItems, and doesn't show the extra select options
     *                - 'autoSubmit': if TRUE, add some js code
     *                  to submit the form on the onChange event
     *
     * @return string xhtml select box
     * @access public
     */
    function get_per_page_select_box($start = 5, $end = 30, $step = 5, $showAllData = FALSE, $extraParams = array())
    {
        // FIXME: needs POST support
        $optionText    = '%d';
        $attributes    = '';
        $checkMaxLimit = FALSE;
        
        if (is_string($extraParams)) 
        {
            //old behavior, BC maintained
            $optionText = $extraParams;
        } 
        else 
        {
            if (array_key_exists('optionText', $extraParams)) 
            {
                $optionText = $extraParams['optionText'];
            }
            if (array_key_exists('attributes', $extraParams)) 
            {
                $attributes = $extraParams['attributes'];
            }
            if (array_key_exists('checkMaxLimit', $extraParams)) 
            {
                $checkMaxLimit = $extraParams['checkMaxLimit'];
            }
        }

        if ( ! strstr($optionText, '%d')) 
        {
            throw new PagerException('Page class invalid format - use "%d" as placeholder.');
        }
        
        $start = (int)$start;
        $end   = (int)$end;
        $step  = (int)$step;
        
        if ( ! empty($_SESSION[$this->pager->_session_var])) 
        {
            $selected = (int)$_SESSION[$this->pager->_session_var];
        } 
        else 
        {
            $selected = $this->pager->_per_page;
        }

        if ($checkMaxLimit && $this->pager->_totalItems >= 0 && $this->pager->_totalItems < $end) 
        {
            $end = $this->pager->_totalItems;
        }

        $tmp = '<select name="'.$this->pager->_session_var.'"';
        if ( ! empty($attributes)) 
        {
            $tmp .= ' '.$attributes;
        }
        
        if ( ! empty($extraParams['autoSubmit'])) 
        {
            if ('GET' == $this->pager->_http_method) 
            {
                $selector = '\' + '.'this.options[this.selectedIndex].value + \'';
                if ($this->pager->_append) 
                {
                    $tmpLinkData = $this->pager->_link_data;
                    if (isset($tmpLinkData[$this->pager->_url_var])) 
                    {
                        $tmpLinkData[$this->pager->_url_var] = $this->pager->getCurrentPageID();
                    }
                    
                    $tmpLinkData[$this->pager->_session_var] = '1';
                    $href = '?' . $this->pager->_http_build_query_wrapper($tmpLinkData);
                    $href = htmlentities($this->pager->_url, ENT_COMPAT, 'UTF-8'). preg_replace(
                        '/(&|&amp;|\?)('.$this->pager->_session_var.'=)(\d+)/',
                        '\\1\\2'.$selector,
                        htmlentities($href, ENT_COMPAT, 'UTF-8')
                    );
                } 
                else 
                {
                    $href = htmlentities($this->pager->_url . str_replace('%d', $selector, $this->pager->_filename), ENT_COMPAT, 'UTF-8');
                }
                
                $tmp .= ' onchange="document.location.href=\''
                     . $href .'\''
                     . '"';
            } 
            elseif ($this->pager->_http_method == 'POST') 
            {
                $tmp .= " onchange='"
                     . $this->pager->_generateFormOnClick($this->pager->_url, $this->pager->_link_data)
                     . "'";
                $tmp = preg_replace(
                    '/(input\.name = \"'.$this->pager->_session_var.'\"; input\.value =) \"(\d+)\";/',
                    '\\1 this.options[this.selectedIndex].value;',
                    $tmp
                );
            }
        }

        $tmp .= '>';
        $last = $start;
        for ($i=$start; $i<=$end; $i+=$step) 
        {
            $last = $i;
            $tmp .= '<option value="'.$i.'"';
            if ($i == $selected) 
            {
                $tmp .= ' selected="selected"';
            }
            $tmp .= '>'.sprintf($optionText, $i).'</option>';
        }
        
        if ($showAllData && $last != $this->pager->_totalItems) 
        {
            $tmp .= '<option value="'.$this->pager->_totalItems.'"';
            if ($this->pager->_totalItems == $selected) 
            {
                $tmp .= ' selected="selected"';
            }
            $tmp .= '>';
            
            if (empty($this->pager->_show_all_text)) 
            {
                $tmp .= str_replace('%d', $this->pager->_totalItems, $optionText);
            } 
            else 
            {
                $tmp .= $this->pager->_show_all_text;
            }
            
            $tmp .= '</option>';
        }
        
        if (substr($tmp, -9, 9) !== '</option>') 
        {
            //empty select
            $tmp .= '<option />';
        }
        $tmp .= '</select>';
        
        return $tmp;
    }

    /**
     * Returns a string with a XHTML SELECT menu with the page numbers,
     * useful as an alternative to the links
     *
     * @param array  $params          - 'optionText': text to show in each option.
     *                                  Use '%d' where you want to see the number
     *                                  of pages selected.
     *                                - 'autoSubmit': if TRUE, add some js code
     *                                  to submit the form on the onChange event
     * @param string $extraAttributes (html attributes) Tag attributes or
     *                                HTML attributes (id="foo" pairs), will be
     *                                inserted in the <select> tag
     *
     * @return string xhtml select box
     * @access public
     */
    function get_page_select_box($params = array(), $extra_attributes = '')
    {
        $optionText = '%d';
        if (array_key_exists('optionText', $params)) 
        {
            $optionText = $params['optionText'];
        }

        if ( ! strstr($optionText, '%d')) 
        {
            throw new PagerException('invalid format - use "%d" as placeholder.');
        }
        
        $tmp = '<select name="'.$this->pager->_url_var.'"';
        
        if ( ! empty($extra_attributes)) 
        {
            $tmp .= ' '.$extra_attributes;
        }
        
        if ( ! empty($params['autoSubmit'])) 
        {
            if ($this->pager->_http_method == 'GET') 
            {
                $selector = '\' + '.'this.options[this.selectedIndex].value + \'';
                
                if ($this->pager->_append) 
                {
                    $href = '?' . $this->pager->_http_build_query_wrapper($this->pager->_link_data);
                    $href = htmlentities($this->pager->_url, ENT_COMPAT, 'UTF-8'). preg_replace(
                        '/(&|&amp;|\?)('.$this->pager->_url_var.'=)(\d+)/',
                        '\\1\\2'.$selector,
                        htmlentities($href, ENT_COMPAT, 'UTF-8')
                    );
                } 
                else 
                {
                    $href = htmlentities($this->pager->_url . str_replace('%d', $selector, $this->pager->_filename), ENT_COMPAT, 'UTF-8');
                }
                
                $tmp .= ' onchange="document.location.href=\''
                     . $href .'\''
                     . '"';
            } 
            elseif ($this->pager->_http_method == 'POST') 
            {
                $tmp .= " onchange='"
                     . $this->pager->_generateFormOnClick($this->pager->_url, $this->pager->_link_data)
                     . "'";
                $tmp = preg_replace(
                    '/(input\.name = \"'.$this->pager->_url_var.'\"; input\.value =) \"(\d+)\";/',
                    '\\1 this.options[this.selectedIndex].value;',
                    $tmp
                );
            }
        }
        $tmp .= '>';
        $start    = 1;
        $end      = $this->pager->num_pages();
        $selected = $this->pager->get_current_page();
        
        for ($i=$start; $i<=$end; $i++) 
        {
            $tmp .= '<option value="'.$i.'"';
            if ($i == $selected) 
            {
                $tmp .= ' selected="selected"';
            }
            
            $tmp .= '>'.sprintf($optionText, $i).'</option>';
        }
        
        $tmp .= '</select>';
        return $tmp;
    }
       
}

// END Pager_html_widgets Class

/* End of file Pager_html_widgets.php */
/* Location: ./base/libraries/php5/drivers/pager/Pager_html_widgets.php */