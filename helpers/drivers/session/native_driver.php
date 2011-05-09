<?php
defined('BASE') or exit('Access Denied!');

/**
* Obullo Framework (c) 2010.
* Procedural Session Implementation With stdClass.
* Less coding, Less Memory.
*
* @author      Ersin Guvenc.
* @version     0.1
* @version     0.2 added extend support
* @version     0.3 added config_item('sess_die_cookie') and sess() func.
*/
if( ! function_exists('_sess_start') )
{
    function _sess_start($params = array())
    {
        log_me('debug', "Session Native Driver Initialized");

        $_ob = base_register('Storage');

        foreach (array('sess_expiration', 'sess_match_ip', 'sess_die_cookie',
        'sess_match_useragent', 'sess_cookie_name', 'cookie_path', 'cookie_domain',
        'sess_time_to_update', 'time_reference', 'cookie_prefix') as $key)
        {
            $_ob->session->$key = (isset($params[$key])) ? $params[$key] : config_item($key);
        }

        // _unserialize func. use strip_slashes() func. We can add it later if we need it in Native Library. ?
        // loader::helper('ob/string');

        if($_ob->session->sess_die_cookie)
        {
            session_set_cookie_params(0);

            ini_set('session.gc_maxlifetime', '0');
            ini_set('session.cookie_lifetime', '0');  // 0
        }
        else
        {
            session_set_cookie_params($_ob->session->sess_expiration, $_ob->session->cookie_path, $_ob->session->cookie_domain);

            // Configure garbage collection
            ini_set('session.gc_divisor', 100);
            ini_set('session.gc_maxlifetime', ($_ob->session->sess_expiration == 0) ? 7200 : $_ob->session->sess_expiration);
        }

        $_ob->session->now = _get_time();

        session_name($_ob->session->cookie_prefix . $_ob->session->sess_cookie_name);

        session_start();

        if (is_numeric($_ob->session->sess_expiration))
        {
            if ($_ob->session->sess_expiration > 0)
            {
                $_ob->session->sess_id_ttl = $_ob->session->sess_expiration;
            }
            else
            {
                $_ob->session->sess_id_ttl = (60 * 60 * 24 * 365 * 2);
            }
        }

        // check if session id needs regeneration
        if ( _session_id_expired() )
        {
            // regenerate session id (session data stays the
            // same, but old session storage is destroyed)
            _session_regenerate_id();
        }

        // delete old flashdata (from last request)
        _flashdata_sweep();

        // mark all new flashdata as old (data will be deleted before next request)
        _flashdata_mark();

        log_me('debug', "Session routines successfully run");

        return TRUE;
    }
}

// --------------------------------------------------------------------

if( ! function_exists('_session_regenerate_id') )
{
    function _session_regenerate_id()
    {
        // copy old session data, including its id
        $old_session_id = session_id();
        $old_session_data = $_SESSION;

        // regenerate session id and store it
        session_regenerate_id();
        $new_session_id = session_id();

        // switch to the old session and destroy its storage
        session_id($old_session_id);
        session_destroy();

        // switch back to the new session id and send the cookie
        session_id($new_session_id);
        session_start();

        // restore the old session data into the new session
        $_SESSION = $old_session_data;

        // update the session creation time
        $_SESSION['regenerated'] = _get_time();

        // end the current session and store session data.
        session_write_close();
    }

}

// --------------------------------------------------------------------

/**
* Destroy the current session
*
* @access    public
* @return    void
*/
if( ! function_exists('sess_destroy') )
{
    function sess_destroy()
    {
        $_ob = base_register('Storage');

        unset($_SESSION);

        if ( isset( $_COOKIE[session_name()] ) )
        {
            setcookie(session_name(), '', (_get_time() - 42000), $_ob->session->cookie_path, $_ob->session->cookie_domain);
        }

        session_destroy();
    }
}
// --------------------------------------------------------------------

/**
* Fetch a specific item from the session array
*
* @access   public
* @param    string
* @return   string
*/
if( ! function_exists('sess_get') )
{
    function sess_get($item)
    {
        if($item == 'session_id')
        {
            return session_id();
        }
        else
        {
            return ( ! isset($_SESSION[$item])) ? FALSE : $_SESSION[$item];
        }
    }
}
// --------------------------------------------------------------------

/**
* Alias of sess_get(); function.
*
* @access   public
* @param    string
* @return   string
*/
if( ! function_exists('sess') )
{
    function sess($item)
    {
        return sess_get($item);
    }
}
// --------------------------------------------------------------------

/**
* Fetch all session data
*
* @access    public
* @return    mixed
*/
if( ! function_exists('sess_alldata') )
{
    function sess_alldata()
    {
        return ( ! isset($_SESSION)) ? FALSE : $_SESSION;
    }
}
// --------------------------------------------------------------------

/**
* Add or change data in the "userdata" array
*
* @access   public
* @param    mixed
* @param    string
* @return   void
*/
if( ! function_exists('sess_set') )
{
    function sess_set($newdata = array(), $newval = '')
    {
        if (is_string($newdata))
        {
            $newdata = array($newdata => $newval);
        }

        if (count($newdata) > 0)
        {
            foreach ($newdata as $key => $val)
            {
                $_SESSION[$key] = $val;
            }
        }
    }
}
// --------------------------------------------------------------------

/**
* Delete a session variable from the "userdata" array
*
* @access    public
* @param     array()
* @return    void
*/
if( ! function_exists('sess_unset') )
{
    function sess_unset($newdata = array())  // obullo changes ...
    {
        if (is_string($newdata))
        {
            $newdata = array($newdata => '');
        }

        if (count($newdata) > 0)
        {
            foreach ($newdata as $key => $val)
            {
                unset($_SESSION[$key]);
            }
        }
    }
}
// ------------------------------------------------------------------------

/**
* Checks if session has expired
* @access    private
*/
if( ! function_exists('_session_id_expired') )
{
    function _session_id_expired()
    {
        $_ob = base_register('Storage');

        if ( ! isset( $_SESSION['regenerated'] ) )
        {
            $_SESSION['regenerated'] = _get_time();
            return FALSE;
        }

        $expiry_time = time() - $_ob->session->sess_id_ttl;

        if ( $_SESSION['regenerated'] <=  $expiry_time )
        {
            return TRUE;
        }

        return FALSE;
    }
}

/**
* Add or change flashdata, only available
* until the next request
*
* @access   public
* @param    mixed
* @param    string
* @return   void
*/
if( ! function_exists('sess_set_flash') )
{
    function sess_set_flash($newdata = array(), $newval = '')  // ( obullo changes ... )
    {
        $_ob = base_register('Storage');

        if (is_string($newdata))
        {
            $newdata = array($newdata => $newval);
        }

        if (count($newdata) > 0)
        {
            foreach ($newdata as $key => $val)
            {
                $flashdata_key = $_ob->session->flashdata_key.':new:'.$key;
                sess_set($flashdata_key, $val);
            }
        }
    }
}
// ------------------------------------------------------------------------

/**
* Keeps existing flashdata available to next request.
*
* @access   public
* @param    string
* @return   void
*/
if( ! function_exists('sess_keep_flash') )
{
    function sess_keep_flash($key) // ( obullo changes ...)
    {
        $_ob = base_register('Storage');

        // 'old' flashdata gets removed.  Here we mark all
        // flashdata as 'new' to preserve it from _flashdata_sweep()
        // Note the function will return FALSE if the $key
        // provided cannot be found
        $old_flashdata_key = $_ob->session->flashdata_key.':old:'.$key;
        $value = sess_get($old_flashdata_key);

        $new_flashdata_key = $_ob->session->flashdata_key.':new:'.$key;
        sess_set($new_flashdata_key, $value);
    }
}
// ------------------------------------------------------------------------

/**
* Fetch a specific flashdata item from the session array
*
* @access   public
* @param    string  $key you want to fetch
* @param    string  $prefix html open tag
* @param    string  $suffix html close tag
*
* @version  0.1
* @version  0.2     added prefix and suffix parameters.
*
* @return   string
*/
if( ! function_exists('sess_get_flash') )
{
    function sess_get_flash($key, $prefix = '', $suffix = '')  // obullo changes ...
    {
        $_ob = base_register('Storage');

        $flashdata_key = $_ob->session->flashdata_key.':old:'.$key;

        $value = sess_get($flashdata_key);

        if($value == '')
        {
            $prefix = '';
            $suffix = '';
        }

        return $prefix.$value.$suffix;
    }
}
// ------------------------------------------------------------------------

/**
* Identifies flashdata as 'old' for removal
* when _flashdata_sweep() runs.
*
* @access    private
* @return    void
*/
if( ! function_exists('_flashdata_mark') )
{
    function _flashdata_mark()
    {
        $_ob = base_register('Storage');

        $userdata = sess_alldata();
        foreach ($userdata as $name => $value)
        {
            $parts = explode(':new:', $name);
            if (is_array($parts) && count($parts) === 2)
            {
                $new_name = $_ob->session->flashdata_key.':old:'.$parts[1];
                sess_set($new_name, $value);
                sess_unset($name);
            }
        }
    }
}
// ------------------------------------------------------------------------

/**
* Removes all flashdata marked as 'old'
*
* @access    private
* @return    void
*/
if( ! function_exists('_flashdata_sweep') )
{
    function _flashdata_sweep()
    {
        $userdata = sess_alldata();
        foreach ($userdata as $key => $value)
        {
            if (strpos($key, ':old:'))
            {
                sess_unset($key);
            }
        }
    }
}
// --------------------------------------------------------------------

/**
* Get the "now" time
*
* @access    private
* @return    string
*/
if( ! function_exists('_get_time') )
{
    function _get_time()
    {
        $_ob = base_register('Storage');

        $time = time();
        if (strtolower($_ob->session->time_reference) == 'gmt')
        {
            $now  = time();
            $time = mktime( gmdate("H", $now),
            gmdate("i", $now),
            gmdate("s", $now),
            gmdate("m", $now),
            gmdate("d", $now),
            gmdate("Y", $now)
            );
        }
        return $time;
    }
}
// --------------------------------------------------------------------


/* End of file cookie_driver.php */
/* Location: ./obullo/helpers/drivers/session/native_driver.php */
