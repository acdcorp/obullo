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

        foreach (array(
            'sess_expiration'
          , 'sess_match_ip'
          , 'sess_die_cookie'
          , 'sess_match_useragent'
          , 'sess_cookie_name'
          , 'sess_encrypt_cookie'
          ////////////////////
          // Memcache Settings
          , 'sess_memcache_ips'
          , 'sess_flash_auto_expire'
          ////////////////////
          , 'cookie_path'
          , 'cookie_domain'
          , 'cookie_prefix'
          , 'sess_time_to_update'
          , 'time_reference'
        ) as $key)
        {
            $_ob->session->$key = (isset($params[$key])) ? $params[$key] : config_item($key);
        }

        // Create/Store an instance of memcache
        $_ob->session->memcache= new Memcache;
        $memcache_ips = json_decode($_ob->session->sess_memcache_ips);
        foreach($memcache_ips as $ip)
        $_ob->session->memcache->addServer($ip,11211);

        // Lets initiate all the defaults
        $_ob->session->keys= array();
        $_ob->session->keys['session_id']  = fuel_new_session_id();
        $_ob->session->keys['previous_id'] = $_ob->session->keys['session_id'];  // prevents errors if previous_id has a unique index
        $_ob->session->keys['ip_address']  = fuel_real_ip();
        $_ob->session->keys['user_agent']  = fuel_user_agent();
        $_ob->session->keys['created']     = time();
        $_ob->session->keys['updated']     = $_ob->session->keys['created'];
        $_ob->session->data=array();
        $_ob->session->flash=array();

        fuel_write_memcached($_ob->session->keys['session_id'], serialize(array()));
        fuel_set_cookie();

        /*$_ob->session->now = _get_time();

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
        _flashdata_mark();*/

        log_me('debug', "Session routines successfully run");

        return TRUE;
    }
}

/**
* Fetch a specific item from the session array
*
* @access   public
* @param    string
* @return   string
*/
if( ! function_exists('sess_get') )
{
  function sess_get($name, $default = null)
  {
    fuel_read();
    $_ob = base_register('Storage');

    if (is_null($name))
    {
      return $_ob->session->data;
    }
    elseif (isset($_ob->session->data[$name]))
    {
      return $_ob->session->data[$name];
    }

    if (strpos($name, '.') !== false)
    {
      $parts = explode('.', $name);

      switch (count($parts))
      {
        case 2:
          if (isset($_ob->session->data[$parts[0]][$parts[1]]))
          {
            return $_ob->session->data[$parts[0]][$parts[1]];
          }
        break;

        case 3:
          if (isset($_ob->session->data[$parts[0]][$parts[1]][$parts[2]]))
          {
            return $_ob->session->data[$parts[0]][$parts[1]][$parts[2]];
          }
        break;

        case 4:
          if (isset($_ob->session->data[$parts[0]][$parts[1]][$parts[2]][$parts[3]]))
          {
            return $_ob->session->data[$parts[0]][$parts[1]][$parts[2]][$parts[3]];
          }
        break;

        default:
          $return = false;
          foreach ($parts as $part)
          {
            if ($return === false and isset($_ob->session->data[$part]))
            {
              $return = $_ob->session->data[$part];
            }
            elseif (isset($return[$part]))
            {
              $return = $return[$part];
            }
            else
            {
              return $default;
            }
          }
          return $return;
        break;
      }
    }

    return $default;
  }
}

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
  function sess_set($name, $value)
  {
    $_ob = base_register('Storage');
    $_ob->session->data[$name] = $value;
    fuel_write();
  }
}

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
    // do we have something to destroy?
    if ( ! empty($_ob->session->keys))
    {
      // delete the key from the memcached server
      if ($_ob->session->memcache->delete($_ob->session->sess_cookie_name.'_'.$_ob->session->keys['session_id']) === false)
      {
        log_me('error', 'Memcached returned error code "'.$_ob->session->memcache->getResultCode().'" on delete. Check your configuration.');
      }
    }

    // reset the stored session data
    $_ob->session->keys = $_ob->session->flash = $_ob->session->data = array();
  }
}
// --------------------------------------------------------------------

//////////////////////////////////////
// FUNCTIONS FROM FUEL
//////////////////////////////////////
if( ! function_exists('fuel_write_memcached') )
{
  function fuel_write_memcached($session_id, $payload)
  {
    $_ob = base_register('Storage');
    // session payload
    $payload = fuel_serialize(array($_ob->session->data, $_ob->session->flash));

    // write it to the memcached server
    if ($_ob->session->memcache->set( $_ob->session->sess_cookie_name.'_'.$_ob->session->keys['session_id'], $payload, $_ob->session->sess_expiration) === false)
    {
      log_me('error', 'Memcached returned error code "'.$_ob->session->memcached->getResultCode().'" on write. Check your configuration.');
    }
  }
}

  /**
   * Reads the memcached entry
   *
   * @access  private
   * @return  mixed, the payload if the file exists, or false if not
   */
if( ! function_exists('fuel_read_memcached') )
{
  function fuel_read_memcached($session_id)
  {
    $_ob = base_register('Storage');
    // fetch the session data from the Memcached server
    return $_ob->session->memcache->get($_ob->session->sess_cookie_name.'_'.$_ob->session->keys['session_id']);
  }
}

  /**
   * read the session
   *
   * @access  public
   * @param boolean, set to true if we want to force a new session to be created
   * @return  void
   */
if( ! function_exists('fuel_read') )
{
  function fuel_read($force = false)
  {
    $_ob = base_register('Storage');
    // get the session cookie
    $cookie = fuel_get_cookie();

    // if no session cookie was present, create it
    if ($cookie === false or $force)
    {
      _sess_start();
    }

    // read the session file
    $payload = fuel_read_memcached($_ob->session->keys['session_id']);

    if ($payload === false)
    {
      // try to find the previous one
      $payload = fuel_read_memcached($_ob->session->keys['previous_id']);

      if ($payload === false)
      {
        // cookie present, but session record missing. force creation of a new session
        fuel_read(true);
        return;
      }
    }

    // unpack the payload
    $payload = fuel_unserialize($payload);

    // session referral?
    if (isset($payload['rotated_session_id']))
    {
      $payload = fuel_read_memcached($payload['rotated_session_id']);
      if ($payload === false)
      {
        // cookie present, but session record missing. force creation of a new session
        fuel_read(true);
        return;
      }
      else
      {
        // update the session
        $_ob->session->keys['previous_id'] = $_ob->session->keys['session_id'];
        $_ob->session->keys['session_id'] = $payload['rotated_session_id'];

        // unpack the payload
        $payload = fuel_unserialize($payload);
      }
    }

    if (isset($payload[0])) $_ob->session->data = $payload[0];
    if (isset($payload[1])) $_ob->session->flash = $payload[1];

    //parent::read();
    if ($_ob->session->sess_flash_auto_expire === true)
    {
      foreach($_ob->session->flash as $key => $value)
      {
        $_ob->session->flash[$key]['state'] = 'old';
      }
    }
  }
}

  /**
   * write the session
   *
   * @access  public
   * @return  void
   */
if( ! function_exists('fuel_write') )
{
  function fuel_write()
  {
    $_ob = base_register('Storage');
    // do we have something to write?
    if ( ! empty($_ob->session->keys))
    {
      //parent::write();
      fuel_cleanup_flash();

      // rotate the session id if needed
      fuel_rotate(false);

      // session payload
      $payload = fuel_serialize(array($_ob->session->data, $_ob->session->flash));

      // create the session file
      fuel_write_memcached($_ob->session->keys['session_id'], $payload);

      // was the session id rotated?
      if ( isset($_ob->session->keys['previous_id']) && $_ob->session->keys['previous_id'] != $_ob->session->keys['session_id'])
      {
        // point the old session file to the new one, we don't want to lose the session
        $payload = fuel_serialize(array('rotated_session_id' => $_ob->session->keys['session_id']));
        fuel_write_memcached($_ob->session->keys['previous_id'], $payload);
      }

      fuel_set_cookie();
    }
  }
}

/**
 * force a session_id rotation
 *
 * @access  public
 * @param boolean, if true, force a session id rotation
 * @return  void
 */
if( ! function_exists('fuel_rotate') )
{
  function fuel_rotate($force = true)
  {
    $_ob = base_register('Storage');
    // existing session. need to rotate the session id?
    if ($_ob->session->sess_time_to_update &&
      ($force or $_ob->session->keys['created'] + $_ob->session->sess_time_to_update <= time()))
    {

      // generate a new session id, and update the create timestamp
      $_ob->session->keys['previous_id']  = $_ob->session->keys['session_id'];
      $_ob->session->keys['session_id']   = fuel_new_session_id();
      $_ob->session->keys['created']      = time();
      $_ob->session->keys['updated']      = $_ob->session->keys['created'];
    }

  }
}

/**
 * removes flash variables marked as old
 *
 * @access  private
 * @return  void
 */
if( ! function_exists('fuel_cleanup_flash') )
{
  function fuel_cleanup_flash()
  {
    $_ob = base_register('Storage');
    foreach($_ob->session->flash as $key => $value)
    {
      if ($value['state'] === 'old')
      {
        unset($_ob->session->flash[$key]);
      }
    }
  }
}

/**
* Write the session cookie
*
* @access    public
* @return    void
*/
if( ! function_exists('fuel_set_cookie') )
{
    function fuel_set_cookie($payload = array())
    {
        $_ob = base_register('Storage');

        // record the last update time of the session
        $_ob->session->keys['updated']= time();

        array_unshift($payload, $_ob->session->keys);

        if (is_null($payload))
        {
          $payload = $_ob->session->data;
        }

        // Serialize the userdata for the cookie
        $payload = fuel_serialize($payload);

        if ($_ob->session->sess_encrypt_cookie == TRUE)
        {
            $encrypt = base_register('Encrypt');
            $payload = $encrypt->encode($payload);
        }
        else
        {
            // if encryption is not used, we provide an md5 hash to prevent userside tampering
            $payload = $payload . md5($payload . $_ob->session->encryption_key);
        }

        // Set the cookie
        cookie_set(
          $_ob->session->sess_cookie_name,
          $payload,
          $_ob->session->sess_expiration,
          $_ob->session->cookie_path,
          $_ob->session->cookie_domain,
          0
        );
    }
}

  /**
   * read a cookie
   *
   * @access  private
   * @return  void
   */
if( ! function_exists('fuel_get_cookie') )
{
   function fuel_get_cookie()
   {
        $_ob = base_register('Storage');

        // Fetch the cookie
        $cookie = cookie_get($_ob->session->sess_cookie_name);

        // No cookie?  Goodbye cruel world!...
        if ($cookie === FALSE)
        {
            log_me('debug', 'A session cookie was not found.');
            return FALSE;
        }

        // Decrypt the cookie data
        if ($_ob->session->sess_encrypt_cookie == TRUE)
        {
            $encrypt = base_register('Encrypt');
            $cookie = $encrypt->decode($cookie);
        }
        else
        {
            // encryption was not used, so we need to check the md5 hash
            $hash    = substr($cookie, strlen($cookie)-32); // get last 32 chars
            $cookie = substr($cookie, 0, strlen($cookie)-32);

            // Does the md5 hash match?  This is to prevent manipulation of session data in userspace
            if ($hash !==  md5($cookie . $_ob->session->encryption_key))
            {
                log_me('error', 'The session cookie data did not match what was expected. This could be a possible hacking attempt.');

                sess_destroy();
                return FALSE;
            }
        }

        // Unserialize the session array
        $cookie = fuel_unserialize($cookie);

      // validate the cookie
      if ( ! isset($cookie[0]) )
      {
        // not a valid cookie payload
      }
      elseif ($cookie[0]['updated'] + $_ob->session->sess_expiration <= time())
      {
        // session has expired
      }
      elseif ($_ob->session->sess_match_ip && $cookie[0]['ip_address'] !== fuel_real_ip())
      {
        // IP address doesn't match
      }
      elseif ($_ob->session->sess_match_useragent && $cookie[0]['user_agent'] !== fuel_user_agent())
      {
        // user agent doesn't match
      }
      else
      {
        // session is valid, retrieve the session keys
        if (isset($cookie[0])) $_ob->session->keys = $cookie[0];

        // and return the cookie payload
        array_shift($cookie);
        return $cookie;
      }

    // no payload
    return false;
   }
}

if( ! function_exists('fuel_serialize') )
{
  function fuel_serialize($data)
  {
    if (is_array($data))
    {
      foreach ($data as $key => $val)
      {
        if (is_string($val))
        {
          $data[$key] = str_replace('\\', '{{slash}}', $val);
        }
      }
    }
    else
    {
      if (is_string($data))
      {
        $data = str_replace('\\', '{{slash}}', $data);
      }
    }

    return serialize($data);
  }
}
  /**
   * generate a new session id
   *
   * @access  private
   * @return  void
   */
if( ! function_exists('fuel_new_session_id') )
{
  function fuel_new_session_id()
  {
    $session_id = '';
    while (strlen($session_id) < 32)
    {
      $session_id .= mt_rand(0, mt_getrandmax());
    }
    return md5(uniqid($session_id, TRUE));
  }
}

if( ! function_exists('fuel_real_ip') )
{
  function fuel_real_ip()
  {
    if (fuel_server('HTTP_X_FORWARDED_FOR') !== null)
    {
      return fuel_server('HTTP_X_FORWARDED_FOR');
    }
    elseif (fuel_server('HTTP_CLIENT_IP') !== null)
    {
      return fuel_server('HTTP_CLIENT_IP');
    }
    elseif (fuel_server('REMOTE_ADDR') !== null)
    {
      return fuel_server('REMOTE_ADDR');
    }
    else
    {
      // detection failed, return a dummy IP
      return '0.0.0.0';
    }
  }
}
if( ! function_exists('fuel_user_agent') )
{
  function fuel_user_agent()
  {
    return fuel_server('HTTP_USER_AGENT', '');
  }
}

if( ! function_exists('fuel_server') )
{
  function fuel_server($index, $default = null)
  {
    return fuel_fetch_from_array($_SERVER, strtoupper($index), $default);
  }
}


if( ! function_exists('fuel_fetch_from_array') )
{
  function fuel_fetch_from_array(&$array, $index, $default = null)
  {
    if (is_null($index))
    {
      return $array;
    }
    elseif ( ! isset($array[$index]))
    {
      return $default;
    }

    return $array[$index];
  }
}

  /**
   * Serialize an array
   *
   * This function first converts any slashes found in the array to a temporary
   * marker, so when it gets unserialized the slashes will be preserved
   *
   * @access  private
   * @param array
   * @return  string
   */
if( ! function_exists('fuel_serialize') )
{
  function fuel_serialize($data)
  {
    if (is_array($data))
    {
      foreach ($data as $key => $val)
      {
        if (is_string($val))
        {
          $data[$key] = str_replace('\\', '{{slash}}', $val);
        }
      }
    }
    else
    {
      if (is_string($data))
      {
        $data = str_replace('\\', '{{slash}}', $data);
      }
    }

    return serialize($data);
  }
}

  // --------------------------------------------------------------------

  /**
   * Unserialize
   *
   * This function unserializes a data string, then converts any
   * temporary slash markers back to actual slashes
   *
   * @access  private
   * @param array
   * @return  string
   */
if( ! function_exists('fuel_unserialize') )
{
  function fuel_unserialize($data)
  {
    $data = @unserialize($data);

    if (is_array($data))
    {
      foreach ($data as $key => $val)
      {
        if (is_string($val))
        {
          $data[$key] = str_replace('{{slash}}', '\\', $val);
        }
      }

      return $data;
    }

    return (is_string($data)) ? str_replace('{{slash}}', '\\', $data) : $data;
  }
}

///////////////////////////////////////
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
