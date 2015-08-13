<?php

/*
 * This file is part of the symfony package.
 * (c) 2004-2006 Dustin Whittle <dustin.whittle@symfony-project.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

/**
 *
 * sfCrypt class.
 *
 * This class provides an abstraction layer to the PHP module mcrypt. Provides encryption/decryption.
 *
 * @package    symfony
 * @subpackage sfCryptPlugin
 * @author     Dustin Whittle <dustin.whittle@symfony-project.com>
 */
class sfCrypt
{

  private
    $engine    = 0,
    $pear      = 0,
    $td        = 0,
    $mode      = 0,
    $algorithm = 0,
    $key       = 0;

  /**
   * Constructs a td with the given mode, algorithm, key as a parameter.
   *
   * @param string mode
   * @param string algorithm
   * @param string key
   * @return void;
   *
   * @link http://www.php.net/mcrypt
   * @link http://pear.php.net/package/Crypt_Blowfish
   *
   * @example $sfCrypt = new sfCrypt(); $encrypted_text = $sfCrypt->encrypt('something_secret'); $plain_text = $sfCrypt->decrypt($encrypted_text)
   *
   */

  public function __construct($mode = null, $algorithm = null, $key = null)
  {

    $this->mode = ($mode == null) ? sfConfig::get('sf_crypt_mode', 'ecb') : $mode;
    $this->algorithm = ($algorithm == null) ? sfConfig::get('sf_crypt_algorithm', 'tripledes') : $algorithm;
    $this->key = ($key === null) ? sfConfig::get('sf_crypt_key', 'sfcrypt_default_key') : $key;

    if(!extension_loaded('mcrypt'))
    {
      dl((PHP_SHLIB_SUFFIX == 'dll') ? 'php_' : '' . 'mcrypt.' . PHP_SHLIB_SUFFIX);
    }

    if(extension_loaded('mcrypt'))
    {
      $this->engine = 'mcrypt';
      $this->td = mcrypt_module_open($this->algorithm, '', $this->mode, '') ;
      $iv = substr(mcrypt_create_iv(mcrypt_enc_get_iv_size($this->td), strstr(PHP_OS, "WIN") ? MCRYPT_RAND : MCRYPT_DEV_RANDOM), 0, mcrypt_enc_get_iv_size($this->td));
      $this->key = substr($this->key, 0, mcrypt_enc_get_key_size($this->td));
      mcrypt_generic_init($this->td, $this->key, $iv);
    }
    elseif(include_once('Crypt/Blowfish.php'))
    {
      $this->engine = 'pear';
      $this->pear = new Crypt_Blowfish($this->key);
    }
    else
    {
      $this->engine = 'n/a';
      throw new sfException('sfCrypt: You must install the php mcrypt module (http://www.php.net/mcrypt) or the PEAR package Crypt_Blowfish (http://pear.php.net/package/Crypt_Blowfish).');
    }

  }

  /**
  * Sets the encryption mode
  *
  * @return void
  * @access public
  */
  public function setMode($mode)
  {
    $this->mode = $mode;
  }

  /**
  * Sets the encryption algorithm
  *
  * @return void
  * @access public
  */
  public function setAlgorithm($algorithm)
  {
    $this->algorithm = $algorithm;
  }

  /**
  * Sets the encryption key
  *
  * @return void
  * @access public
  */
  public function setKey($key)
  {
    $this->key = $key;
  }

  /**
  * Returns the encryption mode
  *
  * @return string
  * @access public
  */
  public function getMode()
  {
    return $this->mode;
  }

  /**
  * Returns the encryption algorithm
  *
  * @return string
  * @access public
  */
  public function getAlgorithm()
  {
    return $this->algorithm;
  }

  /**
  * Returns the encryption key
  *
  * @return string
  * @access public
  */
  public function getKey()
  {
    return $this->key;
  }

  /**
  * Returns the encrypted string
  *
  * @param string string
  * @return string
  * @access public
  */
  public function encrypt($string)
  {
    if(0 == strlen($string))
    {
      throw new sfException('sfCrypt: You can not encrypt an empty string.');
    }

    if($this->engine == 'mcrypt')
    {
      return base64_encode(mcrypt_generic($this->td, $string));
    }
    elseif($this->engine == 'pear')
    {
      return $this->pear->encrypt($string);
    }
    else
    {
      return false;
    }
  }

  /**
  * Returns the decrypted string
  *
  * @param string string
  * @return string
  * @access public
  */
  public function decrypt($string)
  {

    if(0 == strlen($string))
    {
      throw new sfException('sfCrypt: You can not decrypt an empty string.');
    }

    if($this->engine == 'mcrypt')
    {
      return trim(mdecrypt_generic($this->td, base64_decode($string)));
    }
    elseif($this->engine == 'pear')
    {
      return $this->pear->decrypt($string);
    }
    else
    {
      return false;
    }
  }

  /**
  * Deconstructs a td.
  *
  * @return void
  * @access public
  */
  public function __destruct()
  {
    if($this->engine == 'mcrypt')
    {
      mcrypt_generic_deinit($this->td);
      mcrypt_module_close($this->td);
    }
  }
}

?>