<?php

/*
 * @package    symfony
 * @subpackage dwCryptPlugin
 * @author     Dustin Whittle <dustin.whittle@symfony-project.com>
 * @version    SVN: $Id: sfCryptTest.php 6909 2008-01-03 06:46:15Z dwhittle $
 */

require_once(dirname(__FILE__).'/../../../test/bootstrap/unit.php');
require_once(dirname(__FILE__).'/../lib/sfCrypt.class.php');

$t = new lime_test(2, new lime_output_color());
$sfCrypt = new sfCrypt('ecb', 'tripledes', 'sfcrypt_default_key');

// sfCrypt->encrypt()
$t->diag("sfCrypt->encrypt()");
$t->is($sfCrypt->encrypt('test'), 'y1aNsFHhjIo=', 'sfCrypt->encrypt() takes a string as its first argument');

// sfCrypt->decrypt()
$t->diag('sfCrypt->decrypt()');
$t->is($sfCrypt->decrypt('y1aNsFHhjIo='), 'test', 'sfCrypt->decrypt() takes a string as its first argument');

?>
