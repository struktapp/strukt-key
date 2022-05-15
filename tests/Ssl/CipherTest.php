<?php

use Strukt\Ssl\KeyPair;
use Strukt\Ssl\KeyPairBuilder;
use Strukt\Ssl\Cipher;

use Strukt\Ssl\All;

use PHPUnit\Framework\TestCase;

class CipherTest extends TestCase{

	public function setUp():void{

		$this->message = "Hi, my is what? My is who? My name is (Tski tski) Slim Shady!";
	}

	public function testKeyPairBuilderCipher(){

		$cipher = All::makeKeys()->useCipher();
		$encrypted = $cipher->encrypt($this->message);
		$decrypted = $cipher->decrypt($encrypted);

		$this->assertEquals($this->message, $decrypted);
	}

	public function testKeyPairEncrypDecryptNoPass(){

		$this->markTestSkipped('@requires:privKeyFile');

		// $path = sprintf("file:///%s", realpath("fixture/no-pass/pri.pem"));

		// $keys = new KeyPair($path);

		// $c = new Cipher($keys);
		// $encrypted = $c->encrypt($this->message);
		// $decrypted = $c->decrypt($encrypted);

		// $this->assertEquals($this->message, $decrypted);
	}

	public function testKeyPairEncryptDecryptWithPass(){

		$this->markTestSkipped('@requires:privKeyFile');

		// $path = sprintf("file:///%s", realpath("fixture/pass/pri.pem"));

		// $keys = new KeyPair($path, "p@55w0rd");

		// $cipher = new Cipher($keys);
		// $encrypted = $cipher->encrypt($this->message);
		// $decrypted = $cipher->decrypt($encrypted);

		// $this->assertEquals($this->message, $decrypted);
	}
}