<?php

namespace Strukt\Ssl;

use Strukt\Contract\AbstractKeyPair;

class KeyPair extends AbstractKeyPair{

	public function __construct($keyOrPemFile, $pass=""){	
		
		if($this->expectsPassword($keyOrPemFile) && empty(trim($pass)))
			throw new \Exception("Private key expects a password!");

		$this->privateKey = PrivateKeyBuilder::fromPem($keyOrPemFile, $pass);
	}

	public function expectsPassword($contents){

		if(strpos($contents, 'file:///') !== false)
			$contents = file_get_contents($contents);		
		
		return strpos($contents, 'ENCRYPTED') !== false;
	}
}