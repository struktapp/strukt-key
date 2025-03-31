<?php

namespace Strukt\Ssl;

use Strukt\Contract\AbstractKeyPair;

class KeyPair extends AbstractKeyPair{

	/**
	 * @param mixed $keyOrPemFile
	 * @param string $pass = ""
	 */
	public function __construct(mixed $keyOrPemFile="", string $pass=""){	
		
		if(!empty($keyOrPemFile)){

			if($this->expectsPassword($keyOrPemFile) && empty(trim($pass)))
				throw new \Exception("Private key expects a password!");

			$this->privateKey = PrivateKeyBuilder::fromPem($keyOrPemFile, $pass);
		}
	}

	/**
	 * @param string $contents
	 * 
	 * @return bool
	 */
	public function expectsPassword(string $contents):bool{

		if(strpos($contents, 'file:///') !== false)
			$contents = file_get_contents($contents);		
		
		return strpos($contents, 'ENCRYPTED') !== false;
	}
}