<?php

namespace Strukt\Ssl;

class PublicKey{

	private $res;

	public function __construct($res){

		if(!is_resource($res))
			throw new \Exception("Is not resource!");
			
		$this->res = $res;
	}

	public static function fromPem($key){

		return new self(openssl_get_publickey($key));
	}

	public function getResource(){

		return $this->res;
	}

	public function getKey(){

		return openssl_pkey_get_details($this->res);
	}

	public function getPem(){

		$pubKeyDetails = $this->getKey();

		return $pubKeyDetails["key"];
	}
}