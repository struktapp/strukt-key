<?php

namespace Strukt\Ssl;

class PublicKey{

	private $res;

	public function __construct(\OpenSSLAsymmetricKey $res){

		// if(!is_resource($res))
			// throw new \Exception("Is not resource!");
			
		$this->res = $res;
	}

	public static function fromPrivateKeyPem($data){

		return static::fromPrivateKey(openssl_pkey_get_private($data)['key']);
	}

	public static function fromPrivateKey($res){

		return static::fromPem(openssl_pkey_get_details($res)['key']);
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