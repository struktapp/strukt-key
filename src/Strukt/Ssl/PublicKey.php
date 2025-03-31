<?php

namespace Strukt\Ssl;

use OpenSSLAsymmetricKey as SslAsymKey;

class PublicKey{

	private $res;

	/**
	 * @param OpenSSLAsymmetricKey $res
	 */
	public function __construct(SslAsymKey $res){

		// if(!is_resource($res))
			// throw new \Exception("Is not resource!");
			
		$this->res = $res;
	}

	/**
	 * @param mixed $data
	 * 
	 * @return static
	 */
	public static function fromPrivateKeyPem(mixed $data):static{

		return static::fromPrivateKey(openssl_pkey_get_private($data)['key']);
	}

	/**
	 * @return OpenSSLAsymmetricKey $res
	 * 
	 * @return static
	 */
	public static function fromPrivateKey(SslAsymKey $res):static{

		return static::fromPem(openssl_pkey_get_details($res)['key']);
	}

	/**
	 * @param mixed $key
	 * 
	 * @return static
	 */
	public static function fromPem(mixed $key):static{

		return new self(openssl_get_publickey($key));
	}

	/**
	 * @return OpenSSLAsymmetricKey
	 */
	public function getResource():SslAsymKey{

		return $this->res;
	}

	/**
	 * @return array|false
	 */
	public function getKey():array|false{

		return openssl_pkey_get_details($this->res);
	}

	/**
	 * @return string
	 */
	public function getPem():string{

		$pubKeyDetails = $this->getKey();

		return $pubKeyDetails["key"];
	}
}