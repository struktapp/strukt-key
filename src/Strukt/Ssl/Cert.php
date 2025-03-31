<?php

namespace Strukt\Ssl;

use Strukt\Fs;
use OpenSSLAsymmetricKey as SslAsymKey;

class Cert{

	private $data;

	/**
	 * @param string $path
	 */
	private function __construct(string $path){

		if(!Fs::isPath($path))
			throw new \Exception(sprintf("[%s] does not exist!", $path));			

		$this->data = Fs::cat($path);
	}

	/**
	 * @param string $path
	 * 
	 * @return static
	 */
	public static function withPath(string $path):static{

		return new self($path);
	}

	/**
	 * @return \OpenSSLAsymmetricKey|false
	 */
	public function getResource():SslAsymKey|false{

		// return openssl_get_publickey($this->data);
		return openssl_pkey_get_public($this->data);
	}

	/**
	 * @return \Strukt\Ssl\PublicKey
	 */
	public function extractPublicKey(){

		$details = openssl_pkey_get_details($this->getResource());

		return new PublicKey(openssl_get_publickey($details["key"]));
	}
}