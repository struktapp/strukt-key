<?php

namespace Strukt\Ssl;

use Strukt\Ssl\Csr\Csr;
use Strukt\Fs;

class PrivateKey{

	private $res = null;
	private $pass = null;
	private $conf = null;

	public function __construct(\OpenSSLAsymmetricKey $res){

		// if(!is_resource($res))
			// throw new \Exception("Is not a resource!");

		$this->res = $res;
	}

	public static function fromPath(string $path){

		$pem_private_key = Fs::cat($path);

		return new self(openssl_pkey_get_private($pem_private_key));
	}

	public static function fromPem($data){

		return new self(openssl_pkey_get_private($data));
	}

	public function getKey(){

		return $this->res;
	}

	public function withConf(Config $conf){

		$this->conf = $conf;

		return $this;
	}


	public function getConf(){

		return $this->conf;
	}

	public function withPass($pass){

		$this->pass = $pass;

		return $this;
	}

	/**
	* Extract the private key from $res to $privKey
	*/
	public function getPem(){

		$confList = null;
		if(!is_null($this->conf))
			$confList = $this->conf->getAll();

		openssl_pkey_export($this->res, $priKey, $this->pass, $confList);

		return $priKey;
	}

	public function getPublicKey(){

		return PublicKey::fromPrivateKey($this->getKey());
	}

	/**
	 * self signing
	 */
	public function getSelfSignedCert(Csr $request, $days=365){

		$confList = null;
		if(!is_null($this->conf))
			$confList = $this->conf->getAll();

		$privKeyRes = $this->getKey();

		$cert = openssl_csr_sign($request->getCsr(), null, $privKeyRes, $days, $confList);

		return $cert;
	}
}