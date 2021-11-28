<?php

namespace Strukt\Ssl;

use Strukt\Ssl\Csr\Csr;

class PrivateKey{

	private $res = null;
	private $pass = null;
	private $conf = null;

	public function __construct($res){

		if(!is_resource($res))
			throw new \Exception("Is not a resource!");

		$this->res = $res;
	}

	public function getResource(){

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

		return new PublicKey($this->getResource());
	}

	/**
	 * self signing
	 */
	public function getSelfSignedCert(Csr $request, $days=365){

		$confList = null;
		if(!is_null($this->conf))
			$confList = $this->conf->getAll();

		$privKeyRes = $this->getResource();

		$cert = openssl_csr_sign($request->getCsr(), null, $privKeyRes, $days, $confList);

		return $cert;
	}
}