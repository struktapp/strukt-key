<?php

/**
* @link https://goo.gl/gr94AR
*
* the self-signed certificate is signed by the same party that owns the private key, while the 
* digital identity certificate returned by the certificate authority upon receiving the certificate 
* signing request is signed using the certificate authority's private key.
* 
* That is correct.
* 
* Therefore the self-signed certificate is guaranteed to work for encryption but not identification, 
* while the digital identification certificate from the certificate authority is guaranteed to work * for encryption and identification.
* 
* This gets kinda tricky. The CA signed cert is only trusted for identification because the CA is 
* include in the pre-populated certificate store built into browsers/OS. If I didn't have a *
* pre-populated certificate store neither of them would be trusted.
* 
* If I downloaded and verified certificate of that self-signed key and added it to my certificate 
* store, then I could trust it for all purposes.
*
* So from the point of view of the technology the only difference is that your self-signed cert 
* wouldn't be built into my browser/OS.
*/
namespace Strukt\Ssl\Csr;

use Strukt\Ssl\Config;
use Strukt\Ssl\KeyPairContract;
use Strukt\Ssl\PrivateKey;

class Csr{

	private $distgName;
	private $keys;
	private $csr;
	private $cert;
	private $confList = null;

	public function __construct(UniqueName $unique, KeyPairContract $keys, Config $conf = null){

		$this->distgName = $unique->getDetails();
		if(empty($this->distgName))
			throw new \Exception("Distinguishing Name is empty!");

		$this->keys = $keys;

		$privKeyRes = $keys->getPrivateKey()->getResource();

		if(is_null($conf))
			$conf = new Config();
		
		$this->confList = $conf->getAll();

		$this->csr = openssl_csr_new($this->distgName, $privKeyRes, $this->confList);
	}

	//self signed
	public function signOwn($days=365){

		$privKeyRes = $this->keys->getPrivateKey()->getResource();

		$this->cert = openssl_csr_sign($this->csr, null, $privKeyRes, $days, $this->confList);
	}

	public function sign($csr, $cert, $days=365){

		$privKeyRes = $this->keys->getPrivateKey()->getResource();

		$this->cert = openssl_csr_sign($csr, $cert, $privKeyRes, $days, $this->confList);
	}

	public function getCsr(){

		openssl_csr_export($this->csr, $csr);

		return $csr;
	}

	public function getCert(){

		openssl_x509_export($this->cert, $cert);

		return $cert;
	}

	public function getSubject(){

		$subject = openssl_csr_get_subject($this->csr);

		return $subject;
	}

	public function parse(){

		return self::parseCert($this->cert);
	}

	public function verify(){

		$privKey = $this->builder->getPrivateKey();

		$isOkay = self::verifyCert($privKey, $this->cert);

		return $isOkay;
	}

	public static function parseCert($cert){

		$cert = openssl_x509_parse($cert);

		return $cert;
	}

	public static function verifyCert(PrivateKey $privKey, $cert){

		$privKey = $privKey->getPem();

		$isOkay = openssl_x509_check_private_key($cert, $privKey);

		return $isOkay;
	}
}
