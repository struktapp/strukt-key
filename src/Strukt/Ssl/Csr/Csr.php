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

use Strukt\Ssl\PrivateKey;

class Csr{

	private $csr;
	private $cert;

	public function __construct($csr = null, $cert = null){

		$this->setCsr($csr);
		$this->setCert($cert);
	}

	public function getCsr(){

		return $this->csr;
	}

	public function setCsr($csr){

		if(!is_null($csr))
			openssl_csr_export($csr, $this->csr);
	}

	public function getCert(){

		return $this->cert;
	}

	public function setCert($cert){

		if(!is_null($cert))
			openssl_x509_export($cert, $this->cert);
	}

	public function getSubject(){

		$subject = openssl_csr_get_subject($this->csr);

		return $subject;
	}

	public function parse(){

		return self::parseCert($this->cert);
	}

	public function verifyWith(PrivateKey $privKey):boolean{

		return self::verifyCert($privKey, $this->cert);
	}

	public static function parseCert($cert){

		$cert = openssl_x509_parse($cert);

		return $cert;
	}

	public static function verifyCert(PrivateKey $privKey, $cert){

		$privKey = $privKey->getPem();

		return openssl_x509_check_private_key($cert, $privKey);
	}

	public static function sign(Csr $request, PrivateKey $privKey, array $settings = null){

		$privKeyRes = $privKey->getResource();

		$csr = $request->getCsr();
		$cert = $request->getCert();

		$days = 365;
		$serial = 0;

		$options = null;
		if(!is_null($privKey->getConf()))
			$options = $privKey->getConf()->getAll();

		if(!empty($settings)){

			if(array_key_exists("days", $settings))
				$days = $settings["days"];

			if(array_key_exists("serial_no", $settings))
				$serial = $settings["serial_no"];
		}

		$usercert = openssl_csr_sign($csr, $cert, $privKeyRes, $days, $options, $serial);

		return $usercert;
	}
}