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
use OpenSSLCertificateSigningRequest as SslCsr;
use OpenSSLCertificate as SslCert;

class Csr{

	private $csr;
	private $cert;

	/**
	 * @param \OpenSSLCertificateSigningRequest|string|null $csr
	 */
	public function __construct(SslCsr|string|null $csr = null){

		$this->setCsr($csr);
		// $this->setCert($cert);
	}

	public function getCsr(){

		return $this->csr;
	}

	/**
	 * @param \OpenSSLCertificateSigningRequest|string $csr
	 * 
	 * @return void
	 */
	public function setCsr(SslCsr|string $csr):void{

		// if(!is_null($csr))
		openssl_csr_export($csr, $this->csr);
	}

	public function getCert(){

		return $this->cert;
	}

	/**
	 * @param \OpenSSLCertificate|string $cert
	 * 
	 * @return void
	 */
	public function exportCert(\SslCert|string $cert):void{

		// if(!is_null($cert))
		openssl_x509_export($cert, $this->cert); //returns bool
	}

	/**
	 * @return array|false
	 */
	public function getSubject():array|false{

		$subject = openssl_csr_get_subject($this->csr);

		return $subject;
	}

	/**
	 * @return array|false
	 */
	public function parse():array|false{

		return self::parseCert($this->cert);
	}

	/**
	 * @param \Strukt\Ssl\PrivateKey $privKey
	 * 
	 * @return bool
	 */
	public function verifyWith(PrivateKey $privKey):bool{

		return self::verifyCert($privKey, $this->cert);
	}

	/**
	 * @param OpenSSLCertificate|string $cert
	 * 
	 * @return array|false
	 */
	public static function parseCert(SslCert|string $cert):array|false{

		$cert = openssl_x509_parse($cert);

		return $cert;
	}

	/**
	 * @param \Strukt\Ssl\PrivateKey $privKey
	 * @param \OpenSSLCertificate|string $cert
	 * 
	 * @return bool
	 */
	public static function verifyCert(PrivateKey $privKey, SslCert|string $cert):bool{

		$privKey = $privKey->getPem();

		return openssl_x509_check_private_key($cert, $privKey);
	}

	/**
	 * @param \Strukt\Ssl\Csr\Csr $request
	 * @param \Strukt\Ssl\PrivateKey $privKey
	 * @param ?array $settings
	 * 
	 * @return \OpenSSLCertificate|false
	 */
	public static function sign(Csr $request, PrivateKey $privKey, ?array $settings = null):SslCert|false{

		$privKeyRes = $privKey->getKey();

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