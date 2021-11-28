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
use Strukt\Ssl\Csr\Csr as CsrRequest;

class CsrBuilder{

	private $distgName;
	private $keys;
	private $csr;
	private $cert;
	private $confList = null;

	public function __construct(UniqueName $unique, KeyPairContract $keys, Config $conf = null){

		$this->distgName = $unique->getDetails();
		if(empty($this->distgName))
			throw new \Exception("Distinguishing Name is empty!");

		$privKeyRes = $keys->getPrivateKey()->getResource();

		if(is_null($conf))
			$conf = new Config();
		
		$this->confList = $conf->getAll();

		$this->csr = openssl_csr_new($this->distgName, $privKeyRes, $this->confList);
	}

	public function getCsr():CsrRequest{

		return new CsrRequest($this->csr);
	}
}
