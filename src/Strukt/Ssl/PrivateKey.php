<?php

namespace Strukt\Ssl;

use Strukt\Ssl\Csr\Csr;
use Strukt\Fs;
use OpenSSLCertificate as SslCert;
use OpenSSLAsymmetricKey as SslAsymKey;

class PrivateKey{

	private $res = null;
	private $pass = null;
	private $conf = null;

	/**
	 * @param \OpenSSLAsymmetricKey $res
	 */
	public function __construct(SslAsymKey $res){

		// if(!is_resource($res))
			// throw new \Exception("Is not a resource!");

		$this->res = $res;
	}

	/**
	 * @param string $path
	 * 
	 * @return static
	 */
	public static function fromPath(string $path):static{

		$pem_private_key = Fs::cat($path);

		return new self(openssl_pkey_get_private($pem_private_key));
	}

	/**
	 * @param mixed $data
	 * 
	 * @return static
	 */
	public static function fromPem(mixed $data):static{

		return new self(openssl_pkey_get_private($data));
	}

	/**
	 * @return \OpenSSLAsymmetricKey
	 */
	public function getKey():SslAsymKey{

		return $this->res;
	}

	/**
	 * @param \Strukt\Ssl\Config $conf
	 * 
	 * @return static
	 */
	public function withConf(Config $conf):static{

		$this->conf = $conf;

		return $this;
	}

	/**
	 * @return \Strukt\Ssl\Config
	 */
	public function getConf(){

		return $this->conf;
	}

	/**
	 * @param string $pass
	 * 
	 * @return static
	 */
	public function withPass(string $pass):static{

		$this->pass = $pass;

		return $this;
	}

	/**
	* Extract the private key from $res to $privKey
	* 
	* @return mixed
	*/
	public function getPem():mixed{

		$confList = null;
		if(!is_null($this->conf))
			$confList = $this->conf->getAll();

		openssl_pkey_export($this->res, $priKey, $this->pass, $confList);

		return $priKey;
	}

	/**
	 * @return \Strukt\Ssl\PublicKey
	 */
	public function getPublicKey():PublicKey{

		return PublicKey::fromPrivateKey($this->getKey());
	}

	/**
	 * self signing
	 * 
	 * @param \Strukt\Ssl\Csr\Csr $request
	 * @param integer $days = 365
	 * 
	 * @return \OpenSSLCertificate|false
	 */
	public function getSelfSignedCert(Csr $request, int $days=365):SslCert|false{

		$confList = null;
		if(!is_null($this->conf))
			$confList = $this->conf->getAll();

		$privKeyRes = $this->getKey();

		$cert = openssl_csr_sign($request->getCsr(), null, $privKeyRes, $days, $confList);

		return $cert;
	}
}