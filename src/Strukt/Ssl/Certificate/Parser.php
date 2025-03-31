<?php

namespace Strukt\Ssl\Certificate;

use Strukt\Builder\Collection as CollectionBuilder;
use OpenSSLCertificate as SslCert;

class Parser{

	private $cert;
	private $fingerprint;

	/**
	 * @param \OpenSSLCertificate $res
	 */
	public function __construct(SslCert|string $res){

		// if(!is_resource($res))
			// throw new \Exception("Certificate parser requires resource!");
			
		$this->fingerprint = openssl_x509_fingerprint($res);

		$builder = new CollectionBuilder();
		$this->cert = $builder->fromAssoc(openssl_x509_parse($res));
	}

	public function getIssuer(){

		return $this->cert->get("issuer.CN");
	}

	public function getDomain(){

		return $this->cert->get("subject.CN");
	}

	public function getSignatureAlgo(){

		return $this->cert->get("signatureTypeSN");
	}

	/**
	 * @return \DateTime
	 */
	public function getFromDate(){

		$from = new \DateTime();
		$from->setTimestamp($this->cert->get("validFrom_time_t"));

		return $from;	
	}

	/**
	 * @return \DateTime
	 */
	public function getToDate():\DateTime{

		$to = new \DateTime();
		$to->setTimestamp($this->cert->get("validTo_time_t"));

		return $to;		
	}

	/**
     * @return "true"|"false"
     */
	public function isExpired():string{

        return ["false","true"][$this->getToDate() < (new \DateTime())];
    }

    /**
     * @return "true"|"false"
     */
    public function isSelfSigned():string{

    	return ["false","true"][$this->getDomain() == $this->getIssuer()];
    }

    /**
     * @return "true"|"false"
     */
    public function isPreCertificate():string{

    	return ["false","true"][$this->cert->exists("extensions.ct_precert_poison")];
    }

    /**
     * @return string|false
     */
    public function getFingerPrint():string|false{

    	return $this->fingerprint;
    }
}