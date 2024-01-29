<?php

namespace Strukt\Ssl\Certificate;

use Strukt\Builder\Collection as CollectionBuilder;

class Parser{

	private $cert;
	private $fingerprint;

	public function __construct(\OpenSSLCertificate $res){

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

	public function getFromDate(){

		$from = new \DateTime();
		$from->setTimestamp($this->cert->get("validFrom_time_t"));

		return $from;	
	}

	public function getToDate(){

		$to = new \DateTime();
		$to->setTimestamp($this->cert->get("validTo_time_t"));

		return $to;		
	}

	public function isExpired(){

        return ["false","true"][$this->getToDate() < (new \DateTime())];
    }

    public function isSelfSigned(){

    	return ["false","true"][$this->getDomain() == $this->getIssuer()];
    }

    public function isPreCertificate(){

    	return ["false","true"][$this->cert->exists("extensions.ct_precert_poison")];
    }

    public function getFingerPrint(){

    	return $this->fingerprint;
    }
}