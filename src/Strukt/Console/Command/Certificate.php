<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

/**
* cert:cert          Validate SSL certs
* 
* Usage:
*   
*      cert:cert <url> <val>
*
* Arguments:
*
*      url         Url e.g google.com
*      val         Value
*
*                  issuer, domain, subject, algo, from, 
*                  to, selfsigned, expired, fingerprint, all
*/
class Certificate extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$url = $in->get("url");
		$vals = $in->get("val");

		$attrs = array(

			"issuer", 
			"domain",
			"algo", 
			"from", 
			"to", 
			"selfsigned", 
			"expired", 
			"isprecert",
			"fingerprint"
		);

		if(preg_match("/:/", $vals))
			$vals = explode(":", $vals);
		elseif($vals == "all")
			$vals = $attrs;
		else
			$vals = array($vals);

		$vals = array_intersect($vals, $attrs);

		$downloader = new \Strukt\Ssl\Certificate\Downloader($url);

		$parser = new \Strukt\Ssl\Certificate\Parser($downloader->getResource());

		foreach($vals as $val){

			switch ($val){
				case 'issuer':
						$out->add(sprintf("issuer: %s\n", $parser->getIssuer()));
					break;
				case 'domain':
						$out->add(sprintf("domain: %s\n", $parser->getDomain()));
					break;
				case 'algo':
						$out->add(sprintf("algo: %s\n", $parser->getSignatureAlgo()));
					break;
				case 'from':
						$from = $parser->getFromDate()->format("Y-m-d H:i:s");
						$out->add(sprintf("from: %s\n", $from));
				break;
				case 'to':
						$to = $parser->getToDate()->format("Y-m-d H:i:s");
						$out->add(sprintf("to: %s\n", $to));
					break;
				case 'expired':
						$out->add(sprintf("expired: %s\n", $parser->isExpired()));
					break;
				case 'selfsigned':
						$out->add(sprintf("self-signed: %s\n", $parser->isSelfSigned()));
					break;
				case 'isprecert':
						$out->add(sprintf("pre-certificate: %s\n", $parser->isPreCertificate()));
					break;
				case 'fingerprint':
						$out->add(sprintf("fingerprint: %s\n", $parser->getFingerPrint()));
					break;
				default:
						throw new \Exception(sprintf("Unidentified value [%s]!", $val));
					break;
			}
		}
	}
}