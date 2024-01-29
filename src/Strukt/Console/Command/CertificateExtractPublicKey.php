<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Fs;
use Strukt\Ssl\PublicKey;
use Strukt\Ssl\Cert;

/**
* cert:xpub        Certificate Extract Public Key
*
* Usage:
*
*      cert:xpub --cert <cert> 
*
* Options:
*
*	   --cert -c   Certificate Path
*/
class CertificateExtractPublicKey extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$cert = $in->get("cert");

		$cpath = sprintf("file://%s/%s", getcwd(), $cert);
		
		$pubKey = Cert::withPath($cpath)->extractPublicKey();

		$out->add($pubKey->getPem());
	}
}