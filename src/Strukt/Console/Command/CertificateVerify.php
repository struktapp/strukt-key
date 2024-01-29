<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Fs;
use Strukt\Ssl\All;

/**
* cert:verify        Verify Certificate
*
* Usage:
*
*      cert:verify <privkey> <cert>
*
* Arguments:
*
*     privkey   Private Key Path
*     cert      Certificate Path
*/
class CertificateVerify extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$priv = $in->get("privkey");
		$cert = $in->get("cert");

		$cpath = sprintf("file://%s/%s", getcwd(), $cert);
		$kpath = sprintf("file://%s/%s", getcwd(), $priv);

		$verified = All::keyPath($kpath)->withCert($cpath)->verify();

		$msg = "Failed!";
		if($verified)
			$msg = "Success.";

		$out->add($msg);
	}
}