<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Fs;
use Strukt\Ssl\All;

/**
* cert:selfsign          Self Signed Certificate
*
* Usage:
*
*      cert:selfsign <privkey> [<out>]
*
* Arguments:
*
*     privkey   Private Key Path
*     out       Certificate Path
*/
class CertificateSelfSign extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$priv = $in->get("privkey");
		// $pass = $in->get("pass");
		$output = $in->get("out");

		// if(Fs::isFile($msg))
			// $msg = Fs::cat($msg);

		$kpath = sprintf("file://%s/%s", getcwd(), $priv);

		// if(!empty($pass))
		// 	$keyPair = new KeyPair($priv, $pass);
		// else
		// 	$keyPair = new KeyPair($priv);

		// $cipher = new Cipher($keyPair);
		// $decrypted = $cipher->decrypt($msg);

		$data = All::keyPath($kpath)->useCsr()->selfSign()->getCert();

		if(!empty($output))
			Fs::touchWrite($output, $data);
		else
			echo $data;

		$out->add("Message decrypted successfully.");
	}
}