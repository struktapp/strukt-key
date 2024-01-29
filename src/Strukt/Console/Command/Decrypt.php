<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Fs;
use Strukt\Ssl\{KeyPair, Cipher};

/**
* cry:dec          Decrypt message
* 
* Usage:
*   
*      cry:dec --priv <prikey> [--pass <pass>] [--out <out>] <msg>
*
* Arguments:
*
*      msg         Message or filename
* 
* Options:
* 
*      --priv -k   File name
*      --pass -p   Password
*	   --out  -o   Output file
*/
class Decrypt extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$priv = $in->get("priv");
		$pass = $in->get("pass");
		$output = $in->get("out");
		$msg = $in->get("msg");

		if(Fs::isFile($msg))
			$msg = Fs::cat($msg);

		$priv = sprintf("file://%s/%s", getcwd(), $priv);

		if(!empty($pass))
			$keyPair = new KeyPair($priv, $pass);
		else
			$keyPair = new KeyPair($priv);

		$cipher = new Cipher($keyPair);
		$decrypted = $cipher->decrypt($msg);

		if(!empty($output))
			Fs::touchWrite($output, $decrypted);
		else
			echo $decrypted;

		$out->add("Message decrypted successfully.");
	}
}