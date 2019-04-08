<?php

namespace Strukt\Ssl\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Fs;
use Strukt\Ssl\{PublicKey, Cipher};

/**
* cry:enc         Encrypt message
* 
* Usage:
*   
*      cry:enc --pub <pub> --out <out> <msg>
*
* Arguments:
*
*      msg        Encrypted message or filename
* 
* Options:
* 
*      --pub -p   File name
*      --out -o   Output file name
*/
class Encrypt extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$pub = $in->get("pub");
		$output = $in->get("out");
		$msg = $in->get("msg");

		if(Fs::isFile($msg))
			$msg = Fs::cat($msg);

		$pubKey = PublicKey::fromPem(sprintf("file://%s/%s", getcwd(), $pub));

		$encrypted = Cipher::encryptWith($pubKey, $msg);

		Fs::touchWrite($output, $encrypted);

		$out->add("Message encrypted successfully.");
	}
}