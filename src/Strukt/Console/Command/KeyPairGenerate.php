<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Ssl\KeyPairBuilder;
use Strukt\Fs;

/**
* cry:keys          Key Pair Builder
*
* Usage:
*
*      cry:keys <name> [--pass <pass>]
*
* Arguments:
*
*     name   file name
*
* Options:
*
*      --pass -p   Password
*/
class KeyPairGenerate extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$name = $in->get("name");
		$pass = $in->get("pass");

		if(empty($name))
			throw new \Exception("Must enter a name!");
			
		if(!empty($pass))
			$keyPair = new KeyPairBuilder();
		else
			$keyPair = new KeyPairBuilder(null, $pass);

		$privKey = $keyPair->getPrivateKey()->getPem();
		$pubKey = $keyPair->getPublicKey()->getPem();

		Fs::touchWrite($name, $privKey);
		Fs::touchWrite(sprintf("%s.pub", $name), $pubKey);

		$out->add("Key pair generated successfully.");
	}
}