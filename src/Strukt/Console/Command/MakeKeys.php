<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

/**
* make:keys     Create/Recreate Keys in cfg/crypt.ini
*/
class MakeKeys extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$vector = bin2hex(\Strukt\Ssl\FixVector::make());
		$cipher = "AES-128-CBC";
		$key = sha1(rand());

		fs()->mkdir("cfg");
		fs("cfg")->overwrite("crypt.ini", "vector = ${vector}
algo = ${cipher}
key = ${key}");

		$out->add("cfg/crypt.ini was created!");
	}
}