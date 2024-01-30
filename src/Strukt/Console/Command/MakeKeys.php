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

		try{

			$root_dir = env("root_dir");
			$cfg_dir = sprintf("%s/cfg", $root_dir);

		}
		catch(\Exception $e){

			$root_dir = "./";
			$cfg_dir = "./cfg";
		}

$ini_data = "vector = ${vector}
algo = ${cipher}
key = ${key}";

		fs($root_dir)->mkdir("cfg");
		$ini_exists = fs($cfg_dir)->isPath("crypt.ini");

		if(!$ini_exists)
			fs($cfg_dir)->touchWrite("crypt.ini", $ini_data);

		if($ini_exists)
			fs($cfg_dir)->overwrite("crypt.ini", $ini_data);

		$out->add("cfg/crypt.ini was created!");
	}
}