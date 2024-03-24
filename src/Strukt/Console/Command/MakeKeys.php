<?php

namespace Strukt\Console\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

/**
* make:keys     Create/Recreate Keys in cfg directory
*
* Usage:
*
*      make:keys <name>
*
* Arguments:
*
*     name   options crypt|cry,jwt|auth,csrf|form
*/
class MakeKeys extends \Strukt\Console\Command{ 

	public function makeCsrf(){

		$vector = bin2hex(\Strukt\Ssl\FixVector::make());
		$duration = 120;

		return str("key = ")->concat($vector)->concat("\n")
				->concat("duration = ")->concat($duration)
				->yield();
	}

	public function makeJwt(){

		$vector = bin2hex(\Strukt\Ssl\FixVector::make());
		$cipher = "HS256";
		$expire = 3600; //an hour
		$issuer = "http://localhost:8081";
		$timezone = "Africa/Nairobi";

		return str("timezone = ")->concat($timezone)->concat("\n")
					->concat("issuer = ")->concat($issuer)->concat("\n")
					->concat("secret = ")->concat($vector)->concat("\n")
					->concat("; expire = ")->concat("300")->concat("\n")
					->concat("algo = ")->concat($cipher)->concat("\n")
					->concat("expire = ")->concat($expire)->concat("\n")
					->yield();
	}

	public function makeCry(){

		$vector = bin2hex(\Strukt\Ssl\FixVector::make());
		$cipher = "AES-128-CBC";
		$key = sha1(rand());

		return str("vector = ")->concat($vector)->concat("\n")
				->concat("algo = ")->concat($cipher)->concat("\n")
				->concat("key = ")->concat($key)->concat("\n")
				->yield();
	}

	public function execute(Input $in, Output $out){

		$name = $in->get("name");
		$names = array(

			"auth"=>"jwt",
			"jwt"=>"jwt",
			"cry"=>"crypt",
			"crypt"=>"crypt",
			"form"=>"csrf",
			"csrf"=>"csrf"
		);

		if(negate(arr(array_keys($names))->has($name)))
			raise(sprintf("Invalid name %s!", $name));

		$name = str($name);
		if($name->equals("jwt") || $name->equals("auth"))
			$ini_data = $this->makeJwt();

		if($name->equals("csrf") || $name->equals("form"))
			$ini_data = $this->makeCsrf();

		if($name->equals("crypt") || $name->equals("cry"))
			$ini_data = $this->makeCry();

		$ini_file = str($names[$name->yield()])->concat(".ini")->yield();

		$root_dir = reg()->exists("env.root_dir")?env("root_dir"):"./";
		$cfg_dir = sprintf("%s/cfg", $root_dir);

		fs($root_dir)->mkdir("cfg");
		$ini_exists = fs($cfg_dir)->isPath($ini_file);

		if(!$ini_exists)
			fs($cfg_dir)->touchWrite($ini_file, $ini_data);

		if($ini_exists)
			fs($cfg_dir)->overwrite($ini_file, $ini_data);

		$out->add(sprintf("cfg/%s was created!", $ini_file));
	}
}