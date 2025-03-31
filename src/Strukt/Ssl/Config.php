<?php

namespace Strukt\Ssl;

use Strukt\Fs;
use Strukt\Raise;

class Config{

	private $config = array();

	/**
	 * @param array $config = []
	 */
	public function __construct(array $config = []){

		$this->config = static::dump();
		if(Fs::isFile("ssl.cfg.ini"))
			$this->config = parse_ini_file("ssl.cfg.ini");

		if(!Fs::isFile($this->config["config"]))
			new Raise(sprintf("Unable to find [%s] file!", $this->config["config"]));

		$this->config = array_merge($this->config, $config);
	}

	/**
	 * @return array
	 */
	public static function dump():array{

		return array(

		 	"config" => "fixture/openssl.cnf", 
		 	"digest_alg" => "sha256", 
		 	"x509_extensions" => "v3_ca", 
		 	"req_extensions" => "v3_req", 
		 	"private_key_bits" => 4096, 
		 	"private_key_type" => OPENSSL_KEYTYPE_RSA, 
		 	"encrypte_key" => true
		 );
	}

	/**
	 * @return array
	 */
	public function getAll():array{

		return $this->config;
	}
}