<?php

namespace Strukt\Ssl;

class Config{

	private $config = array();

	public function __construct(Array $config = []){

		$config = array(

		 	"config" => "fixture/openssl.cnf", 
		 	"digest_alg" => "sha256", 
		 	"x509_extensions" => "v3_ca", 
		 	"req_extensions" => "v3_req", 
		 	"private_key_bits" => 4096, 
		 	"private_key_type" => OPENSSL_KEYTYPE_RSA, 
		 	"encrypte_key" => true
		 );

		$this->config = array_merge($this->config, $config);
	}

	public function getAll(){

		return $this->config;
	}
}