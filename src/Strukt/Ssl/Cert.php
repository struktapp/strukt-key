<?php

namespace Strukt\Ssl;

use Strukt\Fs;

class Cert{

	private $data;

	private function __construct(string $path){

		if(!Fs::isPath($path))
			throw new \Exception(sprintf("[%s] does not exist!", $path));			

		$this->data = Fs::cat($path);
	}

	public static function withPath(string $path){

		return new self($path);
	}

	public function getResource(){

		return openssl_get_publickey($this->data);
	}
}