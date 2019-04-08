<?php

namespace Strukt\Ssl\Csr;

class Downloader{

	private $var;

	public function __construct($url){

		$stream = stream_context_create(array(

			"ssl" => array(

				"capture_peer_cert" => true
			)
		));

		$read = fopen($url, "rb", false, $stream);
		$cont = stream_context_get_params($read);

		$this->var = ($cont["options"]["ssl"]["peer_certificate"]);
	}

	public function toArray(){

		return $this->var;
	}
}