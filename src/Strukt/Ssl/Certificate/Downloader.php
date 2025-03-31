<?php

namespace Strukt\Ssl\Certificate;

use Strukt\Type\Str;

class Downloader{

	private $resource;

	/**
	 * @param string $url
	 */
	public function __construct(string $url){

		$url = new Str($url);
		if($url->startsWith("https://") == false)
			$url = $url->prepend("https://");

		$stream = stream_context_create(array(

			"ssl" => array(

				"capture_peer_cert" => true
			)
		));

		$read = fopen((string)$url, "rb", false, $stream);
		$context = stream_context_get_params($read);

		$this->resource = ($context["options"]["ssl"]["peer_certificate"]);
	}

	/**
	 * @return resource
	 */
	public function getResource(){

		return $this->resource;
	}
}