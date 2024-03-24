<?php

namespace Strukt;

class Csrf{

	private $data;
	private $iat;
	private $eat;

	public function __construct(array|string $data, int $duration=300){

		$this->codec = codec();

		$this->data = $data;
		$this->iat = when("now")->getTimestamp();
		$this->eat = when(sprintf("now + %d seconds", $duration))->getTimestamp();
	}

	public static function make(array|string $data, int $duration=300){

		return new self($data, $duration);
	}

	public static function decode($encrypted){

		return codec()->decode($encrypted);		
	}

	public static function valid(string $token):bool{

		$expiry = when(token(static::decode($token))->get("eat"));

        return negate(when()->gt($expiry));
    }

	public function __toString(){

		$token = tokenize([

			"data"=>$this->data,
			"iat"=>$this->iat,
			"eat"=>$this->eat
		]);

		return $this->codec->encode($token);
	}
}