<?php

namespace Strukt;

class Csrf{

	private $data;
	private $iat;
	private $eat;

	/**
	 * @param array|string $data
	 * @param integer $duration = 300
	 */
	public function __construct(array|string $data, int $duration=300){

		$this->codec = codec();

		$this->data = $data;
		$this->iat = when("now")->getTimestamp();
		$this->eat = when(sprintf("now + %d seconds", $duration))->getTimestamp();
	}

	/**
	 * @param array|string $data
	 * @param integer $duration = 300
	 * 
	 * @return static
	 */
	public static function make(array|string $data, int $duration=300):static{

		return new self($data, $duration);
	}

	/**
	 * @param string $encrypted
	 * 
	 * @return string|false
	 */
	public static function decode(string $encrypted):string|false{

		return codec()->decode($encrypted);		
	}

	/**
	 * @param string $token
	 * 
	 * @return bool
	 */
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