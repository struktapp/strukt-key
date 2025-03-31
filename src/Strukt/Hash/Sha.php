<?php

namespace Strukt\Hash;

class Sha{

	/**
	 * @param string $whatever
	 * 
	 * @return string
	 */
	public static function once256(string $whatever){

		return hash("sha256", $whatever);
	}

	/**
	 * @param string $whatever
	 * 
	 * @return string
	 */
	public static function dbl256(string $whatever){

		return self::once256(self::once256($whatever));
	}
}