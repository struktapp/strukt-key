<?php

namespace Strukt\Hash\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

/**
* hash:sha          Simple Hash Algorithm
* 
* Usage:
*   
*      hash:sha  <type> <value>
*
* Arguments:
*
*      type    Algo type either dbl, once   
*      value   Value to hash
*/
class Sha extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$value = $in->get("value");
		$type = $in->get("type");

		if(!in_array($type, array("dbl","once")))
			throw new \Exception("Algo type must be declared.");
			
		if($type == "once")
			$hash = \Strukt\Hash\Sha::once256($value);
		elseif($type == "dbl")
			$hash = \Strukt\Hash\Sha::dbl256($value);

		$out->add($hash);
	}
}