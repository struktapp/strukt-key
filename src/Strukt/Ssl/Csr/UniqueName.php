<?php

namespace Strukt\Ssl\Csr;

class UniqueName{

	private $distgName;
	protected $keys;

	public function __construct(Array $names){

		$this->keys = array(

		    "country"=>"countryName",
		    "loc"=>"stateOrProvinceName",
		    "subLoc"=>"localityName",
		    "org"=>"organizationName",
		    "orgUnit"=>"organizationalUnitName",
		    "common"=>"commonName",
		    "email"=>"emailAddress"
		);

		foreach($this->keys as $alias=>$key)
			if(in_array($alias, array_keys($names)))
				$this->distgName[$key] = $names[$alias];
	}

	public function get($key){

		return $this->distgName[$this->keys[$key]];
	}

	public function getDetails(){

		return $this->distgName;
	}
}