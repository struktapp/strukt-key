<?php

namespace Strukt\Ssl\Csr;

class UniqueName{

	private $distgName;
	protected $keys;

	/**
	 * @param array $names
	 */
	public function __construct(array $names){

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

	/**
	 * @param string $key
	 */
	public function get(string $key){

		return $this->distgName[$this->keys[$key]];
	}

	/**
	 * @return array
	 */
	public function getDetails():array{

		return $this->distgName;
	}
}