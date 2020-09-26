<?php

namespace Strukt\Ssl\Command;

use Strukt\Console\Input;
use Strukt\Console\Output;

use Strukt\Fs;
use Strukt\Ssl\Config as SslConfig;

/**
* dump:cfg          Dump Ssl Configuration
* 
* Usage:
*   
*      dump:cfg [--sslcfg <sslcfg>]
* 
* Options:
* 
*      --sslcfg -s   path to openssl.cnf file
*/
class DumpCfg extends \Strukt\Console\Command{ 

	public function execute(Input $in, Output $out){

		$sslcfg = $in->get("sslcfg");

		$cfgs = SslConfig::dump();

		if(!empty($sslcfg))
			$cfgs["config"] = $sslcfg;

		foreach($cfgs as $key=>$val)
			$ini[] = sprintf("%s = %s", $key, $val);
	
		Fs::touchWrite("ssl.cfg.ini", implode("\n", $ini));

		$out->add("Dumped [ssl.cfg.ini] successfully.");
	}
}