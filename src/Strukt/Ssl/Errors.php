<?php

namespace Strukt\Ssl;

trait Errors{

	public static function get(){

        $message = array();
        while ($msg = openssl_error_string())
            $message[] = $msg;
        
        return $message;
    }

    public static function clear(){

        while ($msg = openssl_error_string());
    }
}