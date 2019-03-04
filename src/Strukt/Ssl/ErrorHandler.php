<?php

namespace Strukt\Ssl;

trait ErrorHandler{

	public static function getErrors(){

        $message = array();
        while ($msg = openssl_error_string())
            $message[] = $msg;
        
        if(!empty($message))
        	throw new \Exception(implode(', ', $message));
    }

    public static function clearErrors(){

        while ($msg = openssl_error_string());
    }
}