<?php

namespace Strukt;

use Firebase\JWT\JWT as FireJWT;
use Firebase\JWT\Key;
// use Firebase\JWT\SignatureInvalidException;
// use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException as FireJWTExpiredException;
// use DomainException;
// use InvalidArgumentException;
// use UnexpectedValueException;

class Jwt{

    protected $secrect;
    protected $issuedAt;
    protected $expire;

    function __construct(){

        // set your default time-zone
        date_default_timezone_set(config("jwt.timezone"));
        $this->issuedAt = time();

        // Token Validity (3600 second = 1hr)
        // $this->expire = $this->issuedAt + 3600;
        $this->expire = $this->issuedAt + number(config("jwt.expire"))->yield();

        // Set your strong secret or signature
        $this->secrect = config("jwt.secret");
    }

    /**
     * @param string|array $data
     * 
     * @return string
     */
    public function encode(string|array $data):string{

        $token = array(
            //Adding the identifier to the token (who issue the token)
            "iss" => config("jwt.issuer"),
            "aud" => config("jwt.issuer"),
            // Adding the current timestamp to the token, for identifying that when the token was issued.
            "iat" => $this->issuedAt,
            // Token expiration
            "exp" => $this->expire,
            // Payload
            "data" => $data
        );

        return FireJWT::encode($token, $this->secrect, config("jwt.algo"));
    }

    /**
     * @param string $token
     * 
     * @return array|string|null
     */
    public function decode(string $token):array|string|null{
        
        try {

            $decode = FireJWT::decode($token, new Key($this->secrect, config("jwt.algo")));

            return $decode;
        }
        catch (FireJWTExpiredException|\Exception $e) {

            $logger = cmd("service.logger");
            if(notnull($logger))
                $logger->error($e->getMessage());

            return null;
        }
    }

    /**
     * @param \stdClass $data
     * 
     * @return bool
     */
    public static function valid(\stdClass $data):bool{

        return negate(when()->gt(when($data->exp)));
    }
}