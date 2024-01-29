<?php

error_reporting(E_ALL & ~E_STRICT & ~E_NOTICE & ~E_WARNING & ~E_DEPRECATED);

$loader = require("vendor/autoload.php");
$loader->add("Strukt",__DIR__."/src/");

if(!Strukt\Fs::isPath("fixture/pitsolu")){
            
    exec("php console cry:keys pitsolu");
    exec("php console cry:keys pitsolu_next --pass p@55w0rd");
    exec("php console cert:selfsign pitsolu cacert.pem");
    exec("mv pitsolu* ./fixture");
    exec("mv cacert.pem ./fixture");
}