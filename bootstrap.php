<?php

error_reporting(E_ALL & ~E_STRICT & ~E_NOTICE & ~E_WARNING & ~E_DEPRECATED);

$loader = require("vendor/autoload.php");
$loader->add("Strukt",__DIR__."/src/");