<?php

$data = new stdClass();
$data->a_string = "hi";
$data->how_long = 238474757;
$data->boole = true;
$data->a_dub = 3.14159265;
$data->nul = null;

$xcom = new Xcom("https://api.sandbox.x.com/fabric/", "YOUR_FABRIC_TOKEN", "YOUR_CAPABILITY_TOKEN");
$xcom->__debug = true;

$http_code = $xcom->send("/topic/path", $data, file_get_contents("schema.avpr"));

?>
