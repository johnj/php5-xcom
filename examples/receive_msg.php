<?php

$xcom = new Xcom("https://api.sandbox.x.com/fabric/", "YOUR_FABRIC_TOKEN", "YOUR_CAPABILITY_TOKEN");
var_dump($xcom->decode(file_get_contents("php://input"), file_get_contents("schema.avpr")));

?>
