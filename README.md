php5-xcom
=========

X.Commerce message handling extension for PHP5

Installing/Configuring
======================

Debian pkg's are provided under debs/

<pre>
$ phpize && ./configure
$ make && sudo make install
# echo "extension=xcom.so" >> /your/php.ini
</pre>

A gcc-like toolchain, php headers, and libavro are required.

Examples
========
Sending a message to X.commerce:
```php
<?php

$data = new stdClass();
$data->member_id = 123495585343;

$xcom = new Xcom("http://api.sandbox.x.com/fabric/", "fabric_token",
"capability_token");

var_dump($xcom->send("/topic/", $data, '{"json": "schema"}'));

/*
 * Output:
 * int(200)
 */

?>
```

Receiving a message from X.commerce:
```php
<?php

$xcom = new Xcom("http://api.sandbox.x.com/fabric/", "fabric_token",
"capability_token");

var_dump($xcom->decode(file_get_contents("php://input"), '{"json": "schema"}'));

/*
 * Output:
 * object(stdClass)#87 (2) { ["username"]=> string(2) "hi" ["active"]=> int(38347473) }
 */
?>
```
Enable debug:
```php
<?php

$xcom = new Xcom("http://api.sandbox.x.com/fabric/", "fabric_token",
"capability_token");

$xcom->__debug = true;

?>
```

Encoding a message:
```php
<?php

$data = new stdClass();
$data->member_id = 123495585343;

$xcom = new Xcom("http://api.sandbox.x.com/fabric/", "fabric_token",
"capability_token");

var_dump($xcom->encode($data, '{"json": "schema"}'));

/*
 * Output:
 * a binary string that contains an avro message, which can be POST'ed to
 * X.Commerce
 */

?>
```
