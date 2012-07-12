#!/bin/sh
# original @ https://raw.github.com/nicolasff/phpredis/f3dff08cfaf5d6a7a78bd87e70ee19c92f0ad27d/mkdeb-apache2.sh

VER="1.0.0"
phpize
./configure CFLAGS="-O3"
make clean all
DIR=`php-config --extension-dir | cut -c 2-`

rm -rf debian

mkdir -p debian
mkdir -p debian/DEBIAN
mkdir -p debian/$DIR

cp debian.control debian/DEBIAN/control

UBUNTU=`uname -v | grep -ci ubuntu`
mkdir -p debian/etc/php5/apache2/conf.d/
if [ $UBUNTU = "0" ]; then
    mkdir -p debian/etc/php5/cli/conf.d/
fi

echo "extension=xcom.so" >> debian/etc/php5/apache2/conf.d/xcom.ini

if [ $UBUNTU = "0" ]; then
    cp debian/etc/php5/apache2/conf.d/xcom.ini debian/etc/php5/cli/conf.d/xcom.ini
fi

cp modules/xcom.so debian/$DIR
PKG_NAME="php5-xcom-${VER}-`lsb_release -c -s`-`uname -m`.deb"
dpkg -b debian ${PKG_NAME}
rm -rf debian/

