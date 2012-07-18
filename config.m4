dnl
dnl X.Commerce config.m4
dnl

PHP_ARG_WITH(xcom, for X.Commerce support,
[  --with-xcom		Include X.Commerce support])

if test "$PHP_XCOM" != "no"; then
  PHP_SUBST(XCOM_SHARED_LIBADD)

  PHP_ADD_LIBRARY(curl,,XCOM_SHARED_LIBADD)
  PHP_ADD_LIBRARY(avro,,XCOM_SHARED_LIBADD)
  PHP_ADD_LIBRARY(pthread,,XCOM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(xcom, xcom.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  PHP_ADD_EXTENSION_DEP(oauth, curl)
fi
