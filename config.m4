dnl
dnl X.Commerce config.m4
dnl

PHP_ARG_WITH(xcom, for X.Commerce support,
    [  --with-xcom		Include X.Commerce support])

if test "$PHP_XCOM" != "no"; then
  PHP_SUBST(XCOM_SHARED_LIBADD)

  AC_CHECK_LIB([avro], [avro_schema_from_json], [
    PHP_ADD_LIBRARY(avro,,XCOM_SHARED_LIBADD)
    AC_CHECK_HEADER([avro.h], [
    HAVE_AVRO=yes
    ])
  ],
  [
    AC_MSG_NOTICE([*** libavro is required before continuing, please install libavro])
    AC_MSG_NOTICE([*** detailed instructions: https://github.com/johnj/php5-xcom/blob/master/README.md@%:@libavro])
    AC_MSG_ERROR([*** libavro not found.])
  ])

  AC_CHECK_HEADER([curl/curl.h], , 
   [AC_MSG_ERROR([Couldn't find or include curl.h (do you have the libcurl dev package installed?])],
  )

  PHP_ADD_LIBRARY(curl,,XCOM_SHARED_LIBADD)
  PHP_ADD_LIBRARY(pthread,,XCOM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(xcom, xcom.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  PHP_ADD_EXTENSION_DEP(xcom, curl)
fi
