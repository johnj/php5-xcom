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
    AC_CHECK_PROG(HAVE_CMAKE, cmake, true, false)
    if test "x$HAVE_CMAKE" = "xfalse"; then
      AC_MSG_ERROR([*** CMake is required to build libavro, please install CMake before continuing])
    else
      AC_MSG_NOTICE([*** libavro is required before continuing, please cd into the avro/ directory by running:])
      AC_MSG_NOTICE([*** $ cd avro && cmake . && sudo make install])
      AC_MSG_ERROR([*** libavro not found.])
    fi
    
  ])

  PHP_ADD_LIBRARY(curl,,XCOM_SHARED_LIBADD)
  PHP_ADD_LIBRARY(pthread,,XCOM_SHARED_LIBADD)

  PHP_NEW_EXTENSION(xcom, xcom.c, $ext_shared)
  CFLAGS="$CFLAGS -Wall -g"

  PHP_ADD_EXTENSION_DEP(xcom, curl)
fi
