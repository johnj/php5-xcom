/*
+----------------------------------------------------------------------+
| See LICENSE file for further copyright information                   |
+----------------------------------------------------------------------+
| Authors: John Jawed <jawed@php.net>                                  |
+----------------------------------------------------------------------+
*/

#ifndef PHP_XCOM_H
#define PHP_XCOM_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

#ifdef PHP_WIN32
#include "win32/time.h"
#endif

#include "SAPI.h"
#include "zend_API.h"
#include "zend_variables.h"
#include "ext/standard/head.h"
#include "php_globals.h"
#include "php_main.h"
#include "php_ini.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_rand.h"
#include "ext/standard/php_smart_str.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "ext/standard/php_versioning.h"
#include "ext/standard/url.h"
#include "php_variables.h"
#include "zend_exceptions.h"
#include "zend_interfaces.h"
#include "php_globals.h"
#include "ext/standard/file.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_lcg.h"
#include "ext/pcre/php_pcre.h"
#include "php_network.h"

#include <curl/curl.h>
#include <avro.h>
#include <avro/io.h>

#define CLEANUP_CURL_AND_FORM(f,h)  \
    curl_easy_cleanup(h); \
curl_formfree(f);

#ifndef Z_ADDREF_P
#define Z_ADDREF_P(pz) (++(pz)->refcount)
#define Z_ADDREF_PP(ppz) Z_ADDREF_P(*(ppz))
#endif

#ifndef Z_DELREF_P
#define Z_DELREF_P(pz) (--(pz)->refcount)
#endif

#if ZEND_MODULE_API_NO >= 20100409
#ifndef ZEND_ENGINE_2_4
#define ZEND_ENGINE_2_4
#endif
#endif

#define PHP_XCOM_VERSION "1.0.0"

#ifdef ZEND_ENGINE_2_4
# define XCOM_READ_PROPERTY(_obj, _mem, _type) zend_get_std_object_handlers()->read_property(_obj, _mem, _type, key TSRMLS_CC)
# define XCOM_WRITE_PROPERTY(_obj, _mem, _val) zend_get_std_object_handlers()->write_property(_obj, _mem, _val, key TSRMLS_CC)
#else
# define XCOM_READ_PROPERTY(_obj, _mem, _type) zend_get_std_object_handlers()->read_property(_obj, _mem, _type TSRMLS_CC)
# define XCOM_WRITE_PROPERTY(_obj, _mem, _val) zend_get_std_object_handlers()->write_property(_obj, _mem, _val TSRMLS_CC)
#endif

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION > 2) || PHP_MAJOR_VERSION > 5
# define XCOM_ARGINFO
# define XCOM_IS_CALLABLE_CC TSRMLS_CC
#else
# define XCOM_ARGINFO static
# define XCOM_IS_CALLABLE_CC
#endif

#define XCOM_ME(func, arg_info, flags) PHP_ME(xcom, func, arg_info, flags)
#define XCOM_METHOD(func) PHP_METHOD(xcom, func)

#define __stringify_1(x)    #x
#define __stringify(x)      __stringify_1(x)
#define __XCOM_EXT_VER PHP_XCOM_VERSION
#define XCOM_EXT_VER __stringify(__XCOM_EXT_VER)
#define XCOM_USER_AGENT "PECL-XCom/" __stringify(__XCOM_EXT_VER)
#define XCOM_HTTP_PORT 80
#define XCOM_HTTPS_PORT 443
#define XCOM_MAX_HEADER_LEN 512L

extern zend_module_entry xcom_module_entry;

#define phpext_xcom_ptr &oauth_module_entry

#define PHP_XCOM_API

#define XCOM_HTTP_METHOD_POST "POST"

#define XCOM_SSLCHECK_NONE 0
#define XCOM_SSLCHECK_HOST 1
#define XCOM_SSLCHECK_PEER 2
#define XCOM_SSLCHECK_BOTH (OAUTH_SSLCHECK_HOST | OAUTH_SSLCHECK_PEER)

/* errors */
#define XCOM_ERR_BAD_REQUEST 400
#define XCOM_ERR_BAD_AUTH 401
#define XCOM_ERR_INTERNAL_ERROR 503

/* values */
#define XCOM_CALLBACK_OOB "oob"

#define XCOM_PARAM_PREFIX "xcom_"
#define XCOM_PARAM_PREFIX_LEN 6

#ifdef ZTS
#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(xcom);
PHP_MSHUTDOWN_FUNCTION(xcom);
PHP_MINFO_FUNCTION(xcom);

#ifdef ZTS
#define XCOM(v) TSRMG(xcom_globals_id, zend_xcom_globals *, v)
#else
#define XCOM(v) (xcom_globals.v)
#endif

typedef struct {
    smart_str headers_in;
    smart_str headers_out;
    smart_str body_in;
    smart_str body_out;
    smart_str curl_info;
} php_xcom_debug;

typedef struct {
    zend_object zo;
    HashTable *properties;
    smart_str lastresponse;
    smart_str headers_in;
    smart_str headers_out;
    uint sslcheck; /* whether we check for SSL verification or not */
    uint debug; /* verbose output */
    long timeout; /* timeout in milliseconds */
    zval *this_ptr;
    zval *debugArr;
    char *fabric_url;
    char *fabric_token;
    char *cap_token;
    php_xcom_debug *debug_info;
    void ***thread_ctx;
} php_xcom;

#if (PHP_MAJOR_VERSION >= 6)
#define ZEND_HASH_KEY_STRVAL(key) key.s
typedef zstr zend_hash_key_type;
#else
#define ZEND_HASH_KEY_STRVAL(key) key
typedef char * zend_hash_key_type;
#endif

#ifndef Z_ADDREF_P
#define Z_ADDREF_P(x) ZVAL_ADDREF(x)
#endif

#ifndef zend_parse_parameters_none
#define zend_parse_parameters_none()    \
    zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "")
#endif

#ifndef zend_hash_quick_del
#define HASH_DEL_KEY_QUICK 2
#define zend_hash_quick_del(ht, arKey, nKeyLength, h) \
    zend_hash_del_key_or_index(ht, arKey, nKeyLength, h, HASH_DEL_KEY_QUICK)
#endif

#define XCOM_ME(func, arg_info, flags) PHP_ME(xcom, func, arg_info, flags)
#define XCOM_METHOD(func) PHP_METHOD(xcom, func)
#define FREE_ARGS_HASH(a) \
    if (a) { \
        zend_hash_destroy(a); \
        FREE_HASHTABLE(a); \
    }

#define INIT_SMART_STR(a) \
    (a).len = 0; \
(a).c = NULL;

#define HTTP_IS_REDIRECT(http_response_code) \
    (http_response_code > 300 && http_response_code < 304)

#define INIT_DEBUG_INFO(a) \
    INIT_SMART_STR((a)->headers_out); \
INIT_SMART_STR((a)->body_in); \
INIT_SMART_STR((a)->body_out); \
INIT_SMART_STR((a)->curl_info);

#define FREE_DEBUG_INFO(a) \
    smart_str_free(&(a)->headers_out); \
smart_str_free(&(a)->body_in); \
smart_str_free(&(a)->body_out); \
smart_str_free(&(a)->curl_info); 

/* this and code that uses it is from ext/curl/interface.c */
#define CAAL(s, v) add_assoc_long_ex(info, s, sizeof(s), (long) v);
#define CAAD(s, v) add_assoc_double_ex(info, s, sizeof(s), (double) v);
#define CAAS(s, v) add_assoc_string_ex(info, s, sizeof(s), (char *) (v ? v : ""), 1);

#define HTTP_RESPONSE_CAAS(zvalpp, header, storkey) { \
    if (0==strncasecmp(Z_STRVAL_PP(zvalpp),header,sizeof(header)-1)) { \
        CAAS(storkey, (Z_STRVAL_PP(zvalpp)+sizeof(header)-1)); \
    } \
}

#define HTTP_RESPONSE_CAAD(zvalpp, header, storkey) { \
    if (0==strncasecmp(Z_STRVAL_PP(zvalpp),header,sizeof(header)-1)) { \
        CAAD(storkey, strtoul(Z_STRVAL_PP(zvalpp)+sizeof(header)-1,NULL,10)); \
    } \
}

#define HTTP_RESPONSE_CODE(zvalpp) \
    if (response_code < 0 && 0==strncasecmp(Z_STRVAL_PP(zvalpp),"HTTP/", 5) && Z_STRLEN_PP(zvalpp)>=12) { \
        response_code = strtol(Z_STRVAL_PP(zvalpp)+9, NULL, 10); \
        CAAL("http_code", response_code); \
    }

#define HTTP_RESPONSE_LOCATION(zvalpp) \
    if (0==strncasecmp(Z_STRVAL_PP(zvalpp), "Location: ", 10)) { \
        strlcpy(soo->last_location_header, Z_STRVAL_PP(zvalpp)+10, XCOM_MAX_HEADER_LEN); \
    }


#define ADD_DEBUG_INFO(a, k, s, t) \
    if(s.len) { \
        smart_str_0(&(s)); \
        if(t) { \
            tmp = php_trim((s).c, (s).len, NULL, 0, NULL, 3 TSRMLS_CC); \
            add_assoc_string((a), k, tmp, 1); \
            efree(tmp); \
        } else { \
            add_assoc_string((a), k, (s).c, 1); \
        } \
    }

#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#define XCOM_FREE(i) if(i) efree(i);

#if LIBCURL_VERSION_NUM >= 0x071304
#define XCOM_PROTOCOLS_ALLOWED CURLPROTO_HTTP | CURLPROTO_HTTPS
#endif
#endif

/**
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 * vim600: fdm=marker
 * vim: noet sw=4 ts=4 expandtab
 */
