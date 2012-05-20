/*
+----------------------------------------------------------------------+
| See LICENSE file for further copyright information                   |
+----------------------------------------------------------------------+
| Authors: John Jawed <jawed@php.net>                                  |
+----------------------------------------------------------------------+
*/

#include "php_xcom.h"

static zend_class_entry *xcom_ce;
static zend_class_entry *xcom_exc_ce;
static zend_object_handlers xcom_object_handlers;

static zend_object_value php_xcom_clone_obj(zval *this_ptr TSRMLS_DC);
static php_xcom* php_xcom_new(zend_class_entry *ce TSRMLS_DC);
static zend_object_value php_xcom_register_object(php_xcom *xc TSRMLS_DC);

static void xcom_object_free_storage(void *obj TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom;

    xcom = (php_xcom *) obj;

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
    if (xcom->zo.guards) {
        zend_hash_destroy(xcom->zo.guards);
        FREE_HASHTABLE(xcom->zo.guards);
    }
    if (xcom->zo.properties) {
        zend_hash_destroy(xcom->zo.properties);
        FREE_HASHTABLE(xcom->zo.properties);
    }
#else
    zend_object_std_dtor(&xcom->zo TSRMLS_CC);
#endif

    if (xcom->lastresponse.c) {
        smart_str_free(&xcom->lastresponse);
    }
    if (xcom->headers_in.c) {
        smart_str_free(&xcom->headers_in);
    }
    if (xcom->headers_out.c) {
        smart_str_free(&xcom->headers_out);
    }
    efree(obj);
}
/* }}} */

static inline php_xcom* php_xcom_fetch_obj(zval *obj TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom = (php_xcom *)zend_object_store_get_object(obj TSRMLS_CC); 
    xcom->this_ptr = obj;
    return xcom;
}

static zend_object_value php_xcom_register_object(php_xcom *xc TSRMLS_DC) /* {{{ */
{
    zend_object_value rv;

    rv.handle = zend_objects_store_put(xc, (zend_objects_store_dtor_t)zend_objects_destroy_object, xcom_object_free_storage, NULL TSRMLS_CC);
    rv.handlers = (zend_object_handlers *) &xcom_object_handlers;
    return rv;
}
/* }}} */
static zend_object_value php_xcom_clone_obj(zval *this_ptr TSRMLS_DC) /* {{{ */
{
    php_xcom *old_obj = (php_xcom *)zend_object_store_get_object(this_ptr TSRMLS_CC);
    php_xcom *new_obj = php_xcom_new(old_obj->zo.ce TSRMLS_CC);
    zend_object_value new_ov = php_xcom_register_object(new_obj TSRMLS_CC);

    zend_objects_clone_members(&new_obj->zo, new_ov, &old_obj->zo, Z_OBJ_HANDLE_P(this_ptr) TSRMLS_CC);

    return new_ov;
}
/* }}} */

static inline php_xcom* php_xcom_fetch_obj_store(zval *obj TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom = (php_xcom *)zend_object_store_get_object(obj TSRMLS_CC);
    xcom->this_ptr = obj;
    return xcom;
}
/* }}} */

long php_xcom_send_msg(php_xcom *xcom, char *payload, char *topic, char *schema_uri, int debug) /* {{{ */
{
    CURL *curl;
    struct curl_slist *curl_headers = NULL;
    long response_code = -1;
    char auth_hdr[4096] = "", fab_url[4096] = "", schema_ver_hdr[32] = "", schema_uri_hdr[1024] = "";
    char content_type_hdr[] = "Content-Type: avro/binary";
    
    curl = curl_easy_init();

    if(xcom->cap_token) {
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: %s", xcom->cap_token);
    }

    if(xcom->fabric_url) {
        snprintf(fab_url, sizeof(fab_url), "%s%s", xcom->fabric_url, topic ? topic : "");
    }

    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: %s", xcom->cap_token);
    if(schema_uri) {
        snprintf(schema_uri_hdr, sizeof(schema_uri_hdr), "X-XC-SCHEMA-URI: %s", schema_uri);
    }
    snprintf(schema_ver_hdr, sizeof(schema_ver_hdr), "X-XC-SCHEMA-VERSION: %s", "1.0.0");

    curl_headers = curl_slist_append(curl_headers, auth_hdr);
    curl_headers = curl_slist_append(curl_headers, schema_uri_hdr);
    curl_headers = curl_slist_append(curl_headers, schema_ver_hdr);
    curl_headers = curl_slist_append(curl_headers, content_type_hdr);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    curl_easy_setopt(curl, CURLOPT_URL, fab_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(payload));
    if(debug) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
    }

    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    curl_easy_cleanup(curl);
    return response_code;
}
/* }}} */

void php_xcom_obj_from_avro_msg(zval **obj, char *msg, char *json_schema TSRMLS_DC) /* {{{ */
{
    avro_schema_t schema;
    avro_schema_error_t error = NULL;
    avro_value_iface_t *iface;
    avro_value_t val;
    size_t sz, i, vsz;

    const char *av_s, av_b;
    int32_t av_d32;
    int64_t av_d64;
    double av_d;
    float av_f;

    avro_reader_t reader = avro_reader_memory(msg, strlen(msg));

    avro_schema_from_json(json_schema, strlen(json_schema), &schema, &error);

    iface = avro_generic_class_from_schema(schema);

    avro_generic_value_new(iface, &val);

    avro_value_read(reader, &val);

    avro_value_get_size(&val, &sz);

    for(i=0; i<sz; ++i) {
        avro_value_t field_val;
        const char *field_name;
        avro_value_get_by_index(&val, i, &field_val, &field_name);

        switch(avro_value_get_type(&field_val)) {
            case AVRO_STRING:
                avro_value_get_string(&field_val, &av_s, &vsz);
                zend_update_property_string(zend_standard_class_def, *obj, field_name, strlen(field_name), av_s TSRMLS_CC);
            break;
            case AVRO_NULL:
                zend_update_property_null(zend_standard_class_def, *obj, field_name, strlen(field_name) TSRMLS_CC);
            break;
            case AVRO_BOOLEAN:
                avro_value_get_boolean(&field_val, (int *)&av_b);
                zend_update_property_bool(zend_standard_class_def, *obj, field_name, strlen(field_name), av_b TSRMLS_CC);
            break;
            case AVRO_INT64:
                avro_value_get_long(&field_val, &av_d64);
                zend_update_property_long(zend_standard_class_def, *obj, field_name, strlen(field_name), av_d64 TSRMLS_CC);
            break;
            case AVRO_INT32:
                avro_value_get_int(&field_val, &av_d32);
                zend_update_property_long(zend_standard_class_def, *obj, field_name, strlen(field_name), av_d32 TSRMLS_CC);
            break;
            case AVRO_FLOAT:
                avro_value_get_float(&field_val, &av_f);
                zend_update_property_double(zend_standard_class_def, *obj, field_name, strlen(field_name), (double)av_f TSRMLS_CC);
            break;
            case AVRO_DOUBLE:
                avro_value_get_double(&field_val, &av_d);
                zend_update_property_double(zend_standard_class_def, *obj, field_name, strlen(field_name), av_d TSRMLS_CC);
            break;
            default:
            break;
        }
    }
    avro_value_decref(&val);
    avro_value_iface_decref(iface);
    avro_schema_decref(schema);
    avro_reader_free(reader);
    return;
}

static char* php_xcom_avro_record_from_obj(zval *obj, char *json_schema TSRMLS_DC) /* {{{ */
{
    int i;
    HashTable *myht;
    char *msg_buf = NULL;
    avro_writer_t writer = NULL;
    avro_value_t val;
    size_t writer_bytes = 0;
    avro_schema_t schema = NULL;
    avro_schema_error_t error = NULL;
    avro_value_iface_t *iface;

    avro_schema_from_json(json_schema, strlen(json_schema), &schema, &error);

    if(schema==NULL) {
      php_error_docref(NULL TSRMLS_CC, E_ERROR, "invalid schema: %s", avro_strerror());
      return NULL;
    }

    iface = avro_generic_class_from_schema(schema);

    avro_generic_value_new(iface, &val);

    myht = Z_OBJPROP_P(obj);

    if (myht && myht->nApplyCount > 1) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "recursion detected");
        return NULL;
    }

    i = myht ? zend_hash_num_elements(myht) : 0;

    if (i > 0)
    {
        char *key;
        zval **data;
        ulong index;
        uint key_len;
        HashPosition pos;
        HashTable *tmp_ht = NULL;

        zend_hash_internal_pointer_reset_ex(myht, &pos);
        for (;; zend_hash_move_forward_ex(myht, &pos)) {
            i = zend_hash_get_current_key_ex(myht, &key, &key_len, &index, 0, &pos);
            if (i == HASH_KEY_NON_EXISTANT)
                break;

            avro_value_t field;
            avro_wrapped_buffer_t wbuf;

            if (zend_hash_get_current_data_ex(myht, (void *)&data, &pos) == SUCCESS) {
                tmp_ht = HASH_OF(*data);
                if (tmp_ht) {
                    tmp_ht->nApplyCount++;
                }

                avro_value_get_by_name(&val, key, &field, NULL);

                switch (Z_TYPE_PP(data))
                {
                    case IS_NULL:
                        avro_value_set_null(&field);
                        writer_bytes += 64;
                        break;
                    case IS_BOOL:
                        avro_value_set_boolean(&field, Z_BVAL_PP(data));
                        writer_bytes += 64;
                        break;
                    case IS_LONG:
                        avro_value_set_long(&field, Z_LVAL_PP(data));
                        writer_bytes += 64;
                        break;
                    case IS_DOUBLE:
                        avro_value_set_double(&field, Z_DVAL_PP(data));
                        writer_bytes += 64;
                        break;
                    case IS_STRING:
                        avro_wrapped_buffer_new_string(&wbuf, Z_STRVAL_PP(data));
                        avro_value_give_string_len(&field, &wbuf);
                        writer_bytes += Z_STRLEN_PP(data);
                        break;
                    case IS_ARRAY:
                    case IS_OBJECT:
                        /* support complex types later */
                        break;
                    default:
                        break;
                }
            }

            if (tmp_ht) {
                tmp_ht->nApplyCount--;
            }
        }
    }
    writer_bytes = writer_bytes * 2;

    msg_buf = emalloc(writer_bytes);
    writer = avro_writer_memory(msg_buf, writer_bytes);

    avro_value_write(writer, &val);
    avro_value_iface_decref(iface);
    avro_schema_decref(schema);
    avro_writer_free(writer);
    avro_value_decref(&val);

    return msg_buf;
}
/* }}} */

XCOM_METHOD(__construct) /* {{{ */
{
    php_xcom *xcom;
    zval *obj;
    char *fab_url, *fab_token, *cap_token;
    size_t fab_url_len = 0, fab_token_len = 0, cap_token_len = 0;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osss", &obj, xcom_ce, &fab_url, &fab_url_len, &fab_token, &fab_token_len, &cap_token, &cap_token_len)==FAILURE) {
        ZVAL_NULL(obj);
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);
    xcom->fabric_url = estrndup(fab_url, fab_url_len);
    xcom->fabric_token = estrndup(fab_token, fab_token_len);
    xcom->cap_token = estrndup(cap_token, cap_token_len);

    return;
}
/* }}} */

XCOM_METHOD(send) /* {{{ */
{
    php_xcom *xcom;
    zval *obj, *data_obj, *debug;
    char *topic, *json_schema, *schema_uri;
    size_t topic_len = 0, schema_len = 0, schema_uri_len = 0;
    char *msg = NULL;
    long resp_code = -1;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "OsOs|s", &obj, xcom_ce, &topic, &topic_len, &data_obj, zend_standard_class_def,
                &json_schema, &schema_len, &schema_uri, &schema_uri_len)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    msg = php_xcom_avro_record_from_obj(data_obj, json_schema TSRMLS_CC);

    debug = zend_read_property(xcom_ce, obj, "__debug", sizeof("__debug")-1, 1 TSRMLS_CC);

    resp_code = php_xcom_send_msg(xcom, msg, topic, schema_uri_len ? schema_uri : NULL, debug ? Z_BVAL_P(debug) : 0);

    RETVAL_LONG(resp_code);

    efree(msg);

    return;
}
/* }}} */
XCOM_METHOD(decode) /* {{{ */
{
    php_xcom *xcom;
    zval *obj, *data_obj;
    char *avro_msg, *json_schema;
    size_t avro_msg_len = 0, schema_len = 0;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss", &obj, xcom_ce, &avro_msg, &avro_msg_len, &json_schema, &schema_len)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    object_init(data_obj);

    php_xcom_obj_from_avro_msg(&data_obj, avro_msg, json_schema TSRMLS_CC);

    RETURN_ZVAL(data_obj, 1, 0);

    zval_ptr_dtor(&data_obj);
    return;
}
/* }}} */
XCOM_METHOD(__destruct) /* {{{ */
{
    php_xcom *xcom;
    zval *obj;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O", &obj, xcom_ce)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    XCOM_FREE(xcom->fabric_url)
    XCOM_FREE(xcom->fabric_token)
    XCOM_FREE(xcom->cap_token)

    return;
}
/* }}} */

/* {{{ arginfo */
XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom__construct, 0, 0, 3)
ZEND_ARG_INFO(0, fabric_url)
ZEND_ARG_INFO(0, fabric_token)
ZEND_ARG_INFO(0, capability_token)
ZEND_END_ARG_INFO()

XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom_send, 0, 0, 2)
ZEND_ARG_INFO(0, obj)
ZEND_ARG_INFO(0, topic)
ZEND_END_ARG_INFO()

XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom_decode, 0, 0, 2)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_INFO(0, schema)
ZEND_END_ARG_INFO()

XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_function_entry xcom_methods[] = { /* {{{ */
XCOM_ME(__construct,arginfo_xcom__construct,ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
XCOM_ME(send,arginfo_xcom_send,ZEND_ACC_PUBLIC)
XCOM_ME(decode,arginfo_xcom_decode,ZEND_ACC_PUBLIC)
XCOM_ME(__destruct,arginfo_xcom_noparams,ZEND_ACC_PUBLIC)
{NULL, NULL, NULL}
};
/* }}} */

static php_xcom* php_xcom_new(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom;
#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
#ifndef ZEND_ENGINE_2_4
    zval *tmp;
    tmp = NULL;
#endif
#endif

    xcom = ecalloc(1, sizeof(php_xcom));
    xcom->fabric_url = NULL;
    xcom->fabric_token = NULL;
    xcom->cap_token = NULL;

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 3)
    ALLOC_HASHTABLE(xcom->zo.properties);
    zend_hash_init(xcom->zo.properties, 0, NULL, ZVAL_PTR_DTOR, 0);

    xcom->zo.ce = ce;
    xcom->zo.guards = NULL;
#else
    zend_object_std_init(&xcom->zo, ce TSRMLS_CC);
#ifndef ZEND_ENGINE_2_4
    zend_hash_copy(xcom->zo.properties, &ce->default_properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));
#else
    object_properties_init(&xcom->zo, ce);
#endif
#endif

    return xcom;
}

static zend_object_value new_xcom_object(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom;

    xcom = php_xcom_new(ce TSRMLS_CC);
    return php_xcom_register_object(xcom TSRMLS_CC);
}
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
*/
PHP_MINIT_FUNCTION(xcom) 
{
    zend_class_entry xce, xece;

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return FAILURE;
    }

    INIT_CLASS_ENTRY(xce, "Xcom", xcom_methods);

    xce.create_object = new_xcom_object;

    xcom_ce = zend_register_internal_class(&xce TSRMLS_CC);
    memcpy(&xcom_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    xcom_object_handlers.clone_obj = php_xcom_clone_obj;

    INIT_CLASS_ENTRY(xece, "XcomException", NULL);

#if (PHP_MAJOR_VERSION == 5 && PHP_MINOR_VERSION < 2)
    xcom_exc_ce = zend_register_internal_class_ex(&xece, zend_exception_get_default(), NULL TSRMLS_CC);
#else
    xcom_exc_ce = zend_register_internal_class_ex(&xece, zend_exception_get_default(TSRMLS_C), NULL TSRMLS_CC);
#endif

    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
*/
PHP_MSHUTDOWN_FUNCTION(xcom) 
{
    xcom_ce = NULL;
    xcom_exc_ce = NULL;
    curl_global_cleanup();
    return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
*/
PHP_MINFO_FUNCTION(xcom) 
{
    php_info_print_table_start();
    php_info_print_table_header(2, "X.commerce", "enabled");
    php_info_print_table_row(2, "HTTP Engine", "curl");
    php_info_print_table_row(2, "version", PHP_XCOM_VERSION);
    php_info_print_table_end();
}
/* }}} */

/* {{{ xcom_module_entry */
zend_module_entry xcom_module_entry = {
STANDARD_MODULE_HEADER_EX, NULL,
NULL,
"X.commerce",
NULL,
PHP_MINIT(xcom),
PHP_MSHUTDOWN(xcom),
NULL,
NULL,
PHP_MINFO(xcom),
XCOM_EXT_VER,
STANDARD_MODULE_PROPERTIES
};
/* }}} */

#if COMPILE_DL_XCOM
ZEND_GET_MODULE(xcom)
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
