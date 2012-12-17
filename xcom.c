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

pthread_attr_t pthread_attrs;

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
    if (xcom->debug_output.c) {
        smart_str_free(&xcom->debug_output);
    }
    if(xcom->debugArr) {
        zval_ptr_dtor(&xcom->debugArr);
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

static size_t php_xcom_read_response(char *ptr, size_t size, size_t nmemb, void *ctx) /* {{{ */
{
    uint relsize;
    php_xcom *xcom = (php_xcom *)ctx;

    relsize = size * nmemb;
    smart_str_appendl(&xcom->lastresponse, ptr, relsize);

    return relsize;
}
/* }}} */

static size_t php_xcom_read_noop(char *ptr, size_t size, size_t nmemb, void *ctx) /* {{{ */
{
    uint relsize;
    relsize = size * nmemb;
    return relsize;
}
/* }}} */

static int php_xcom_read_debug(CURL *ch, curl_infotype ign, char *debug, size_t len, void *ctx) /* {{{ */
{
    php_xcom *xcom = (php_xcom *)ctx;
    switch(ign) {
        case CURLINFO_TEXT:
        case CURLINFO_SSL_DATA_IN:
        case CURLINFO_SSL_DATA_OUT:
        case CURLINFO_END:
            return 0;
        default:
            smart_str_appendl(&xcom->debug_output, debug, len);
            if(ign==CURLINFO_HEADER_OUT) {
                smart_str_appendl(&xcom->headers_out, debug, len);
            }
            else if(ign==CURLINFO_HEADER_IN) {
                smart_str_appendl(&xcom->headers_in, debug, len);
            }
            return 0;
    }
}

static void* php_xcom_send_msg(void *r) /* {{{ */
{
    CURL *curl;
    long response_code = -1, l_code = 0;
    char *content_type, *s_code;
    double d_code;
    php_xcom_req_t *req;
    zval *info;

    req = (php_xcom_req_t *)r;

    curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req->curl_headers);
    curl_easy_setopt(curl, CURLOPT_URL, req->uri);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, req->payload);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(req->payload));

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    if(req->sslchecks & XCOM_SSLCHECK_HOST) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    }

    if(req->sslchecks & XCOM_SSLCHECK_PEER) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    }

    if(!req->async) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, php_xcom_read_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, req->xcom);
        if(req->debug) {
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
            curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, php_xcom_read_debug);
            curl_easy_setopt(curl, CURLOPT_DEBUGDATA, req->xcom);
            if (req->xcom->headers_in.c) {
                smart_str_free(&req->xcom->headers_in);
            }
            if (req->xcom->headers_out.c) {
                smart_str_free(&req->xcom->headers_out);
            }
            if (req->xcom->debug_output.c) {
                smart_str_free(&req->xcom->debug_output);
            }
        }
    }

    curl_easy_perform(curl);

    if(!req->async) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &content_type);

        ALLOC_INIT_ZVAL(info);
        array_init(info);

        if(content_type!=NULL) {
            CAAS("content_type", content_type);
        }

        CAAL("http_code", response_code);

        if (content_type != NULL) {
            CAAS("content_type", content_type);
        }
        if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &s_code) == CURLE_OK) {
            CAAS("url", s_code);
        }

        if (curl_easy_getinfo(curl, CURLINFO_HEADER_SIZE, &l_code) == CURLE_OK) {
            CAAL("header_size", l_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_REQUEST_SIZE, &l_code) == CURLE_OK) {
            CAAL("request_size", l_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_FILETIME, &l_code) == CURLE_OK) {
            CAAL("filetime", l_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &l_code) == CURLE_OK) {
            CAAL("ssl_verify_result", l_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &l_code) == CURLE_OK) {
            CAAL("redirect_count", l_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME,&d_code) == CURLE_OK) {
            CAAD("total_time", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_NAMELOOKUP_TIME, &d_code) == CURLE_OK) {
            CAAD("namelookup_time", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_CONNECT_TIME, &d_code) == CURLE_OK) {
            CAAD("connect_time", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_PRETRANSFER_TIME, &d_code) == CURLE_OK) {
            CAAD("pretransfer_time", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD, &d_code) == CURLE_OK){
            CAAD("size_upload", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &d_code) == CURLE_OK){
            CAAD("size_download", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &d_code) == CURLE_OK){
            CAAD("speed_download", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD, &d_code) == CURLE_OK){
            CAAD("speed_upload", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &d_code) == CURLE_OK) {
            CAAD("download_content_length", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_UPLOAD, &d_code) == CURLE_OK) {
            CAAD("upload_content_length", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &d_code) == CURLE_OK){
            CAAD("starttransfer_time", d_code);
        }
        if (curl_easy_getinfo(curl, CURLINFO_REDIRECT_TIME, &d_code) == CURLE_OK){
            CAAD("redirect_time", d_code);
        }

        if(req->debug) {
            smart_str_0(&req->xcom->headers_in);
            smart_str_0(&req->xcom->headers_out);
            CAAS("headers_recv", req->xcom->headers_in.c);
            CAAS("headers_sent", req->xcom->headers_out.c);
        }

        req->xcom->debugArr = info;
    }

    if (req->curl_headers) {
        curl_slist_free_all(req->curl_headers);
    }

    curl_easy_cleanup(curl);
    req->response_code = response_code;
    if(req->async) {
        free(req->payload);
        free(req);
    }
    return NULL;
}
/* }}} */

int php_xcom_obj_from_avro_msg(zval **obj, char *msg, char *json_schema TSRMLS_DC) /* {{{ */
{
    avro_schema_t schema;
    avro_schema_error_t error = NULL;
    avro_value_iface_t *iface;
    avro_value_t val;
    size_t sz, i, vsz;

    char *av_s, av_b;
    int32_t av_d32;
    int64_t av_d64;
    double av_d;
    float av_f;

    avro_reader_t reader = avro_reader_memory(msg, strlen(msg));

    avro_schema_from_json(json_schema, strlen(json_schema), &schema, &error);

    if(!schema) {
        return FALSE;
    }

    iface = avro_generic_class_from_schema(schema);

    if(!iface) {
        return FALSE;
    }

    avro_generic_value_new(iface, &val);

    avro_value_get_size(&val, &sz);

    avro_value_read(reader, &val);

    for(i=0; i<sz; ++i) {
        avro_value_t field_val, branch;
        char *field_name;
        avro_value_get_by_index(&val, i, &field_val, (const char **)&field_name);

        php_avro_read_type:
        switch(avro_value_get_type(&field_val)) {
            case AVRO_STRING:
                if(!avro_value_get_string(&field_val, (const char **)&av_s, &vsz)) {
                    zend_update_property_string(zend_standard_class_def, *obj, field_name, strlen(field_name), av_s TSRMLS_CC);
                }
            break;
            case AVRO_NULL:
                zend_update_property_null(zend_standard_class_def, *obj, field_name, strlen(field_name) TSRMLS_CC);
            break;
            case AVRO_BOOLEAN:
                if(!avro_value_get_boolean(&field_val, (int *)&av_b)) {
                    zend_update_property_bool(zend_standard_class_def, *obj, field_name, strlen(field_name), av_b TSRMLS_CC);
                }
            break;
            case AVRO_INT64:
                if(!avro_value_get_long(&field_val, &av_d64)) {
                    zend_update_property_long(zend_standard_class_def, *obj, field_name, strlen(field_name), av_d64 TSRMLS_CC);
                }
            break;
            case AVRO_INT32:
                if(!avro_value_get_int(&field_val, &av_d32)) {
                    zend_update_property_long(zend_standard_class_def, *obj, field_name, strlen(field_name), av_d32 TSRMLS_CC);
                }
            break;
            case AVRO_FLOAT:
                if(!avro_value_get_float(&field_val, &av_f)) {
                    zend_update_property_double(zend_standard_class_def, *obj, field_name, strlen(field_name), (double)av_f TSRMLS_CC);
                }
            break;
            case AVRO_DOUBLE:
                if(!avro_value_get_double(&field_val, &av_d)) {
                    zend_update_property_double(zend_standard_class_def, *obj, field_name, strlen(field_name), av_d TSRMLS_CC);
                }
            break;
            case AVRO_UNION:
                if(avro_value_get_current_branch(&field_val, &branch)) {
                    zend_update_property_null(zend_standard_class_def, *obj, field_name, strlen(field_name) TSRMLS_CC);
                } else {
                    avro_value_get_type(&branch);
                    field_val = branch;
                    goto php_avro_read_type;
                }
            break;
            default:
            break;
        }
    }
    avro_value_decref(&val);
    avro_value_iface_decref(iface);
    avro_schema_decref(schema);
    avro_reader_free(reader);
    return TRUE;
}

static void* php_xcom_send_msg_common(INTERNAL_FUNCTION_PARAMETERS, int async) {
    php_xcom *xcom;
    zval *obj, *data_obj, *debug, *hdrs = NULL, **cur_val, *sslchecks, *tmp;
    char *topic, *json_schema = NULL;
    size_t topic_len = 0, schema_len = 0;
    char *msg = NULL;
    long resp_code = -1;
    pthread_t thr;
    php_xcom_req_t *req;
    char content_type_hdr[] = "Content-Type: avro/binary", auth_hdr[4096] = "", schema_ver_hdr[32] = "", schema_uri_hdr[1024] = "";
    uint cur_key_len, msg_free = 0;
    ulong num_key;
    zend_hash_key_type cur_key;
    smart_str sheader = {0};
    HashTable *h_hdrs;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Osz|sa", &obj, xcom_ce, &topic, &topic_len, &data_obj, &json_schema, &schema_len, &hdrs)==FAILURE) {
        return NULL;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    if(schema_len) {
        if(Z_TYPE_P(data_obj)!=IS_OBJECT && Z_TYPE_P(data_obj)!=IS_ARRAY) {
            php_error_docref(NULL TSRMLS_CC, E_ERROR, "the data must be specified in an object or an array for avro messages (a schema was passed)");
            RETVAL_FALSE;
            return NULL;
        }
        msg = php_xcom_avro_record_from_obj(data_obj, json_schema TSRMLS_CC);
        if(msg==NULL) {
            RETVAL_FALSE;
            return NULL;
        }
        msg_free = 1;
    } else {
        convert_to_string_ex(&data_obj);
        msg = Z_STRVAL_P(data_obj);
        if(!strlen(msg)) {
            RETVAL_FALSE;
            return NULL;
        }
    }

    if(async) {
        req = malloc(sizeof(php_xcom_req_t));
        req->async = 1;
    } else {
        req = emalloc(sizeof(php_xcom_req_t));
        req->async = 0;
    }
    req->curl_headers = NULL;

    if(xcom->cap_token) {
        snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: %s", xcom->cap_token);
    }

    if(!hdrs || Z_TYPE_P(hdrs)!=IS_ARRAY || SUCCESS!=zend_hash_find(HASH_OF(hdrs), "X-XC-SCHEMA-VERSION", sizeof("X-XC-SCHEMA-VERSION"), (void *)&tmp)) {
        snprintf(schema_ver_hdr, sizeof(schema_ver_hdr), "X-XC-SCHEMA-VERSION: %s", "1.0.0");
    }

    req->curl_headers = curl_slist_append(req->curl_headers, "Expect:");
    req->curl_headers = curl_slist_append(req->curl_headers, auth_hdr);
    req->curl_headers = curl_slist_append(req->curl_headers, schema_uri_hdr);
    req->curl_headers = curl_slist_append(req->curl_headers, schema_ver_hdr);
    req->curl_headers = curl_slist_append(req->curl_headers, content_type_hdr);

    if(hdrs) {
        h_hdrs = HASH_OF(hdrs);
        for (zend_hash_internal_pointer_reset(h_hdrs);
                zend_hash_get_current_data(h_hdrs, (void *)&cur_val) == SUCCESS;
                zend_hash_move_forward(h_hdrs)) {
            /* check if a string based key is used */
            switch (zend_hash_get_current_key_ex(h_hdrs, &cur_key, &cur_key_len, &num_key, 0, NULL)) {
#if (PHP_MAJOR_VERSION >= 6)
                case HASH_KEY_IS_UNICODE:
                    {
                        char *temp;
                        int temp_len;

                        zend_unicode_to_string(UG(utf8_conv), &temp, &temp_len, cur_key.u, cur_key_len-1 TSRMLS_CC);
                        smart_str_appendl(&sheader, temp, temp_len);
                        efree(temp);
                    }
                    break;
#endif
                case HASH_KEY_IS_STRING:
                    smart_str_appendl(&sheader, ZEND_HASH_KEY_STRVAL(cur_key), cur_key_len-1);
                    break;
                default:
                    continue;
            }
            smart_str_appends(&sheader, ": ");
            switch (Z_TYPE_PP(cur_val)) {
                case IS_STRING:
                    smart_str_appendl(&sheader, Z_STRVAL_PP(cur_val), Z_STRLEN_PP(cur_val));
                    break;
#if (PHP_MAJOR_VERSION >= 6)
                case IS_UNICODE:
                    {
                        char *temp;
                        int temp_len;

                        zend_unicode_to_string(UG(utf8_conv), &temp, &temp_len, Z_USTRVAL_PP(cur_val), Z_USTRLEN_PP(cur_val) TSRMLS_CC);
                        smart_str_appendl(&sheader, temp, temp_len);
                        efree(temp);
                    }
                    break;
#endif
                default:
                    smart_str_free(&sheader);
                    continue;
            }

            smart_str_0(&sheader);
            req->curl_headers = curl_slist_append(req->curl_headers, sheader.c);
            smart_str_free(&sheader);
        }
    }

    if(xcom->fabric_url==NULL) {
      php_error_docref(NULL TSRMLS_CC, E_ERROR, "the fabric URL is not set");
      return NULL;
    }

    snprintf(req->uri, sizeof(req->uri), "%s%s", xcom->fabric_url, topic);

    debug = zend_read_property(xcom_ce, obj, "__debug", sizeof("__debug")-1, 0 TSRMLS_CC);

    req->debug = debug ? Z_BVAL_P(debug) : 0;

    sslchecks = zend_read_property(xcom_ce, obj, "__sslchecks", sizeof("__sslchecks")-1, 0 TSRMLS_CC);

    req->sslchecks = Z_LVAL_P(sslchecks);

    if(async) {
        req->payload = strdup(msg);
        req->debug = debug ? Z_BVAL_P(debug) : 0;
        pthread_create(&thr, &pthread_attrs, php_xcom_send_msg, (void*)req);
        resp_code = 0L;
    } else {
        req->xcom = xcom;
        req->payload = msg;
        php_xcom_send_msg(req);
        resp_code = req->response_code;
        efree(req);
    }

    RETVAL_LONG(resp_code);

    if(msg_free) {
        efree(msg);
    }

    return NULL;
}

static char* php_xcom_avro_record_from_obj(zval *obj, char *json_schema TSRMLS_DC) /* {{{ */
{
    int i;
    HashTable *ht;
    char *msg_buf = NULL;
    avro_writer_t writer = NULL;
    avro_value_t val;
    size_t writer_bytes = 0;
    avro_schema_t schema = NULL;
    avro_schema_error_t error = NULL;
    avro_value_iface_t *iface;
    zval **data;
    avro_value_t field, branch;
    avro_wrapped_buffer_t wbuf;
    const char *f;
    size_t record_size = 0;
    int field_type, was_found = 0, branch_to_use;

    avro_schema_from_json(json_schema, strlen(json_schema), &schema, &error);

    if(schema==NULL) {
      php_error_docref(NULL TSRMLS_CC, E_ERROR, "invalid schema: %s", avro_strerror());
      return NULL;
    }

    iface = avro_generic_class_from_schema(schema);

    avro_generic_value_new(iface, &val);

    ht = Z_TYPE_P(obj)==IS_OBJECT ? Z_OBJPROP_P(obj) : HASH_OF(obj);

    if (ht && ht->nApplyCount > 1) {
        php_error_docref(NULL TSRMLS_CC, E_WARNING, "recursion detected");
        return NULL;
    }

    avro_value_get_size(&val, &record_size);

    for(i=0; i<record_size; ++i) {
        branch_to_use = -1;
        avro_value_get_by_index(&val, i, &field, &f);

        if(f==NULL) {
            break;
        }

        field_type = avro_value_get_type(&field);

        was_found = zend_hash_find(ht, f, strlen(f) + 1, (void *)&data);

        if(SUCCESS!=was_found) {
            if(AVRO_UNION!=field_type) {
                php_error_docref(NULL TSRMLS_CC, E_WARNING, "missing data member: '%s' is in the schema but was not set!", f);
                continue;
            }
        }

        if(AVRO_UNION==field_type) {
            if(was_found==SUCCESS) {
                /* member was found, select the first branch
                   (only two branches null-able unions are supported */
                branch_to_use = 1;
            } else {
                /* member wasn't found, according to the avro spec the
                   "default" value is the first branch, so let's set that */
                branch_to_use = 0;
            }
            avro_value_set_branch(&field, branch_to_use, &branch);
            field = branch;
            field_type = avro_value_get_type(&branch);
        }

        switch(field_type) {
            case AVRO_STRING:
            case AVRO_BYTES:
                convert_to_string_ex(data);
                if(field_type==AVRO_BYTES) {
                    avro_value_set_bytes(&field, Z_STRVAL_PP(data), Z_STRLEN_PP(data));
                } else {
                    avro_wrapped_buffer_new_string(&wbuf, Z_STRVAL_PP(data));
                    avro_value_give_string_len(&field, &wbuf);
                }
                writer_bytes += Z_STRLEN_PP(data);
                break;
            case AVRO_INT32:
                convert_to_long_ex(data);
                avro_value_set_int(&field, Z_LVAL_PP(data));
                writer_bytes += 64;
                break;
            case AVRO_INT64:
                convert_to_long_ex(data);
                avro_value_set_long(&field, Z_LVAL_PP(data));
                writer_bytes += 64;
                break;
            case AVRO_FLOAT:
                convert_to_double_ex(data);
                avro_value_set_float(&field, Z_DVAL_PP(data));
                writer_bytes += 64;
                break;
            case AVRO_DOUBLE:
                convert_to_double_ex(data);
                avro_value_set_double(&field, Z_DVAL_PP(data));
                writer_bytes += 64;
                break;
            case AVRO_BOOLEAN:
                convert_to_boolean_ex(data);
                avro_value_set_boolean(&field, Z_BVAL_PP(data));
                writer_bytes += 64;
                break;
            case AVRO_NULL:
                avro_value_set_null(&field);
                writer_bytes += 64;
                break;
        }

        /* deal with a bug in libavro where the branch is not
           finalized until the ref count on the writer is 0 or
           branches are switched */
        if(branch_to_use >= 0) {
            avro_value_set_branch(&field, !branch_to_use, &branch);
            avro_value_set_branch(&field, branch_to_use, &branch);
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
    char *fab_url = NULL, *fab_token = NULL, *cap_token = NULL, *es = NULL;
    size_t fab_url_len = 0, fab_token_len = 0, cap_token_len = 0;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O|sss", &obj, xcom_ce, &fab_url, &fab_url_len, &fab_token, &fab_token_len, &cap_token, &cap_token_len)==FAILURE) {
        ZVAL_NULL(obj);
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    if(fab_url_len) {
        xcom->fabric_url = estrndup(fab_url, fab_url_len);
        es = xcom->fabric_url + fab_url_len - 1;
        while(es > xcom->fabric_url && *es=='/') {
                --es;
        }
        *(es+1) = '\0';
    }

    if(fab_token_len) {
        xcom->fabric_token = estrndup(fab_token, fab_token_len);
    }
    
    if(cap_token_len) {
        xcom->cap_token = estrndup(cap_token, cap_token_len);
    }

    zend_update_property_bool(xcom_ce, obj, "__debug", sizeof("__debug")-1, 0L TSRMLS_CC);
    zend_update_property_long(xcom_ce, obj, "__sslchecks", sizeof("__sslchecks")-1, XCOM_SSLCHECK_BOTH TSRMLS_CC);

    return;
}
/* }}} */

XCOM_METHOD(encode) /* {{{ */
{
    php_xcom *xcom;
    zval *obj, *data_obj;
    char *json_schema;
    size_t schema_len = 0;
    char *msg = NULL;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "OOs", &obj, xcom_ce, &data_obj, zend_standard_class_def,
                &json_schema, &schema_len)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    msg = php_xcom_avro_record_from_obj(data_obj, json_schema TSRMLS_CC);

    RETURN_STRINGL(msg, strlen(msg), 1);

    efree(msg);

    return;
}
/* }}} */

XCOM_METHOD(send) /* {{{ */
{
    php_xcom_send_msg_common(INTERNAL_FUNCTION_PARAM_PASSTHRU, 0);
}
/* }}} */

XCOM_METHOD(sendAsync) /* {{{ */
{
    php_xcom_send_msg_common(INTERNAL_FUNCTION_PARAM_PASSTHRU, 1);
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

    MAKE_STD_ZVAL(data_obj);
    object_init(data_obj);

    if(!php_xcom_obj_from_avro_msg(&data_obj, avro_msg, json_schema TSRMLS_CC)) {
        RETURN_FALSE;
    }

    RETURN_ZVAL(data_obj, 1, 0);

    zval_ptr_dtor(&data_obj);
    return;
}
/* }}} */

XCOM_METHOD(getLastResponse) /* {{{ */
{
    php_xcom *xcom;
    zval *obj;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O", &obj, xcom_ce)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    if (xcom->lastresponse.c) {
        RETURN_STRINGL(xcom->lastresponse.c, xcom->lastresponse.len, 1);
    }
}
/* }}} */

XCOM_METHOD(getLastResponseInfo) /* {{{ */
{
    php_xcom *xcom;
    zval *obj;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O", &obj, xcom_ce)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    if(xcom->debugArr) {
        RETURN_ZVAL(xcom->debugArr, 1, 0);
    }

    RETURN_FALSE;
}
/* }}} */

XCOM_METHOD(getDebugOutput) /* {{{ */
{
    php_xcom *xcom;
    zval *obj;

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "O", &obj, xcom_ce)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    if (xcom->debug_output.c) {
        RETURN_STRINGL(xcom->debug_output.c, xcom->debug_output.len, 1);
    }
}
/* }}} */

XCOM_METHOD(getOnboardingURL) /* {{{ */
{
    php_xcom *xcom;
    zval *obj, *merchant_params;
    char *cap_name, *agreement_url, *urlencoded_payload, *redirect_url = NULL, *request_payload;
    int cap_name_len = 0, agree_url_len, urlenc_len;
    CURL *curl;
    CURLcode cres;
    smart_str json_payload = {0};

    if (zend_parse_method_parameters(ZEND_NUM_ARGS() TSRMLS_CC, getThis(), "Oss", &obj, xcom_ce,
        &cap_name, &cap_name_len, &agreement_url, &agree_url_len)==FAILURE) {
        return;
    }

    xcom = php_xcom_fetch_obj_store(obj TSRMLS_CC);

    /* the goal here is to craft the json request for the onboarding
     * flow and return the redirect URL (authn) */

    MAKE_STD_ZVAL(merchant_params);
    array_init(merchant_params);

#if (PHP_MAJOR_VERSION >= 6)
    add_ascii_assoc_string(merchant_params, "target_capability_name", cap_name, 0);
#else
    add_assoc_string(merchant_params, "target_capability_name", cap_name, 0);
#endif

    add_assoc_bool(merchant_params, "is_registered", 0);

    php_json_encode(&json_payload, merchant_params, 0 TSRMLS_CC);

    urlencoded_payload = php_url_encode(json_payload.c, json_payload.len, &urlenc_len);

    spprintf(&request_payload, 0, "onboarding_info=%s", urlencoded_payload);

    curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, XCOM_ONBOARDING_URL);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, php_xcom_read_noop);

    cres = curl_easy_perform(curl);

    if(cres==CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_REDIRECT_URL, &redirect_url);
        if(redirect_url) {
            RETVAL_STRING(redirect_url, 0);
        }
    } else {
        RETVAL_BOOL(0);
    }

    smart_str_free(&json_payload);
    zval_ptr_dtor(&merchant_params);
    efree(urlencoded_payload);
    efree(request_payload);
    curl_easy_cleanup(curl);

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
ZEND_ARG_INFO(0, json_schema)
ZEND_ARG_INFO(0, http_headers)
ZEND_END_ARG_INFO()

XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom_encdec, 0, 0, 2)
ZEND_ARG_INFO(0, msg)
ZEND_ARG_INFO(0, schema)
ZEND_END_ARG_INFO()

XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom_onboarding, 0, 0, 2)
ZEND_ARG_INFO(0, capability_name)
ZEND_ARG_INFO(0, agreement_url)
ZEND_END_ARG_INFO()

XCOM_ARGINFO
ZEND_BEGIN_ARG_INFO_EX(arginfo_xcom_noparams, 0, 0, 0)
ZEND_END_ARG_INFO()

static zend_function_entry xcom_methods[] = { /* {{{ */
XCOM_ME(__construct,arginfo_xcom__construct,ZEND_ACC_PUBLIC|ZEND_ACC_CTOR)
XCOM_ME(send,arginfo_xcom_send,ZEND_ACC_PUBLIC)
XCOM_ME(sendAsync,arginfo_xcom_send,ZEND_ACC_PUBLIC)
XCOM_ME(encode,arginfo_xcom_encdec,ZEND_ACC_PUBLIC)
XCOM_ME(decode,arginfo_xcom_encdec,ZEND_ACC_PUBLIC)
XCOM_ME(getLastResponse,arginfo_xcom_noparams,ZEND_ACC_PUBLIC)
XCOM_ME(getLastResponseInfo,arginfo_xcom_noparams,ZEND_ACC_PUBLIC)
XCOM_ME(getDebugOutput,arginfo_xcom_noparams,ZEND_ACC_PUBLIC)
XCOM_ME(getOnboardingURL,arginfo_xcom_onboarding,ZEND_ACC_PUBLIC)
XCOM_ME(__destruct,arginfo_xcom_noparams,ZEND_ACC_PUBLIC)
{NULL, NULL, NULL}
};
/* }}} */

static php_xcom* php_xcom_new(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom;
#ifndef ZEND_ENGINE_2_4
    zval *tmp;
    tmp = NULL;
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
#ifdef ZEND_ENGINE_2_4
    object_properties_init(&xcom->zo, ce);
#else
    zend_hash_copy(xcom->zo.properties, &ce->default_properties, (copy_ctor_func_t) zval_add_ref, (void *) &tmp, sizeof(zval *));
#endif
#endif

    return xcom;
}

static zend_object_value new_xcom_object(zend_class_entry *ce TSRMLS_DC) /* {{{ */
{
    php_xcom *xcom;

    xcom = php_xcom_new(ce TSRMLS_CC);
    INIT_SMART_STR(xcom->lastresponse);
    INIT_SMART_STR(xcom->debug_output);
    INIT_SMART_STR(xcom->headers_out);
    INIT_SMART_STR(xcom->headers_in);
    xcom->debugArr = NULL;
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

    REGISTER_STRING_CONSTANT("XCOM_FABRIC_PRODUCTION", XCOM_FABRIC_PRODUCTION, CONST_CS | CONST_PERSISTENT);
    REGISTER_STRING_CONSTANT("XCOM_FABRIC_SANDBOX", XCOM_FABRIC_SANDBOX, CONST_CS | CONST_PERSISTENT);

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
"xcommerce",
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
