#include <libwebsockets.h>

// a json for deserialization
static const char endpoints_json[] = "{ \
    \"schema\": \"com.google.test.schema\", \
    \"endpoints\": { \
        \"ws\": { \
            \"url\": \"https://example.net:12345/uplink_ws?a=b\" \
        }, \
        \"basic\": { \
            \"url\": \"https://example.net/uplink?c=d\" \
        } \
    } \
}";

// endpoints.[ws|basic].url = url_value
typedef struct endpoint {
    char* url;
} endpoint_t;

// the "endpoints" object
typedef struct endpoints_block {
    endpoint_t*         ws_endpoint;
    endpoint_t*         basic_endpoint;
} endpoints_block_t;

// The whole object with endpoints as subobject
typedef struct full_reply {
    endpoints_block_t*  endpoints;
//    endpoint_t*         one_endpoint;
} full_reply_t;

// an meta model for the endpoint_t struct
static const lws_struct_map_t endpoint_map[] = {
    LSM_STRING_PTR	(endpoint_t, url, "url"),
};

// an meta model for the endpoints_block_t struct
static const lws_struct_map_t endpoints_block_map[] = {
    LSM_CHILD_PTR	(endpoints_block_t, basic_endpoint, endpoint_t, NULL, endpoint_map, "basic"),
    LSM_CHILD_PTR	(endpoints_block_t, ws_endpoint,    endpoint_t, NULL, endpoint_map, "ws"),
};

static const lws_struct_map_t full_reply_map[] = {
    LSM_CHILD_PTR	(full_reply_t,
                        endpoints, /* the child pointer member */
                        endpoints_block_t, /* the child type */
                        NULL, endpoints_block_map, /* map object for item type */
                        "endpoints"), /* outer json object name */
};

static const lws_struct_map_t my_schema_map[] = {
    LSM_SCHEMA	(full_reply_t, NULL, full_reply_map, "com.google.test.schema")
};

void do_parse_json(const char* json)
{
    struct lejp_ctx ctx;
    lws_struct_args_t a;
    int n, e = 0;

    memset(&a, 0, sizeof(a));
    a.map_st[0] = my_schema_map;
    a.map_entries_st[0] = LWS_ARRAY_SIZE(my_schema_map);
    a.ac_block_size = 512;

    lws_struct_json_init_parse(&ctx, NULL, &a);
    n = lejp_parse(&ctx, (uint8_t *)json, (int)strlen(json));
    if (n < 0) {
        lwsl_err("%s: notification JSON decode failed '%s'\n",
                __func__, lejp_error_to_string(n));
        e++;
        goto done;
    }
    lwsac_info(a.ac);

    if (!a.dest) {
        lwsl_err("%s: didn't produce any output\n", __func__);
        e++;
        goto done;
    }

    if( a.top_schema_index != 0) {
        lwsl_err("%s: wrong top_schema_index %d\n", __func__, a.top_schema_index);
        goto done;
    }

    full_reply_t *result_obj = a.dest;
    lwsl_debug("obj = %p, shema = %s\n", result_obj, full_reply_map[a.top_schema_index].colname);
    lwsl_debug("result.endpoints = %p\n", result_obj->endpoints);

done:
    lwsac_free(&a.ac);
}

int main(void)
{
    int logs = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE | LLL_PARSER | LLL_DEBUG;

    lws_set_log_level(logs, NULL);
    lwsl_user("LWS API: lws_struct JSON\n");

    do_parse_json(endpoints_json);

    lwsl_user("LWS API: lws_struct JSON done\n");
    return 0;
}

