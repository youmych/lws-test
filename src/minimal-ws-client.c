/*
 * lws-minimal-ws-client
 *
 * Written in 2010-2020 by Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * This demonstrates a ws client that connects by default to libwebsockets.org
 * dumb increment ws server.
 */

#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#define COUNT_THREADS 8

/*
 * This represents your object that "contains" the client connection and has
 * the client connection bound to it
 */

static struct my_conn {
	lws_sorted_usec_list_t	sul;	     /* schedule connection retry */
	struct lws		*wsi;	     /* related wsi if any */
	uint16_t		retry_count; /* count of consequetive retries */
} mco;

static char tx_buf[LWS_PRE + 1024];
static int tx_buf_is_ready = 0;

static struct lws_context *context;
static struct lws_vhost* ws_client_vhost;
static int interrupted, port = 443, ssl_connection = LCCSCF_USE_SSL;
static const char *server_address = "libwebsockets.org",
          *pro = "dumb-increment-protocol",
          *server_path = "/";



/*
 * The retry and backoff policy we want to use for our client connections
 */

static const uint32_t backoff_ms[] = { 1000, 2000, 3000, 4000, 5000 };

static const lws_retry_bo_t retry = {
	.retry_ms_table			= backoff_ms,
    .retry_ms_table_count	= LWS_ARRAY_SIZE(backoff_ms),
    .conceal_count			= LWS_ARRAY_SIZE(backoff_ms) +1,

	.secs_since_valid_ping		= 3,  /* force PINGs after secs idle */
	.secs_since_valid_hangup	= 10, /* hangup after secs idle */

	.jitter_percent			= 20,
};

/*
 * Scheduled sul callback that starts the connection attempt
 */

static void
connect_client(lws_sorted_usec_list_t *sul)
{
	struct my_conn *mco = lws_container_of(sul, struct my_conn, sul);
	struct lws_client_connect_info i;

	memset(&i, 0, sizeof(i));

	i.context = context;
	i.port = port;
	i.address = server_address;
    i.path = server_path;
	i.host = i.address;
	i.origin = i.address;
	i.ssl_connection = ssl_connection;
	i.protocol = pro;
	i.local_protocol_name = "lws-minimal-client";
	i.pwsi = &mco->wsi;
	i.retry_and_idle_policy = &retry;
	i.userdata = mco;

	if (!lws_client_connect_via_info(&i))
		/*
		 * Failed... schedule a retry... we can't use the _retry_wsi()
		 * convenience wrapper api here because no valid wsi at this
		 * point.
		 */
		if (lws_retry_sul_schedule(context, 0, sul, &retry,
					   connect_client, &mco->retry_count)) {
			lwsl_err("%s: connection attempts exhausted\n", __func__);
			interrupted = 1;
		}
}

static int
callback_minimal(struct lws *wsi, enum lws_callback_reasons reason,
		 void *user, void *in, size_t len)
{
	struct my_conn *mco = (struct my_conn *)user;

	switch (reason) {

    case LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL:
        lwsl_user("%s: LWS_CALLBACK_CLIENT_HTTP_BIND_PROTOCOL\n", __func__);
        break;
    case LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED:
        lwsl_user("%s: LWS_CALLBACK_SERVER_NEW_CLIENT_INSTANTIATED\n", __func__);
        break;
    case LWS_CALLBACK_WSI_CREATE:
        lwsl_user("%s: LWS_CALLBACK_WSI_CREATE: wsi=%p\n", __func__, wsi);
        break;
    case LWS_CALLBACK_WSI_DESTROY:
        lwsl_user("%s: LWS_CALLBACK_WSI_DESTROY: wsi=%p\n", __func__, wsi);
        break;
    case LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER:
        lwsl_user("%s: LWS_CALLBACK_CLIENT_APPEND_HANDSHAKE_HEADER. wsi->parent = %p\n", __func__, lws_get_parent(wsi));
        break;
    case LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP:
        lwsl_user("%s: LWS_CALLBACK_ESTABLISHED_CLIENT_HTTP\n", __func__);
        break;
    case LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH:
        lwsl_user("%s: LWS_CALLBACK_CLIENT_FILTER_PRE_ESTABLISH\n", __func__);
        break;
    case LWS_CALLBACK_CLIENT_HTTP_REDIRECT:
        lwsl_user("%s: LWS_CALLBACK_CLIENT_HTTP_REDIRECT. wsi->parent = %p\n", __func__, lws_get_parent(wsi));
        break;
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP:
        lwsl_user("%s: LWS_CALLBACK_RECEIVE_CLIENT_HTTP\n", __func__);
        break;
    case LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ:
        lwsl_user("%s: LWS_CALLBACK_RECEIVE_CLIENT_HTTP_READ\n", __func__);
        break;

    case LWS_CALLBACK_CLIENT_WRITEABLE: {
        lwsl_user("%s: LWS_CALLBACK_CLIENT_WRITEABLE\n", __func__);
        if( !tx_buf_is_ready ) {
            strcpy(tx_buf + LWS_PRE, "Hello, world!\n");
            tx_buf_is_ready = 1;
            lws_callback_on_writable(wsi);
        }
        else {
            size_t len = strlen(tx_buf + LWS_PRE);
            lws_write(wsi, tx_buf + LWS_PRE, len, 0);
            tx_buf_is_ready = 0;
        }
    } break;

    case LWS_CALLBACK_PROTOCOL_INIT:
        lwsl_user("LWS_CALLBACK_PROTOCOL_INIT: wsi parent = %p\n", lws_get_parent(wsi));
        break;
	case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
		lwsl_err("CLIENT_CONNECTION_ERROR: %s\n",
			 in ? (char *)in : "(null)");
		goto do_retry;
		break;

	case LWS_CALLBACK_CLIENT_RECEIVE:
        lwsl_info("LWS_CALLBACK_CLIENT_RECEIVE: wsi parent = %p\n", lws_get_parent(wsi));
		lwsl_hexdump_notice(in, len);
		break;

	case LWS_CALLBACK_CLIENT_ESTABLISHED:
        lwsl_user("LWS_CALLBACK_CLIENT_ESTABLISHED: wsi parent = %p\n", lws_get_parent(wsi));
		lwsl_user("%s: established\n", __func__);
		break;

	case LWS_CALLBACK_CLIENT_CLOSED:
		goto do_retry;

    case LWS_CALLBACK_GET_THREAD_ID: // Multithread detection support for lws
        return (uint64_t)pthread_self();

	default:
		break;
	}

	return lws_callback_http_dummy(wsi, reason, user, in, len);

do_retry:
	/*
	 * retry the connection to keep it nailed up
	 *
	 * For this example, we try to conceal any problem for one set of
	 * backoff retries and then exit the app.
	 *
	 * If you set retry.conceal_count to be larger than the number of
	 * elements in the backoff table, it will never give up and keep
	 * retrying at the last backoff delay plus the random jitter amount.
	 */
	if (lws_retry_sul_schedule_retry_wsi(wsi, &mco->sul, connect_client,
					     &mco->retry_count)) {
		lwsl_err("%s: connection attempts exhausted\n", __func__);
		interrupted = 1;
	}

	return 0;
}

static const struct lws_protocols protocols[] = {
	{ "lws-minimal-client", callback_minimal, 0, 0, },
	{ NULL, NULL, 0, 0 }
};

// from minimal-http-server-smp.c
void *thread_service(void *threadid)
{
    while (lws_service_tsi(context, 10000,
                   (int)(lws_intptr_t)threadid) >= 0 &&
           !interrupted)
        ;

    pthread_exit(NULL);

    return NULL;
}

static void
sigint_handler(int sig)
{
	interrupted = 1;
    lws_cancel_service(context);
}

int main(int argc, const char **argv)
{
    pthread_t pthread_service[COUNT_THREADS];
	struct lws_context_creation_info info;
	const char *p;
	int n = 0;
    void* retval = NULL;

	signal(SIGINT, sigint_handler);
	memset(&info, 0, sizeof info);
	lws_cmdline_option_handle_builtin(argc, argv, &info);

    const int log = LLL_USER | LLL_ERR | LLL_WARN | LLL_NOTICE
            // for LLL_ verbosity above NOTICE to be built into lws,
            // lws must have been configured and built with
            // -DCMAKE_BUILD_TYPE=DEBUG instead of =RELEASE
            | LLL_INFO /* | LLL_PARSER */ | LLL_HEADER
            /* | LLL_EXT */ | LLL_CLIENT /* | LLL_LATENCY */
            /* | LLL_DEBUG */ | LLL_THREAD;
    lws_set_log_level(log, NULL);

	lwsl_user("LWS minimal ws client\n");

#if defined(LWS_WITH_MBEDTLS) || defined(USE_WOLFSSL)
	/*
	 * OpenSSL uses the system trust store.  mbedTLS has to be told which
	 * CA to trust explicitly.
	 */
	info.client_ssl_ca_filepath = "./libwebsockets.org.cer";
#endif

	if ((p = lws_cmdline_option(argc, argv, "--protocol")))
		pro = p;

    if ((p = lws_cmdline_option(argc, argv, "--path")))
        server_path = p;

	if ((p = lws_cmdline_option(argc, argv, "-s")))
		server_address = p;

	if ((p = lws_cmdline_option(argc, argv, "-p")))
		port = atoi(p);

	if (lws_cmdline_option(argc, argv, "-n"))
		ssl_connection &= ~LCCSCF_USE_SSL;

	if (lws_cmdline_option(argc, argv, "-j"))
		ssl_connection |= LCCSCF_ALLOW_SELFSIGNED;

	if (lws_cmdline_option(argc, argv, "-k"))
		ssl_connection |= LCCSCF_ALLOW_INSECURE;

	if (lws_cmdline_option(argc, argv, "-m"))
		ssl_connection |= LCCSCF_SKIP_SERVER_CERT_HOSTNAME_CHECK;

	if (lws_cmdline_option(argc, argv, "-e"))
		ssl_connection |= LCCSCF_ALLOW_EXPIRED;

    /* #1 create service context without any vhost */
    info.options = LWS_SERVER_OPTION_EXPLICIT_VHOSTS;
    info.count_threads = COUNT_THREADS;

	context = lws_create_context(&info);
	if (!context) {
		lwsl_err("lws init failed\n");
		return 1;
	}

    /* #2 Create a vhost for a ws client */
    memset(&info, 0, sizeof info);
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.port = CONTEXT_PORT_NO_LISTEN; /* we do not run any server */
    info.protocols = protocols;
    info.fd_limit_per_thread = 1 + 1 + 1;

    ws_client_vhost = lws_create_vhost(context, &info);
    if (!ws_client_vhost) {
        lwsl_err("WebSocket client lws vhost creation failed\n");
        lws_context_destroy(context);
        return 1;
    }

	/* schedule the first client connection attempt to happen immediately */
	lws_sul_schedule(context, 0, &mco.sul, connect_client, 1);

    lwsl_notice("  Service threads: %d\n", lws_get_count_threads(context));

     /* start all the service threads */

     for (n = 0; n < lws_get_count_threads(context); n++)
         if (pthread_create(&pthread_service[n], NULL, thread_service,
                    (void *)(lws_intptr_t)n))
             lwsl_err("Failed to start service thread\n");

     /* wait for all the service threads to exit */

     while ((--n) >= 0)
         pthread_join(pthread_service[n], &retval);

	lws_context_destroy(context);
	lwsl_user("Completed\n");

	return 0;
}
