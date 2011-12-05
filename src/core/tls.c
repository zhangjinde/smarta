/* 
** tls.c
** TLS openssl impl.
*/
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/rand.h>

#include "tls.h"
#include "zmalloc.h"

static int tls_initialized = 0;

struct _Tls {
    int fd;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
//    int lasterror;
};

void tls_initialize(void)
{
	SSL_library_init();
	SSL_load_error_strings();
	tls_initialized = 1;
}

void tls_shutdown(void)
{
    return;
}

// Recoverable errors
// SSL_ERROR_NONE 
// SSL_ERROR_WANT_READ
// SSL_ERROR_WANT_WRITE
// SSL_ERROR_WANT_CONNECT
// SSL_ERROR_WANT_ACCEPT);
int tls_error(Tls *tls, int err)
{
	return SSL_get_error(tls->ssl, err);
}

Tls *tls_new(int fd)
{
	int ret;
    Tls *tls = zmalloc(sizeof(Tls));
	memset(tls, 0, sizeof(*tls));

	tls->fd = fd;
	tls->ssl_ctx = SSL_CTX_new(SSLv23_client_method());

	SSL_CTX_set_client_cert_cb(tls->ssl_ctx, NULL);
	SSL_CTX_set_mode (tls->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
	SSL_CTX_set_verify (tls->ssl_ctx, SSL_VERIFY_NONE, NULL);

	tls->ssl = SSL_new(tls->ssl_ctx);

	ret = SSL_set_fd(tls->ssl, fd);
	if (ret <= 0) {
	    tls_free(tls);
	    tls = NULL;
    }

    return tls;
}

void tls_free(Tls *tls)
{
    SSL_CTX_free(tls->ssl_ctx);
    zfree(tls);
}

int tls_start(Tls *tls)
{
	if(!tls_initialized) {
		tls_initialize();
	}

	return SSL_connect(tls->ssl);
}

int tls_stop(Tls *tls)
{
    return SSL_shutdown(tls->ssl);
}

int tls_read(Tls *tls, void * const buff, const size_t len)
{
    return SSL_read(tls->ssl, buff, len);
}

int tls_write(Tls *tls, const void * const buff, const size_t len)
{
    return SSL_write(tls->ssl, buff, len);
}

