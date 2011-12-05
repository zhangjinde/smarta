/*
** tls.h
*/

#ifndef __TLS_H__
#define __TLS_H__

typedef struct _Tls Tls;

void tls_initialize(void);

void tls_shutdown(void);

Tls *tls_new(int fd);

void tls_free(Tls *tls);

int tls_start(Tls *tls);

int tls_stop(Tls *tls);

int tls_error(Tls *tls, int err);

int tls_read(Tls *tls, void * const buff, const size_t len);

int tls_write(Tls *tls, const void * const buff, const size_t len);

//int tls_is_recoverable(int error);

#endif /* __TLS_H__ */
