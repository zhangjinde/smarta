/* strophe.h
** strophe XMPP client library C API
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express or
**  implied.
**
**  This software is distributed under license and may not be copied,
**  modified or distributed except as expressly authorized under the
**  terms of the license contained in the file LICENSE.txt in this
**  distribution.
*/

/** @file
 *  Strophe public C API definitions.
 */

#ifndef _SMARTA_XMPP_H__
#define _SMARTA_XMPP_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#ifndef _WIN32
#include <stdint.h>
#endif

#include "sock.h"
#include "tls.h"
#include "hash.h"
#include "stanza.h"
#include "parser.h"

/* namespace defines */
/** @def XMPP_NS_CLIENT
 *  Namespace definition for 'jabber:client'.
 */
#define XMPP_NS_CLIENT "jabber:client"
/** @def XMPP_NS_COMPONENT
 *  Namespace definition for 'jabber:component:accept'.
 */
#define XMPP_NS_COMPONENT "jabber:component:accept"
/** @def XMPP_NS_STREAMS
 *  Namespace definition for 'http://etherx.jabber.org/streams'.
 */
#define XMPP_NS_STREAMS "http://etherx.jabber.org/streams"
/** @def XMPP_NS_STREAMS_IETF
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-streams'.
 */
#define XMPP_NS_STREAMS_IETF "urn:ietf:params:xml:ns:xmpp-streams"
/** @def XMPP_NS_TLS
 *  Namespace definition for 'url:ietf:params:xml:ns:xmpp-tls'.
 */
#define XMPP_NS_TLS "urn:ietf:params:xml:ns:xmpp-tls"
/** @def XMPP_NS_SASL
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-sasl'.
 */
#define XMPP_NS_SASL "urn:ietf:params:xml:ns:xmpp-sasl"
/** @def XMPP_NS_BIND
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-bind'.
 */
#define XMPP_NS_BIND "urn:ietf:params:xml:ns:xmpp-bind"
/** @def XMPP_NS_SESSION
 *  Namespace definition for 'urn:ietf:params:xml:ns:xmpp-session'.
 */
#define XMPP_NS_SESSION "urn:ietf:params:xml:ns:xmpp-session"
/** @def XMPP_NS_AUTH
 *  Namespace definition for 'jabber:iq:auth'.
 */
#define XMPP_NS_AUTH "jabber:iq:auth"
/** @def XMPP_NS_DISCO_INFO
 *  Namespace definition for 'http://jabber.org/protocol/disco#info'.
 */
#define XMPP_NS_DISCO_INFO "http://jabber.org/protocol/disco#info"
/** @def XMPP_NS_DISCO_ITEMS
 *  Namespace definition for 'http://jabber.org/protocol/disco#items'.
 */
#define XMPP_NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"
/** @def XMPP_NS_ROSTER
 *  Namespace definition for 'jabber:iq:roster'.
 */
#define XMPP_NS_ROSTER "jabber:iq:roster"

/* error defines */
/** @def XMPP_EOK
 *  Success error code.
 */
#define XMPP_EOK 0
/** @def XMPP_EMEM
 *  Memory related failure error code.
 *  
 *  This is returned on allocation errors and signals that the host may
 *  be out of memory.
 */
#define XMPP_EMEM -1
/** @def XMPP_EINVOP
 *  Invalid operation error code.
 *
 *  This error code is returned when the operation was invalid and signals
 *  that the Strophe API is being used incorrectly.
 */
#define XMPP_EINVOP -2
/** @def XMPP_EINT
 *  Internal failure error code.
 */
#define XMPP_EINT -3

#define MAX_LOGMSG_LEN    1024 /* Default maximum length of syslog messages */
#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3

/** run-time context **/

typedef enum {
    XMPP_LOOP_NOTSTARTED,
    XMPP_LOOP_RUNNING,
    XMPP_LOOP_QUIT
} xmpp_loop_status_t;

typedef enum {
    XMPP_LEVEL_DEBUG,
    XMPP_LEVEL_INFO,
    XMPP_LEVEL_WARN,
    XMPP_LEVEL_ERROR
} xmpp_log_level_t;

typedef enum {
    XMPP_UNKNOWN,
    XMPP_CLIENT,
    XMPP_COMPONENT
} xmpp_conn_type_t;

/* connect callback */
typedef enum {
    XMPP_CONN_CONNECT,
    XMPP_CONN_DISCONNECT,
    XMPP_CONN_FAIL
} xmpp_conn_event_t;

typedef enum {
    XMPP_SE_BAD_FORMAT,
    XMPP_SE_BAD_NS_PREFIX,
    XMPP_SE_CONFLICT,
    XMPP_SE_CONN_TIMEOUT,
    XMPP_SE_HOST_GONE,
    XMPP_SE_HOST_UNKNOWN,
    XMPP_SE_IMPROPER_ADDR,
    XMPP_SE_INTERNAL_SERVER_ERROR,
    XMPP_SE_INVALID_FROM,
    XMPP_SE_INVALID_ID,
    XMPP_SE_INVALID_NS,
    XMPP_SE_INVALID_XML,
    XMPP_SE_NOT_AUTHORIZED,
    XMPP_SE_POLICY_VIOLATION,
    XMPP_SE_REMOTE_CONN_FAILED,
    XMPP_SE_RESOURCE_CONSTRAINT,
    XMPP_SE_RESTRICTED_XML,
    XMPP_SE_SEE_OTHER_HOST,
    XMPP_SE_SYSTEM_SHUTDOWN,
    XMPP_SE_UNDEFINED_CONDITION,
    XMPP_SE_UNSUPPORTED_ENCODING,
    XMPP_SE_UNSUPPORTED_STANZA_TYPE,
    XMPP_SE_UNSUPPORTED_VERSION,
    XMPP_SE_XML_NOT_WELL_FORMED
} xmpp_error_type_t;


/* convenience functions for accessing the context */
char *xmpp_strdup(const char * const s);

/** jid */
char *xmpp_jid_new(const char *node, const char *domain, const char *resource);
char *xmpp_jid_bare(const char *jid);
char *xmpp_jid_node(const char *jid);
char *xmpp_jid_domain(const char *jid);
char *xmpp_jid_resource(const char *jid);

typedef struct _xmpp_stream_error_t xmpp_stream_error_t;

/** connection **/

/* opaque connection object */
typedef enum {
    XMPP_STATE_DISCONNECTED,
    XMPP_STATE_CONNECTING,
    XMPP_STATE_CONNECTED
} xmpp_conn_state_t;

typedef struct _xmpp_send_queue_t xmpp_send_queue_t;
struct _xmpp_send_queue_t {
    char *data;
    size_t len;
    size_t written;
    xmpp_send_queue_t *next;
};

typedef struct _XmppConn XmppConn;

typedef void (*xmpp_open_handler)(XmppConn * const conn);

typedef struct _xmpp_handlist_t xmpp_handlist_t;

typedef void (*xmpp_conn_handler)(XmppConn * const conn, 
				  const xmpp_conn_event_t event,
				  const int error,
				  xmpp_stream_error_t * const stream_error,
				  void * const userdata);

/* if the handle returns false it is removed */
typedef int (*xmpp_timed_handler)(XmppConn * const conn, 
				  void * const userdata);

/* if the handler returns false it is removed */
typedef int (*xmpp_handler)(XmppConn * const conn,
			     XmppStanza * const stanza,
			     void * const userdata);

struct _xmpp_handlist_t {
    /* common members */
    int user_handler;
    void *handler;
    void *userdata;
    int enabled; /* handlers are added disabled and enabled after the
		  * handler chain is processed to prevent stanzas from
		  * getting processed by newly added handlers */
    xmpp_handlist_t *next;

    union {
	/* timed handlers */
	struct {
	    unsigned long period;
	    uint64_t last_stamp;
	};
	/* id handlers */
	struct {
	    char *id;
	};
	/* normal handlers */
	struct {
	    char *ns;
	    char *name;
	    char *type;
	};
    };
};

#define SASL_MASK_PLAIN 0x01
#define SASL_MASK_DIGESTMD5 0x02
#define SASL_MASK_ANONYMOUS 0x04

/* opaque run time context containing the above hooks */
typedef struct _xmpp_ctx_t xmpp_ctx_t;

struct _XmppConn {
    unsigned int ref;
    xmpp_ctx_t *ctx;
    xmpp_conn_type_t type;

    xmpp_conn_state_t state;
    uint64_t timeout_stamp;
    int error;
    xmpp_stream_error_t *stream_error;
    sock_t sock;
    tls_t *tls;

    int tls_support;
    int tls_failed; /* set when tls fails, so we don't try again */
    int sasl_support; /* if true, field is a bitfield of supported 
			 mechanisms */ 
    int secured; /* set when stream is secured with TLS */

    /* if server returns <bind/> or <session/> we must do them */
    int bind_required;
    int session_required;

    char *lang;
    char *domain;
    char *connectdomain;
    char *connectport;
    char *jid;
    char *pass;
    char *bound_jid;
    char *stream_id;

    /* send queue and parameters */
    int blocking_send;
    int send_queue_max;
    int send_queue_len;
    xmpp_send_queue_t *send_queue_head;
    xmpp_send_queue_t *send_queue_tail;

    /* xml parser */
    int reset_parser;
    parser_t *parser;

    /* timeouts */
    unsigned int connect_timeout;

    /* event handlers */    

    /* stream open handler */
    xmpp_open_handler open_handler;

    /* user handlers only get called after authentication */
    int authenticated;
    
    /* connection events handler */
    xmpp_conn_handler conn_handler;

    void *userdata;

    /* other handlers */
    xmpp_handlist_t *timed_handlers;
    hash_t *id_handlers;
    xmpp_handlist_t *handlers;
};



void conn_disconnect(XmppConn * const conn);
void conn_disconnect_clean(XmppConn * const conn);
void conn_open_stream(XmppConn * const conn);
void conn_prepare_reset(XmppConn * const conn, xmpp_open_handler handler);
void conn_parser_reset(XmppConn * const conn);

/* handler management */
void handler_fire_stanza(XmppConn * const conn,
			 XmppStanza * const stanza);
uint64_t handler_fire_timed(xmpp_ctx_t * const ctx);
void handler_reset_timed(XmppConn *conn, int user_only);
void handler_add_timed(XmppConn * const conn,
		       xmpp_timed_handler handler,
		       const unsigned long period,
		       void * const userdata);
void handler_add_id(XmppConn * const conn,
		    xmpp_handler handler,
		    const char * const id,
		    void * const userdata);
void handler_add(XmppConn * const conn,
		 xmpp_handler handler,
		 const char * const ns,
		 const char * const name,
		 const char * const type,
		 void * const userdata);

/* utility functions */
void disconnect_mem_error(XmppConn * const conn);

/* auth functions */
void auth_handle_open(XmppConn * const conn);

/* replacement snprintf and vsnprintf */
int xmpp_snprintf (char *str, size_t count, const char *fmt, ...);
int xmpp_vsnprintf (char *str, size_t count, const char *fmt, va_list arg);



void xmpp_log(int level, const char *fmt, ...);

/* initialization and shutdown */
void xmpp_initialize(void);
void xmpp_shutdown(void);

/* version */
int xmpp_version_check(int major, int minor);

/* run-time contexts */

/* user-replaceable memory allocator */
typedef struct _xmpp_mem_t xmpp_mem_t;

/* user-replaceable log object */
typedef struct _xmpp_log_t xmpp_log_t;

xmpp_ctx_t *xmpp_ctx_new(const xmpp_mem_t * const mem, 
			     const xmpp_log_t * const log);
void xmpp_ctx_free(xmpp_ctx_t * const ctx);

struct _xmpp_mem_t {
    void *(*alloc)(const size_t size, void * const userdata);
    void (*free)(void *p, void * const userdata);
    void *(*realloc)(void *p, const size_t size, void * const userdata);
    void *userdata;
};

typedef void (*xmpp_log_handler)(void * const userdata, 
				 const xmpp_log_level_t level,
				 const char * const area,
				 const char * const msg);

struct _xmpp_log_t {
    xmpp_log_handler handler;
    void *userdata;
    /* mutex_t lock; */
};

/* return a default logger filtering at a given level */
xmpp_log_t *xmpp_get_default_logger(xmpp_log_level_t level);

/* connection */

typedef struct _xmpp_connlist_t {
    XmppConn *conn;
    struct _xmpp_connlist_t *next;
} xmpp_connlist_t;

struct _xmpp_ctx_t {
    xmpp_loop_status_t loop_status;
    xmpp_connlist_t *connlist;
};

struct _xmpp_stream_error_t {
    xmpp_error_type_t type;
    char *text;
    XmppStanza *stanza;
}; 

XmppConn *xmpp_conn_new(xmpp_ctx_t * const ctx);

XmppConn * xmpp_conn_clone(XmppConn * const conn);

int xmpp_conn_release(XmppConn * const conn);

const char *xmpp_conn_get_jid(const XmppConn * const conn);
const char *xmpp_conn_get_bound_jid(const XmppConn * const conn);
void xmpp_conn_set_jid(XmppConn * const conn, const char * const jid);
const char *xmpp_conn_get_pass(const XmppConn * const conn);
void xmpp_conn_set_pass(XmppConn * const conn, const char * const pass);
xmpp_ctx_t* xmpp_conn_get_context(XmppConn * const conn);

int xmpp_connect_client(XmppConn * const conn, 
			  const char * const altdomain,
			  unsigned short altport,
			  xmpp_conn_handler callback,
			  void * const userdata);

/*
int xmpp_connect_component(conn, name)
*/
void xmpp_disconnect(XmppConn * const conn);

void xmpp_send(XmppConn * const conn,
	       XmppStanza * const stanza);

void xmpp_send_raw_string(XmppConn * const conn, 
			  const char * const fmt, ...);
void xmpp_send_raw(XmppConn * const conn, 
		   const char * const data, const size_t len);


/* handlers */


void xmpp_timed_handler_add(XmppConn * const conn,
			    xmpp_timed_handler handler,
			    const unsigned long period,
			    void * const userdata);
void xmpp_timed_handler_delete(XmppConn * const conn,
			       xmpp_timed_handler handler);



void xmpp_handler_add(XmppConn * const conn,
		      xmpp_handler handler,
		      const char * const ns,
		      const char * const name,
		      const char * const type,
		      void * const userdata);
void xmpp_handler_delete(XmppConn * const conn,
			 xmpp_handler handler);

void xmpp_id_handler_add(XmppConn * const conn,
			 xmpp_handler handler,
			 const char * const id,
			 void * const userdata);
void xmpp_id_handler_delete(XmppConn * const conn,
			    xmpp_handler handler,
			    const char * const id);

/*
void xmpp_register_stanza_handler(conn, stanza, xmlns, type, handler)
*/


/** event loop **/
void xmpp_run_once(xmpp_ctx_t *ctx, const unsigned long  timeout);
void xmpp_run(xmpp_ctx_t *ctx);
void xmpp_stop(xmpp_ctx_t *ctx);

#endif /* __LIBSTROPHE_STROPHE_H__ */
