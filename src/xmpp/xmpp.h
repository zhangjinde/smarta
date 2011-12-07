/* 
** xmpp.h
*/

#ifndef __XMPP_H
#define __XMPP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include "ae.h"
//#include "tls.h"
#include "hash.h"
#include "list.h"
#include "stanza.h"
#include "parser.h"

#define XMPP_NS_CLIENT "jabber:client"

#define XMPP_NS_COMPONENT "jabber:component:accept"

#define XMPP_NS_STREAMS "http://etherx.jabber.org/streams"

#define XMPP_NS_STREAMS_IETF "urn:ietf:params:xml:ns:xmpp-streams"

#define XMPP_NS_TLS "urn:ietf:params:xml:ns:xmpp-tls"

#define XMPP_NS_SASL "urn:ietf:params:xml:ns:xmpp-sasl"

#define XMPP_NS_BIND "urn:ietf:params:xml:ns:xmpp-bind"

#define XMPP_NS_SESSION "urn:ietf:params:xml:ns:xmpp-session"

#define XMPP_NS_AUTH "jabber:iq:auth"

#define XMPP_NS_DISCO_INFO "http://jabber.org/protocol/disco#info"

#define XMPP_NS_DISCO_ITEMS "http://jabber.org/protocol/disco#items"

#define XMPP_NS_ROSTER "jabber:iq:roster"

#define XMPP_NS_PING "urn:xmpp:ping"

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
} XmppErrorType;

typedef struct _XmppError {
    XmppErrorType type;
    char *text;
    Stanza *stanza;
} XmppError; 

typedef enum {
    XMPP_STREAM_DISCONNECTED = 0,
    XMPP_STREAM_CONNECTING,
    XMPP_STREAM_TLS_NEGOTIATING,
    XMPP_STREAM_TSL_OPENED,
    XMPP_STREAM_SASL_AUTHENTICATING,
    XMPP_STREAM_SASL_AUTHED,
    XMPP_STREAM_BINDING,
    XMPP_STREAM_BINDED,
    XMPP_STREAM_SESSION_NEGOTIATING,
    XMPP_STREAM_ESTABLISHED
} XmppStreamState;

typedef enum {
    SUB_BOTH,
    SUB_TO,
    SUB_FROM
} Subscription;

typedef struct _Xmpp Xmpp;

struct _Xmpp {

	aeEventLoop *el;

    int fd; //socket

    char *jid;

    char*domain;
    
    char *server;

    char *pass;

    int port;

    int retries;

    XmppStreamState state;

    int error;

    XmppError *stream_error;

	//Tls *tls;

    int tls_support;

    int sasl_support; 

    char *stream_id;

    Parser *parser;

    int prepare_reset;

    /* keep alive */

    long long heartbeat;

    long long heartbeat_timeout;

    /* user handlers only get called after authentication */
    int authenticated;
    
    void *userdata;

    list *presences;

    list *conn_callbacks;

    list *presence_callbacks;

    list *message_callbacks;

    Hash *iq_id_callbacks;

    Hash *iq_ns_callbacks;
    
    Hash *roster;

};

typedef struct _Buddy {
    char *jid;
    char *name;
    Subscription sub;
} Buddy;

Buddy *buddy_new();
    
void buddy_release(void *buddy);

Xmpp *xmpp_new(aeEventLoop *el);

char *xmpp_send_ping(Xmpp *xmpp);

void xmpp_send_presence(Xmpp *xmpp, char *show_text, char *status_text);

void xmpp_send_message(Xmpp *xmpp, const char *to, const char *data);

void xmpp_set_state(Xmpp *xmpp, int state);

typedef void (*conn_callback)(Xmpp *xmpp, XmppStreamState state);

void xmpp_add_conn_callback(Xmpp *xmpp, conn_callback callback); 

void xmpp_remove_conn_callback(Xmpp *xmpp, conn_callback callback);

typedef void (*message_callback)(Xmpp *xmpp, Stanza *message);

void xmpp_add_message_callback(Xmpp *xmpp, message_callback callback);

void xmpp_remove_message_callback(Xmpp *xmpp, message_callback callback);

typedef void (*presence_callback)(Xmpp *xmpp, Stanza *presence);

void xmpp_add_presence_callback(Xmpp *xmpp, presence_callback callback);

void xmpp_remove_presence_callback(Xmpp *xmpp, presence_callback callback);

typedef void (*iq_callback)(Xmpp *xmpp, Stanza *iq);

iq_callback xmpp_get_iq_ns_callback(Xmpp *xmpp, char *ns);

void xmpp_add_iq_ns_callback(Xmpp *xmpp, char *iq_ns, iq_callback callback);

void xmpp_remove_iq_id_callback(Xmpp *xmpp, char *iq_id);

iq_callback xmpp_get_iq_id_callback(Xmpp *xmpp, char *id);

void xmpp_add_iq_id_callback(Xmpp *xmpp, char *iq_id, iq_callback callback); 

void xmpp_remove_iq_ns_callback(Xmpp *xmpp, char *iq_ns);

//#define SASL_MASK_PLAIN 0x01
//#define SASL_MASK_DIGESTMD5 0x02
//#define SASL_MASK_ANONYMOUS 0x04

char *xmpp_get_jid(Xmpp *xmpp);

void xmpp_set_jid(Xmpp *xmpp, const char *jid);

void xmpp_set_server(Xmpp *xmpp, const char *server);

void xmpp_set_port(Xmpp *xmpp, int port);

char *xmpp_get_pass(Xmpp *xmpp);

void xmpp_set_pass(Xmpp *xmpp, const char *pass);

int xmpp_connect(Xmpp *xmpp);

int xmpp_reconnect(aeEventLoop *el, long long id, void *clientData);

void xmpp_disconnect(Xmpp *xmpp);

//stream functions
int xmpp_stream_open(Xmpp *xmpp);

int xmpp_stream_feed(Xmpp *xmpp, char *buf, int nread);

void xmpp_send_stanza(Xmpp *xmpp, Stanza *stanza);

void xmpp_send_format(Xmpp *xmpp, char *fmt, ...);

void xmpp_send_string(Xmpp *xmpp, char *data, size_t len);

#endif /* __XMPP_H__ */

