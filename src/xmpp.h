/* xmpp.h
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

#ifndef __XMPP_H
#define __XMPP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include "ae.h"
#include "hash.h"
#include "list.h"
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
#define XMPP_OK 0

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


typedef struct _XmppStreamError XmppStreamError;

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


typedef struct _XmppStream XmppStream;

struct _XmppStream {

    int fd; //socket

    char *jid;

    char *domain;

    char *pass;

    int port;

    int retries;

    XmppStreamState state;

    uint64_t timeout_stamp;

    int error;

    XmppStreamError *stream_error;

    int tls_support;
    int sasl_support; 

    char *stream_id;

    Parser *parser;

    /* timeouts */
    unsigned int connect_timeout;

    int prepare_reset;

    /* user handlers only get called after authentication */
    int authenticated;
    
    void *userdata;

    Hash *events;

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

void xmpp_stream_set_state(XmppStream *stream, int state);

typedef void (*conn_callback)(XmppStream *stream, XmppStreamState state);

void xmpp_add_conn_callback(XmppStream *stream, conn_callback callback); 

void xmpp_remove_conn_callback(XmppStream *stream, conn_callback callback);

typedef void (*message_callback)(XmppStream *stream, XmppStanza *message);

void xmpp_add_message_callback(XmppStream *stream, message_callback callback);

void xmpp_remove_message_callback(XmppStream *stream, message_callback callback);

typedef void (*presence_callback)(XmppStream *stream, XmppStanza *presence);

void xmpp_add_presence_callback(XmppStream *stream, presence_callback callback);

void xmpp_remove_presence_callback(XmppStream *stream, presence_callback callback);

typedef void (*iq_callback)(XmppStream *stream, XmppStanza *iq);

iq_callback xmpp_get_iq_ns_callback(XmppStream *stream, char *ns);

void xmpp_add_iq_ns_callback(XmppStream *stream, char *iq_ns, iq_callback callback);

void xmpp_remove_iq_id_callback(XmppStream *stream, char *iq_id);

iq_callback xmpp_get_iq_id_callback(XmppStream *stream, char *id);

void xmpp_add_iq_id_callback(XmppStream *stream, char *iq_id, iq_callback callback); 

void xmpp_remove_iq_ns_callback(XmppStream *stream, char *iq_ns);

#define SASL_MASK_PLAIN 0x01
#define SASL_MASK_DIGESTMD5 0x02
#define SASL_MASK_ANONYMOUS 0x04

/* connection */
struct _XmppStreamError {
    XmppErrorType type;
    char *text;
    XmppStanza *stanza;
}; 

char *xmpp_stream_get_jid(XmppStream *stream);

void xmpp_stream_set_jid(XmppStream *stream, const char *jid);

char *xmpp_stream_get_pass(XmppStream *stream);

void xmpp_stream_set_pass(XmppStream *stream, const char *pass);

int xmpp_connect(aeEventLoop *el, XmppStream *stream);

void xmpp_disconnect(aeEventLoop *el, XmppStream *stream);

XmppStream *xmpp_stream_new();

int xmpp_stream_open(XmppStream *stream);

int xmpp_stream_feed(XmppStream *stream, char *buf, int nread);

void xmpp_send_stanza(XmppStream * stream, XmppStanza *stanza);

void xmpp_send_format(XmppStream *stream, char *fmt, ...);

void xmpp_send_string(XmppStream *stream, char *data, size_t len);

#endif /* __XMPP_H__ */

