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

#ifndef __XMPP_H
#define __XMPP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

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
#define LOG_DEBUG 0
#define LOG_INFO 1
#define LOG_WARN 2
#define LOG_ERROR 3

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
    XMPP_STREAM_DISCONNECTED,
    XMPP_STREAM_CONNECTING,
    XMPP_STREAM_TLS_NEGOTIATING,
    XMPP_STREAM_TSL_OPENED,
    XMPP_STREAM_SASL_AUTHENTICATING,
    XMPP_STREAM_SASL_AUTHED,
    XMPP_STREAM_CONNECTED
} XmppStreamState;

typedef struct _XmppStream XmppStream;

struct _XmppStream {

    int fd; //socket

    XmppStreamState state;

    uint64_t timeout_stamp;
    int error;
    XmppStreamError *stream_error;

    int tls_support;
    int sasl_support; /* if true, field is a bitfield of supported mechanisms */ 

    char *domain;
    char *connectdomain;
    char *connectport;
    char *jid;
    char *pass;
    char *bound_jid;
    char *stream_id;

    Parser *parser;

    /* timeouts */
    unsigned int connect_timeout;

    int prepare_reset;

    /* user handlers only get called after authentication */
    int authenticated;
    
    void *userdata;

    /* other handlers */
    Hash *iq_callbacks;
};


#define SASL_MASK_PLAIN 0x01
#define SASL_MASK_DIGESTMD5 0x02
#define SASL_MASK_ANONYMOUS 0x04

void xmpp_log(int level, const char *fmt, ...);

int xmpp_vsnprintf (char *str, size_t count, char *fmt, va_list arg);

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
//char *xmpp_conn_get_bound_jid(XmppConn *conn);

XmppStream *xmpp_stream_new(int fd);

int xmpp_stream_open(XmppStream *stream);

int xmpp_stream_feed(XmppStream *stream, char *buf, int nread);

void xmpp_send(XmppStream * stream, XmppStanza *stanza);

void xmpp_send_raw_string(XmppStream *stream, char *fmt, ...);

void xmpp_send_raw(XmppStream *stream, char *data, size_t len);

#endif /* __SMARTA_STROPHE_H__ */
