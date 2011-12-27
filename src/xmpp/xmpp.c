/*
**
** xmpp.c - xmpp client functions
**
** Credits: This file come from libstrophe.
**
** Copyright (c) 2011 nodebus.com.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License version 2 as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
*/
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "ae.h"
#include "sds.h"
#include "jid.h"
#include "anet.h"
#include "sasl.h"
#include "xmpp.h"
#include "stanza.h"
#include "logger.h"
#include "zmalloc.h"
#include "config.h"

#define MAX_RETRIES 3

#define HEARTBEAT 120000

#define HEARTBEAT_TIMEOUT 20000

static void 
xmpp_read(aeEventLoop *el, int fd, void *privdata, int mask);

static void 
_xmpp_stream_starttls(Xmpp *xmpp, Stanza *tlsFeature);

static Stanza *
_make_starttls(Xmpp *xmpp);

//static void _handle_tls_opened(Xmpp *xmpp);

static void 
_xmpp_stream_auth(Xmpp *const xmpp, Stanza *mechanisms);

static Stanza *
_make_sasl_auth(const char *mechanism);

static void 
_xmpp_stream_bind(Xmpp *xmpp, Stanza *bind); 

static void 
_xmpp_stream_bind_callback(Xmpp *xmpp, Stanza *iq); 

static void 
_xmpp_stream_session_callback(Xmpp *xmpp, Stanza *iq);

static void 
_xmpp_stream_session(Xmpp *xmpp);

static void 
_xmpp_stream_closed(Xmpp *xmpp);

static void 
_handle_stream_start(char *name, char **attrs, void *userdata);

static void 
_handle_stream_stanza( Stanza *stanza, void *userdata);

static void 
_handle_stream_features(Xmpp *xmpp, Stanza *stanza);

static void 
_handle_stream_errors(Xmpp *xmpp, Stanza *stanza);

static void 
_handle_xmpp_iq(Xmpp *xmpp, Stanza *iq); 

static void 
_handle_xmpp_message(Xmpp *xmpp, Stanza *message);

static void 
_handle_auth_success(Xmpp *xmpp, Stanza *stanza);

static void 
_handle_auth_failure(Xmpp *xmpp, Stanza *stanza); 

static void 
_handle_xmpp_presence(Xmpp *xmpp, Stanza *presence); 

static void 
_handle_stream_end(char *name, void *userdata);

static void 
_remove_callback_from_list(list *callbacks, void *callback);

static void 
_xmpp_stream_roster(Xmpp *xmpp); 

static void 
_xmpp_stream_roster_callback(Xmpp *xmpp, Stanza *stanza); 

static void 
_xmpp_heartbeat_handler(Xmpp *xmpp, XmppStreamState state);

static int 
xmpp_heartbeat(aeEventLoop *el, long long id, void *clientData); 

static int 
xmpp_heartbeat_timeout(aeEventLoop *el, long long id, void *clientData);

static void 
xmpp_heartbeat_callback(Xmpp *xmpp, Stanza *stanza);

static int 
strequal(const char* s1, const char *s2); 

static int 
strmatch(void *s1, void *s2);

Xmpp *
xmpp_new(aeEventLoop *el) 
{
    Xmpp *xmpp = NULL;
    xmpp = zmalloc(sizeof(Xmpp));

	xmpp->el = el;

    xmpp->retries = 0;

    xmpp->jid = NULL;

    xmpp->domain = NULL;

    xmpp->server = NULL;

    xmpp->port = 5222;

    xmpp->stream_id = NULL;

    xmpp->state = XMPP_STREAM_DISCONNECTED;

    xmpp->presences = listCreate();

    listSetMatchMethod(xmpp->presences, strmatch); 

    xmpp->conn_callbacks = listCreate();
    
    xmpp->message_callbacks = listCreate();

    xmpp->presence_callbacks = listCreate();

    xmpp->roster = hash_new(8, buddy_release);

    xmpp->iq_ns_callbacks = hash_new(8, NULL);

    xmpp->iq_id_callbacks = hash_new(8, NULL);

    xmpp->prepare_reset = 0;

    xmpp->parser = parser_new(_handle_stream_start,
          _handle_stream_end,
          _handle_stream_stanza,
          xmpp);

	//TODO: ok?
	xmpp_add_conn_callback(xmpp, (conn_callback)_xmpp_heartbeat_handler);

    return xmpp;
}

int 
xmpp_connect(Xmpp *xmpp)
{
    char err[1024] = {0};
    char server[1024] = {0};
    if(anetResolve(err, xmpp->server, server) != ANET_OK) {
        logger_error("XMPP", "cannot resolve %s, error: %s", xmpp->server, err);
        exit(-1);
    } 
    logger_debug("XMPP", "connect to %s", server);
    int fd = anetTcpConnect(err, server, xmpp->port);
    if (fd < 0) {
        logger_error("SOCKET", "failed to connect %s: %s\n", xmpp->server, err);
        return fd;
    }
    xmpp->fd = fd;
    aeCreateFileEvent(xmpp->el, fd, AE_READABLE, xmpp_read, xmpp); //| AE_WRITABLE
    xmpp_set_state(xmpp, XMPP_STREAM_CONNECTING);
    xmpp_stream_open(xmpp);
    return fd;
}

static void 
xmpp_read(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    int timeout;
    char buf[4096] = {0};

    Xmpp *xmpp = (Xmpp *)privdata;

	//if(xmpp->tls) {
	//		nread = tls_read(xmpp->tls, buf, 4096);
	//} else {
		nread = read(fd, buf, 4096);
	//}
    if(nread <= 0) {
        if (errno == EAGAIN) { 
            logger_warning("XMPP", "TCP EAGAIN");
            return;
        }
        logger_error("XMPP", "xmpp server is disconnected.");
        xmpp_disconnect(xmpp);
		timeout = (random() % 120) * 1000,
		logger_info("XMPP", "reconnect after %d seconds", timeout/1000);
		aeCreateTimeEvent(el, timeout, xmpp_reconnect, xmpp, NULL);
    } else {
        logger_debug("SOCKET", "RECV: %s", buf);
        xmpp_stream_feed(xmpp, buf, nread);
    }
}

int 
xmpp_reconnect(aeEventLoop *el, long long id, void *clientData)
{
    int fd;
    int timeout;
    Xmpp *xmpp = (Xmpp *)clientData;
    fd = xmpp_connect((Xmpp *)clientData);
    if(fd < 0) {
        if(xmpp->retries > MAX_RETRIES) {
            xmpp->retries = 1;
        } 
        timeout = ((2 * xmpp->retries) * 60) * 1000;
        logger_debug("XMPP", "reconnect after %d seconds", timeout/1000);
        aeCreateTimeEvent(el, timeout, xmpp_reconnect, xmpp, NULL);
        xmpp->retries++;
    } else {
        xmpp->retries = 1;
    }
    return AE_NOMORE;
}

void 
xmpp_disconnect(Xmpp *xmpp) 
{
    logger_debug("XMPP", "xmpp is disconnected");
	//if(xmpp->tls) {
	//		tls_free(xmpp->tls);
	//	xmpp->tls = NULL;
	//}
    if(xmpp->fd > 0) {
        aeDeleteFileEvent(xmpp->el, xmpp->fd, AE_READABLE);
        close(xmpp->fd);
        xmpp->fd = -1;
    }
    xmpp_set_state(xmpp, XMPP_STREAM_DISCONNECTED);

    if(xmpp->presences) {
        listRelease(xmpp->presences);
        xmpp->presences = listCreate();
        listSetMatchMethod(xmpp->presences, strmatch); 
    }

    if(xmpp->roster) {
        hash_release(xmpp->roster);
        xmpp->roster = hash_new(8, buddy_release);
    }

    if(xmpp->iq_id_callbacks) {
        hash_release(xmpp->iq_id_callbacks);
        xmpp->iq_id_callbacks = hash_new(8, NULL);
    }

    if(xmpp->iq_ns_callbacks) {
        hash_release(xmpp->iq_ns_callbacks);
        xmpp->iq_ns_callbacks = hash_new(8, NULL);
    }
    
    xmpp->prepare_reset = 0;

}

char *
xmpp_send_ping(Xmpp *xmpp)
{
    Stanza *iq = NULL, *ping = NULL;
    char *id = sdscatprintf(sdsempty(), "ping_%ld", random());

	iq = stanza_tag("iq");
	stanza_set_type(iq, "get");
	stanza_set_id(iq, id); 

	ping = stanza_tag("ping");
	stanza_set_ns(ping, XMPP_NS_PING);

	stanza_add_child(iq, ping);
	stanza_release(ping);

    xmpp_send_stanza(xmpp, iq);
    stanza_release(iq);
    return id;
}

void 
xmpp_send_presence(Xmpp *xmpp, char *show_text, char *status_text)
{
    Stanza *presence, *show, *status, *text;

    presence = stanza_tag("presence");

	show = stanza_tag("show");
    text = stanza_text(show_text);
    stanza_add_child(show, text);

    stanza_add_child(presence, show);

    status = stanza_tag("status");
    text = stanza_text(status_text);
    stanza_add_child(status, text);

    stanza_add_child(presence, status);

    xmpp_send_stanza(xmpp, presence);

    stanza_release(presence);
}

void 
xmpp_send_body(Xmpp *xmpp, char *to, char *body)
{
	Message *msg = message_new(to, body);
	xmpp_send_message(xmpp, msg);
	message_free(msg);
}

void 
xmpp_send_message(Xmpp *xmpp, Message *m)
{
    Stanza *message, *thread, 
		*subject, *body, *text; 

	message = stanza_tag("message");
	stanza_set_type(message, "chat");
	stanza_set_attribute(message, "to", m->to);
	if(m->thread) {
		thread = stanza_tag("thread");
		text = stanza_text(m->thread);
		stanza_add_child(thread, text);
		stanza_add_child(message, thread);
	}
	if(m->subject) {
		subject = stanza_tag("subject");
		text = stanza_text(m->subject);
		stanza_add_child(subject, text);
		stanza_add_child(message, subject);
	}
	body = stanza_tag("body");
	text = stanza_cdata(m->body);
	stanza_add_child(body, text);
	stanza_add_child(message, body);
	
	xmpp_send_stanza(xmpp, message);
	stanza_release(message);
}

void 
xmpp_set_state(Xmpp *xmpp, int state)  
{
    listNode *node = NULL;
    listIter *iter;
    conn_callback callback;
    if(xmpp->state != state) {
        xmpp->state = state;
        iter = listGetIterator(xmpp->conn_callbacks, AL_START_HEAD);
        while((node = listNext(iter))) {
            callback = (conn_callback)node->value;
            callback(xmpp, state);
        }
        listReleaseIterator(iter);
    }
}

char *
xmpp_get_jid(Xmpp *xmpp) 
{
    return xmpp->jid;
}

void 
xmpp_set_jid(Xmpp *xmpp, const char *jid) 
{
    xmpp->jid = zstrdup(jid);
    xmpp->domain = jid_domain(jid);
    xmpp_set_server(xmpp, xmpp->domain);
}

void 
xmpp_set_server(Xmpp *xmpp, const char *server) 
{ 
    if(xmpp->server) zfree(xmpp->server);
    xmpp->server = zstrdup(server);
}

void 
xmpp_set_port(Xmpp *xmpp, int port) 
{
    xmpp->port = port;
}

char *
xmpp_get_pass(Xmpp *xmpp) 
{
    return xmpp->pass;
}

void 
xmpp_set_pass(Xmpp *xmpp, const char *pass) 
{
    xmpp->pass = zstrdup(pass);
}

void 
xmpp_add_conn_callback(Xmpp *xmpp, conn_callback callback) 
{
    listAddNodeHead(xmpp->conn_callbacks, callback);
}

void xmpp_remove_conn_callback(Xmpp *xmpp, conn_callback callback) 
{
    _remove_callback_from_list(xmpp->conn_callbacks, callback);
}

void 
xmpp_add_message_callback(Xmpp *xmpp, message_callback callback)
{
    listAddNodeHead(xmpp->message_callbacks, callback);
}

void 
xmpp_remove_message_callback(Xmpp *xmpp, message_callback callback) 
{
    _remove_callback_from_list(xmpp->message_callbacks, callback);
}

void 
xmpp_add_presence_callback(Xmpp *xmpp, presence_callback callback) 
{
    listAddNodeHead(xmpp->presence_callbacks, callback);
}

void 
xmpp_remove_presence_callback(Xmpp *xmpp, presence_callback callback) 
{
    _remove_callback_from_list(xmpp->presence_callbacks, callback);
}

iq_callback 
xmpp_get_iq_ns_callback(Xmpp *xmpp, char *ns) 
{
    return hash_get(xmpp->iq_ns_callbacks, ns);
}

void 
xmpp_add_iq_ns_callback(Xmpp *xmpp, char *iq_ns, iq_callback callback) 
{
    hash_add(xmpp->iq_ns_callbacks, iq_ns, callback);
}

void 
xmpp_remove_iq_ns_callback(Xmpp *xmpp, char *iq_ns) 
{
    hash_drop(xmpp->iq_ns_callbacks, iq_ns);
}

void 
xmpp_remove_iq_id_callback(Xmpp *xmpp, char *iq_id) 
{
    hash_drop(xmpp->iq_id_callbacks, iq_id);
}

iq_callback 
xmpp_get_iq_id_callback(Xmpp *xmpp, char *id) 
{
    return hash_get(xmpp->iq_id_callbacks, id);
}

void 
xmpp_add_iq_id_callback(Xmpp *xmpp, char *iq_id, iq_callback callback) 
{
    hash_add(xmpp->iq_id_callbacks, iq_id, callback);
}

int 
xmpp_stream_open(Xmpp *xmpp) 
{

    xmpp->prepare_reset = 1;
    
    xmpp_send_format(xmpp, 
			 "<?xml version=\"1.0\"?>"			\
			 "<stream:stream to=\"%s\" "			\
			 "xml:lang=\"%s\" "				\
			 "version=\"1.0\" "				\
			 "xmlns=\"%s\" "				\
			 "xmlns:stream=\"%s\">", 
			 xmpp->domain,
			 "en",
			 XMPP_NS_CLIENT,
			 XMPP_NS_STREAMS);

    return 0;

}

void 
xmpp_send_format(Xmpp *xmpp, char *fmt, ...) 
{
    va_list ap;
    size_t len = 0;
    char buf[4096]={0}; /* small buffer for common case */

    va_start(ap, fmt);
    len = vsnprintf(buf, 4096, fmt, ap);
    va_end(ap);

    if (len >= 4096) {
        logger_error("xmpp", "cannot send the packet, len:%d is over 4096", len);
        return;
    }

	xmpp_send_string(xmpp, buf, len);
}

void 
xmpp_send_string(Xmpp *xmpp, char *data, size_t len)
{
    if (xmpp->state == XMPP_STREAM_DISCONNECTED) {
        return;
    }
	logger_debug("XMPP", "SENT: %s", data);
	//if(xmpp->tls) {
//		tls_write(xmpp->tls, data, len);
//	} else {
		anetWrite(xmpp->fd, data, len);
//	}
}

void 
xmpp_send_stanza(Xmpp *xmpp, Stanza *stanza) 
{
    int ret;
    char *buf = NULL;
    size_t len = 0;

	if ((ret = stanza_to_text(stanza, &buf, &len)) == 0) {
	    xmpp_send_string(xmpp, buf, len);
	    zfree(buf);
	}
}

int 
xmpp_stream_feed(Xmpp *xmpp, char *buffer, int len) 
{
    return parser_feed(xmpp->parser, buffer, len);
}

static void 
_handle_stream_start(char *name, char **attrs, void *userdata) 
{
    char *id = NULL;

    Xmpp *xmpp = (Xmpp *)userdata;

    if (strcmp(name, "stream:stream") != 0) {
        logger_fatal("xmpp", "server did not open valid stream.");
        exit(1);
    }
    if (xmpp->stream_id) {
        zfree(xmpp->stream_id);
    }
    id = stanza_attrs_get_value(attrs, "id");
    if (id) {
        xmpp->stream_id = zstrdup(id);
    }
}

static void 
_handle_stream_stanza(Stanza * const stanza, void * const userdata) 
{
    char *buf;
    size_t len;
    char *xmlns, *name;
    Xmpp *xmpp = (Xmpp *)userdata;

    if (stanza_to_text(stanza, &buf, &len) == 0) {
        logger_debug("XMPP", "RECV: %s", buf);
        zfree(buf);
    }
    
    xmlns = stanza_get_ns(stanza);
    name = stanza_get_name(stanza);

    logger_debug("XMPP", "xmlns: %s, name: %s", xmlns, name);

    if(strequal(name, "iq")) {
        _handle_xmpp_iq(xmpp, stanza);
    } else if(strequal(name, "presence")) {
        _handle_xmpp_presence(xmpp, stanza);
    } else if(strequal(name, "message")) {
        _handle_xmpp_message(xmpp, stanza);
    } else if(strequal(name, "stream:features")) {
            _handle_stream_features(xmpp, stanza);
    } else if(strequal(name, "stream:error")) {
            _handle_stream_errors(xmpp, stanza);
    } else if(strequal(xmlns, XMPP_NS_SASL)) {
        if(xmpp->state != XMPP_STREAM_SASL_AUTHENTICATING) {
            logger_error("XMPP", "Ignoring suprios SASL stanza %s", name);
        } else {
			if (strequal(name, "challenge")) {
                logger_error("XMPP", "Challenge is not supported %s", name);
				//handle_auth_challenge(xmpp, stnaza);
            } else if (strequal(name, "success")) {
				_handle_auth_success(xmpp, stanza);
            } else if (strequal(name, "failure")) {
				_handle_auth_failure(xmpp, stanza);
            }
        }
    } else if(strequal(xmlns, XMPP_NS_TLS)) {
        if(xmpp->state != XMPP_STREAM_TLS_NEGOTIATING) {
            logger_error("XMPP", "Ignoreing spurios %s", name);
        } else {
            if(strequal(name, "proceed")) {
				//xmpp->tls = tls_new(xmpp->fd);
				//ret = tls_start(xmpp->tls);
				//if(ret <= 0) {
			//		logger_error("XMPP", "Couldn't start TLS, exit now! error: %d", ret);
		//			tls_free(xmpp->tls);
		//			exit(-1);
		//		}
		//		_handle_tls_opened(xmpp); 
            }
        }
    } else {
        logger_error("XMPP", "received unknown stanza: %s", name);
    }

}

//static void _handle_tls_opened(Xmpp *xmpp) 
//{
//    xmpp_set_state(xmpp, XMPP_STREAM_TSL_OPENED);
//    xmpp_stream_open(xmpp);
//}

static int 
is_buddy(Xmpp *xmpp, char *jid) 
{
    char *bare_jid = jid_bare(jid);
    if(hash_get(xmpp->roster, bare_jid)){
        return 1;
    }
    return 0;
}

static void 
_handle_xmpp_presence(Xmpp *xmpp, Stanza *presence) 
{
    listNode *node;
    int changed = 0;
    char *from, *type = NULL;
    presence_callback callback;

    type = stanza_get_type(presence);
    from = stanza_get_attribute(presence, "from");

    //from self
    if(jid_bare_compare(xmpp->jid, from) == 0) {
        return;
    }
    
    if(!is_buddy(xmpp, from)) {
        logger_warning("ROSTER", "%s is not buddy", from);
        return;
    }

    if(!type || strcmp(type, "available") ==0 ||
        strcmp(type, "probe") == 0) { //available
        node = listSearchKey(xmpp->presences, from);
        if(!node) {
            logger_info("ROSTER", "%s is available", from);
            listAddNodeHead(xmpp->presences, zstrdup(from));
            changed = 1;
        }
    } else if(strcmp(type, "unavailable") == 0) {
        node = listSearchKey(xmpp->presences, from);
        if(node) {
            listDelNode(xmpp->presences, node);
            changed = 1;
        }
    } else {
        changed = 1;
    }
    
    if(changed) {
        /* callbacks */    
        listIter *iter = listGetIterator(xmpp->presence_callbacks, AL_START_HEAD);
        while((node = listNext(iter))) {
            callback = (presence_callback)node->value;
            callback(xmpp, presence);
        }
        listReleaseIterator(iter);
    }
}

static void 
_handle_xmpp_message(Xmpp *xmpp, Stanza *message) 
{
    char *from = stanza_get_attribute(message, "from");

    if(!is_buddy(xmpp, from)) {
        logger_warning("ROSTER", "%s is not buddy", from);
        return;
    }

    listNode *node;
    message_callback callback;
    listIter *iter = listGetIterator(xmpp->message_callbacks, AL_START_HEAD);
    while( (node = listNext(iter)) ) {
        callback = (message_callback)node->value;
        callback(xmpp, message);
    }
    listReleaseIterator(iter);
}

static void 
_handle_stream_features(Xmpp *xmpp, Stanza *stanza) 
{
    Stanza *mechanisms, *bind, *session, *starttls;
    mechanisms = stanza_get_child_by_name(stanza, "mechanisms");
    if(mechanisms) {
        _xmpp_stream_auth(xmpp, mechanisms);
        return;
    }
    starttls = stanza_get_child_by_name(stanza, "starttls");
    if(starttls) {
        _xmpp_stream_starttls(xmpp, starttls);
        return;
    }
    bind = stanza_get_child_by_name(stanza, "bind");
    if(bind) {
        _xmpp_stream_bind(xmpp, bind);
        return;
    }
    session = stanza_get_child_by_name(stanza, "session");
    if(session) {
        _xmpp_stream_session(xmpp);
        return;
    }
}

static void 
_handle_stream_errors(Xmpp *xmpp, Stanza *stanza)
{
    logger_error("XMPP", "stream error.");
    //exit(1);
}

static void 
_handle_auth_success(Xmpp *xmpp, Stanza *stanza) 
{
    xmpp_set_state(xmpp, XMPP_STREAM_SASL_AUTHED);
    xmpp_stream_open(xmpp);
}

static void 
_handle_auth_failure(Xmpp *xmpp, Stanza *stanza) 
{
    logger_error("SMARTA", "authentication failure.\n");
    logger_error("SMARTA", "smarta name or apikey is wrong.\n");
    logger_error("SMARTA", "smarta exit!\n");
    exit(1);
}

static void 
_handle_xmpp_iq(Xmpp *xmpp, Stanza *iq) 
{
    char *id, *xmlns;
    Stanza *query;
    iq_callback callback;
    
    id = stanza_get_id(iq);
    if(id) {
        callback = xmpp_get_iq_id_callback(xmpp, id);
        if(callback) callback(xmpp, iq);
        xmpp_remove_iq_id_callback(xmpp, id);
    }

    query = stanza_get_child_by_name(iq, "query");
    if(query) {
        xmlns = stanza_get_ns(query);
        if(xmlns) {
            callback = xmpp_get_iq_ns_callback(xmpp, xmlns);
            if(callback) callback(xmpp, iq);
        }
    }
}

static void 
_handle_stream_end(char *name, void * const userdata) 
{
    Xmpp *xmpp = (Xmpp *)userdata;
    //FIXME LATER
    logger_warning("xmpp", "RECV: </stream:stream>");
    _xmpp_stream_closed(xmpp);
}

static void 
_xmpp_stream_closed(Xmpp *xmpp) 
{
    //TODO: WHAT'S HERE    
    //how to handle this??
}

static void 
_xmpp_stream_starttls(Xmpp *xmpp, Stanza *tlsFeature) 
{
    Stanza *startTLS;
    startTLS = _make_starttls(xmpp);
    xmpp_set_state(xmpp, XMPP_STREAM_TLS_NEGOTIATING);
    xmpp_send_stanza(xmpp, startTLS);
    stanza_release(startTLS);
}

static Stanza *
_make_starttls(Xmpp *xmpp) 
{
    Stanza *starttls = stanza_tag("starttls");
    stanza_set_ns(starttls, XMPP_NS_TLS);
    return starttls;
}

static void 
_xmpp_stream_auth(Xmpp * const xmpp, Stanza *mechanisms) 
{
    char *str;
    Stanza *auth, *authdata;
    auth = _make_sasl_auth("PLAIN");

    str = sasl_plain(xmpp->jid, xmpp->pass);
    authdata = stanza_text(str);

    zfree(str);

    stanza_add_child(auth, authdata);
    stanza_release(authdata);

    xmpp_send_stanza(xmpp, auth);

    xmpp_set_state(xmpp, XMPP_STREAM_SASL_AUTHENTICATING);

    stanza_release(auth);
}

static Stanza *
_make_sasl_auth(const char *mechanism) 
{
    Stanza *auth = stanza_new();
	stanza_set_name(auth, "auth");
	stanza_set_ns(auth, XMPP_NS_SASL);
	stanza_set_attribute(auth, "mechanism", mechanism);
    return auth;
}

static void 
_xmpp_stream_bind(Xmpp *xmpp, Stanza *bind) 
{
    char *bind_id = "_xmpp_bind";
    Stanza *iq, *res, *text;

    //iq element
	iq = stanza_tag("iq");
	stanza_set_type(iq, "set");
	stanza_set_id(iq, bind_id);

    xmpp_add_iq_id_callback(xmpp, bind_id, _xmpp_stream_bind_callback);

    //bind element
	bind = stanza_copy(bind);

    //res element
    res = stanza_tag("resource");

    //res text
    text = stanza_text("smarta");

    stanza_add_child(res, text);
    stanza_add_child(bind, res);
	stanza_add_child(iq, bind);

	/* send bind request */
	xmpp_send_stanza(xmpp, iq);

    xmpp_set_state(xmpp, XMPP_STREAM_BINDING);

	stanza_release(text);
	stanza_release(res);
	stanza_release(bind);
	stanza_release(iq);
}

static void 
_xmpp_stream_bind_callback(Xmpp *xmpp, Stanza *iq) {
    xmpp_set_state(xmpp, XMPP_STREAM_BINDED);
    //TODO: parse iq to get bind jid?
    _xmpp_stream_session(xmpp);
}

static void 
_xmpp_stream_session(Xmpp *xmpp) 
{
    char *session_id = "_xmpp_session";
    Stanza *iq, *session;

    iq = stanza_new();

    stanza_set_name(iq, "iq");
    stanza_set_type(iq, "set");
    stanza_set_id(iq, session_id);

    session = stanza_new();
    stanza_set_name(session, "session");
    stanza_set_ns(session, XMPP_NS_SESSION);
    stanza_add_child(iq, session);
    stanza_release(session);

    xmpp_add_iq_id_callback(xmpp, session_id, _xmpp_stream_session_callback);
    xmpp_send_stanza(xmpp, iq);
    xmpp_set_state(xmpp, XMPP_STREAM_SESSION_NEGOTIATING);

    stanza_release(iq);
}

static void 
_xmpp_stream_session_callback(Xmpp *xmpp, Stanza *iq) 
{
    //not sent presence but roster, OK?
    _xmpp_stream_roster(xmpp);
}

static void 
_xmpp_stream_roster(Xmpp *xmpp) 
{

    char *iq_id = "roster1";
    Stanza *iq, *query;

	/* create iq stanza for request */
	iq = stanza_tag("iq");
	stanza_set_type(iq, "get");
	stanza_set_id(iq, iq_id);

	query = stanza_tag("query");
	stanza_set_ns(query, XMPP_NS_ROSTER);

	stanza_add_child(iq, query);
	stanza_release(query);

	/* set up reply handler */
	xmpp_add_iq_id_callback(xmpp, iq_id, _xmpp_stream_roster_callback);

	/* send out the stanza */
	xmpp_send_stanza(xmpp, iq);

	/* release the stanza */
	stanza_release(iq);
    
}

Message *
message_new(char *to , char *body)
{
	Message *m = zmalloc(sizeof(Message));
	m->to = to;
	m->thread = NULL;
	m->subject = NULL;
	m->body = body;
	return m;
}

void 
message_free(Message *m)
{
	zfree(m);
}

Buddy *
buddy_new() 
{
    Buddy *buddy =  zmalloc(sizeof(Buddy));
    buddy->name = NULL;
    buddy->jid = NULL;
    return buddy;
}
    
void 
buddy_release(void *p) 
{
    Buddy *buddy = (Buddy *)p;
    if(buddy->name) zfree(buddy->name);
    if(buddy->jid) zfree(buddy->jid);
    zfree(buddy);
}

static void 
_add_buddies_to_roster(Xmpp *xmpp, Stanza *stanza) 
{
    Buddy *buddy;
    char *jid, *name, *type, *sub;
    Stanza *query, *item;
    type = stanza_get_type(stanza);

    if (strcmp(type, "error") == 0) {
        logger_error("XMPP", "roster query failed.");
        return;
    }

	query = stanza_get_child_by_name(stanza, "query");
	for (item = stanza_get_children(query);
        item; item = stanza_get_next(item)) {
        buddy = buddy_new();
        name = stanza_get_attribute(item, "name");
        if(name) {
            buddy->name = zstrdup(name);
        }
        jid = stanza_get_attribute(item, "jid");
        buddy->jid = zstrdup(jid);
        sub = stanza_get_attribute(item, "subscription");
        if(strcmp(sub, "both") == 0) {
            buddy->sub = SUB_BOTH;
        } else if(strcmp(sub, "to") == 0) {
            buddy->sub = SUB_TO; 
        } else if(strcmp(sub, "from") == 0) { 
            buddy->sub = SUB_FROM; 
        }
        hash_add(xmpp->roster, buddy->jid, buddy);
    }
}

static void 
_xmpp_stream_roster_callback(Xmpp *xmpp, Stanza *stanza) 
{
    Stanza *presence, *status, *text, *x, *photo;

    _add_buddies_to_roster(xmpp, stanza);

    xmpp_set_state(xmpp, XMPP_STREAM_ESTABLISHED),

    presence = stanza_tag("presence");

    status = stanza_tag("status");
    text = stanza_text("Online");
    stanza_add_child(status, text);

    stanza_add_child(presence, status);
	
	x = stanza_tag("x");
	stanza_set_ns(x, "vcard-temp:x:update");
	photo = stanza_tag("photo");
	text = stanza_text(OSNAME); //FIXME:
	stanza_add_child(photo, text);
	stanza_add_child(x, photo);

	stanza_add_child(presence, x);

    xmpp_send_stanza(xmpp, presence);
    stanza_release(presence);
}

static void 
_xmpp_heartbeat_handler(Xmpp *xmpp, XmppStreamState state)
{
    if(state == XMPP_STREAM_DISCONNECTED) {

        if(xmpp->heartbeat) aeDeleteTimeEvent(xmpp->el, xmpp->heartbeat);

        if(xmpp->heartbeat_timeout) aeDeleteTimeEvent(xmpp->el, xmpp->heartbeat_timeout);

    } else if(state == XMPP_STREAM_ESTABLISHED) {
		//heartbeat	
        if(xmpp->heartbeat)  aeDeleteTimeEvent(xmpp->el, xmpp->heartbeat);

        if(xmpp->heartbeat_timeout) aeDeleteTimeEvent(xmpp->el, xmpp->heartbeat_timeout);

        xmpp->heartbeat = aeCreateTimeEvent(xmpp->el, HEARTBEAT, xmpp_heartbeat, xmpp, NULL);
    } else {
        //IGNORE
    }

}

static int 
xmpp_heartbeat(aeEventLoop *el, long long id, void *clientData)
{
    char *ping_id;
    Xmpp *xmpp = (Xmpp *)clientData;

    ping_id = xmpp_send_ping(xmpp);

    xmpp_add_iq_id_callback(xmpp, ping_id, xmpp_heartbeat_callback);

    xmpp->heartbeat_timeout = aeCreateTimeEvent(el, 
        HEARTBEAT_TIMEOUT, xmpp_heartbeat_timeout, xmpp, NULL);

    sdsfree(ping_id);

    return HEARTBEAT;
}

static int 
xmpp_heartbeat_timeout(aeEventLoop *el, long long id, void *clientData)
{
    Xmpp *xmpp = (Xmpp *)clientData;
    long timeout = (random() % 180) * 1000;
    logger_info("XMPP", "heartbeat timeout.");
	if(xmpp->state == XMPP_STREAM_ESTABLISHED) { //confirm established?
		xmpp_disconnect(xmpp);
		logger_info("XMPP", "reconnect after %d seconds", timeout/1000);
		aeCreateTimeEvent(el, timeout, xmpp_reconnect, xmpp, NULL);
	}
    return AE_NOMORE;
}

static void 
xmpp_heartbeat_callback(Xmpp *xmpp, Stanza *stanza)
{
    logger_debug("XMPP", "pong received");
    if(xmpp->heartbeat_timeout != 0) {
        aeDeleteTimeEvent(xmpp->el, xmpp->heartbeat_timeout);
    }
} 

static void 
_remove_callback_from_list(list *callbacks, void *callback) 
{
    listNode *node = listSearchKey(callbacks, callback); 
    if(!node) {
        logger_error("xmpp", "try to a remove a callback that not exists.");
        return;
    }
    listDelNode(callbacks, node);
}

static int 
strequal(const char* s1, const char *s2) 
{
    return !strcmp(s1, s2);
}

static int 
strmatch(void *s1, void *s2) 
{
    if(strcmp(s1, s2) == 0) {
        return 1;
    } else {
        return 0;
    }
}

