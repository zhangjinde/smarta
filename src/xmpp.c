
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "jid.h"
#include "anet.h"
#include "sasl.h"
#include "xmpp.h"
#include "stanza.h"
#include "logger.h"
#include "zmalloc.h"

static void _xmpp_stream_starttls(XmppStream *stream, XmppStanza *tlsFeature);

static XmppStanza *_make_starttls(XmppStream *stream);

static void _xmpp_stream_auth(XmppStream *const stream, XmppStanza *mechanisms);

static XmppStanza *_make_sasl_auth(const char *mechanism);

static void _xmpp_stream_bind(XmppStream *stream, XmppStanza *bind); 

static void _xmpp_stream_bind_callback(XmppStream *stream, XmppStanza *iq); 

static void _xmpp_stream_session_callback(XmppStream *stream, XmppStanza *iq);

static void _xmpp_stream_session(XmppStream *stream);

static void _xmpp_stream_closed(XmppStream *stream);

static void _handle_stream_start(char *name, char **attrs, void *userdata);

static void _handle_stream_stanza( XmppStanza *stanza, void *userdata);

static void _handle_stream_features(XmppStream *stream, XmppStanza *stanza);

static void _handle_stream_errors(XmppStream *stream, XmppStanza *stanza);

static void _handle_xmpp_iq(XmppStream *stream, XmppStanza *iq); 

static void _handle_xmpp_message(XmppStream *stream, XmppStanza *message);

static void _handle_auth_success(XmppStream *stream, XmppStanza *stanza);

static void _handle_auth_failure(XmppStream *stream, XmppStanza *stanza); 

static void _handle_xmpp_presence(XmppStream *stream, XmppStanza *presence); 

static void _handle_stream_end(char *name, void *userdata);

static void _remove_callback_from_list(list *callbacks, void *callback);

static int strequal(const char* s1, const char *s2); 

XmppStream *xmpp_stream_new(int fd) 
{
    XmppStream *stream = NULL;
    stream = zmalloc(sizeof(XmppStream));

    stream->fd = fd;

    stream->jid = NULL;

    stream->domain = NULL;

    stream->stream_id = NULL;

    stream->state = XMPP_STREAM_CONNECTING;

    stream->conn_callbacks = listCreate();
    
    stream->message_callbacks = listCreate();

    stream->presence_callbacks = listCreate();

    stream->iq_ns_callbacks = hash_new(8, NULL);

    stream->iq_id_callbacks = hash_new(8, NULL);

    stream->prepare_reset = 0;
    stream->parser = parser_new(_handle_stream_start,
          _handle_stream_end,
          _handle_stream_stanza,
          stream);

    return stream;
}

void xmpp_stream_set_state(XmppStream *stream, int state)  
{
    listNode *node;
    listIter *iter;
    conn_callback callback;
    if(stream->state != state) {
        stream->state = state;
        iter = listGetIterator(stream->conn_callbacks, AL_START_HEAD);
        while((node = listNext(iter))) {
            callback = (conn_callback)node->value;
            callback(stream, state);
        }
        listReleaseIterator(iter);
    }
}

char *xmpp_stream_get_jid(XmppStream *stream) 
{
    return stream->jid;
}

void xmpp_stream_set_jid(XmppStream *stream, const char *jid) 
{
    stream->jid = zstrdup(jid);
    stream->domain = xmpp_jid_domain(jid);
}

char *xmpp_stream_get_pass(XmppStream *stream) {
    return stream->pass;
}

void xmpp_stream_set_pass(XmppStream *stream, const char *pass) {
    stream->pass = zstrdup(pass);
}

void xmpp_add_conn_callback(XmppStream *stream, conn_callback callback) 
{
    listAddNodeHead(stream->conn_callbacks, callback);
}

void xmpp_remove_conn_callback(XmppStream *stream, conn_callback callback) 
{
    _remove_callback_from_list(stream->conn_callbacks, callback);
}

void xmpp_add_message_callback(XmppStream *stream, message_callback callback){
    listAddNodeHead(stream->message_callbacks, callback);
}

void xmpp_remove_message_callback(XmppStream *stream, message_callback callback) 
{
    _remove_callback_from_list(stream->message_callbacks, callback);
}

void xmpp_add_presence_callback(XmppStream *stream, presence_callback callback) 
{
    listAddNodeHead(stream->presence_callbacks, callback);
}

void xmpp_remove_presence_callback(XmppStream *stream, presence_callback callback) 
{
    _remove_callback_from_list(stream->presence_callbacks, callback);
}

iq_callback xmpp_get_iq_ns_callback(XmppStream *stream, char *ns) 
{
    return hash_get(stream->iq_ns_callbacks, ns);
}

void xmpp_add_iq_ns_callback(XmppStream *stream, char *iq_ns, iq_callback callback) 
{
    hash_add(stream->iq_ns_callbacks, iq_ns, callback);
}

void xmpp_remove_iq_id_callback(XmppStream *stream, char *iq_id) 
{
    hash_drop(stream->iq_id_callbacks, iq_id);
}

iq_callback xmpp_get_iq_id_callback(XmppStream *stream, char *id) 
{
    return hash_get(stream->iq_id_callbacks, id);
}

void xmpp_add_iq_id_callback(XmppStream *stream, char *iq_id, iq_callback callback) 
{
    hash_add(stream->iq_id_callbacks, iq_id, callback);
}

void xmpp_remove_iq_ns_callback(XmppStream *stream, char *iq_ns) 
{
    hash_drop(stream->iq_id_callbacks, iq_ns);
}

int xmpp_stream_open(XmppStream *stream) 
{

    stream->prepare_reset = 1;
    
    xmpp_send_format(stream, 
			 "<?xml version=\"1.0\"?>"			\
			 "<stream:stream to=\"%s\" "			\
			 "xml:lang=\"%s\" "				\
			 "version=\"1.0\" "				\
			 "xmlns=\"%s\" "				\
			 "xmlns:stream=\"%s\">", 
			 stream->domain,
			 "en",
			 XMPP_NS_CLIENT,
			 XMPP_NS_STREAMS);

    return 0;

}

void xmpp_send_format(XmppStream *stream, char *fmt, ...) 
{
    va_list ap;
    size_t len;
    char buf[4096]; /* small buffer for common case */

    va_start(ap, fmt);
    len = vsnprintf(buf, 4096, fmt, ap);
    va_end(ap);

    if (len >= 4096) {
        logger_error("xmpp", "cannot send the packet, len:%d is over 4096", len);
        return;
    }

	xmpp_send_string(stream, buf, len);
}

void xmpp_send_string(XmppStream *stream, char *data, size_t len)
{

    if (stream->state == XMPP_STREAM_DISCONNECTED) {
        return;
    }

	logger_debug("XMPP", "SENT: %s", data);

    anetWrite(stream->fd, data, len);
}

void xmpp_send_stanza(XmppStream *stream, XmppStanza *stanza) 
{
    int ret;
    char *buf;
    size_t len;

	if ((ret = xmpp_stanza_to_text(stanza, &buf, &len)) == 0) {
	    xmpp_send_string(stream, buf, len);
	    zfree(buf);
	}
}

int xmpp_stream_feed(XmppStream *stream, char *buffer, int len) 
{
    return parser_feed(stream->parser, buffer, len);
}

static void _handle_stream_start(char *name, char **attrs, void *userdata) 
{
    char *id;

    XmppStream *stream = (XmppStream *)userdata;

    if (strcmp(name, "stream:stream") != 0) {
        logger_fatal("xmpp", "server did not open valid stream.");
        //TODO:fix me later
        exit(1);
    }
    if (stream->stream_id) {
        zfree(stream->stream_id);
    }
    id = xmpp_attrs_get_value(attrs, "id");
    if (id) {
        stream->stream_id = zstrdup(id);
    }
}

static void _handle_stream_stanza(XmppStanza * const stanza, void * const userdata) 
{
    char *buf;
    size_t len;
    char *xmlns, *name;
    XmppStream *stream = (XmppStream *)userdata;

    if (xmpp_stanza_to_text(stanza, &buf, &len) == 0) {
        logger_debug("XMPP", "RECV: %s", buf);
        zfree(buf);
    }
    
    xmlns = xmpp_stanza_get_ns(stanza);
    name = xmpp_stanza_get_name(stanza);

    logger_debug("XMPP", "xmlns: %s, name: %s", xmlns, name);

    if(strequal(name, "iq")) {
        _handle_xmpp_iq(stream, stanza);
    } else if(strequal(name, "presence")) {
        _handle_xmpp_presence(stream, stanza);
    } else if(strequal(name, "message")) {
        _handle_xmpp_message(stream, stanza);
    } else if(strequal(name, "stream:features")) {
            _handle_stream_features(stream, stanza);
    } else if(strequal(name, "stream:error")) {
            _handle_stream_errors(stream, stanza);
    } else if(strequal(xmlns, XMPP_NS_SASL)) {
        if(stream->state != XMPP_STREAM_SASL_AUTHENTICATING) {
            logger_error("XMPP", "Ignoring suprios SASL stanza %s", name);
        } else {
			if (strequal(name, "challenge")) {
                logger_error("XMPP", "Challenge is not supported %s", name);
				//handle_auth_challenge(stream, stnaza);
            } else if (strequal(name, "success")) {
				_handle_auth_success(stream, stanza);
            } else if (strequal(name, "failure")) {
				_handle_auth_failure(stream, stanza);
            }
        }
    } else if(strequal(xmlns, XMPP_NS_TLS)) {
        if(stream->state != XMPP_STREAM_TLS_NEGOTIATING) {
            logger_error("XMPP", "Ignoreing spurios %s", name);
        } else {
            if(strequal(name, "proceed")) {
                //FIXME LATER   
                //tls_init
            }
        }
    } else {
        logger_error("XMPP", "received unknown stanza: %s", name);
    }

}

static void _handle_xmpp_presence(XmppStream *stream, XmppStanza *presence) 
{
    listNode *node;
    presence_callback callback;
    listIter *iter = listGetIterator(stream->presence_callbacks, AL_START_HEAD);
    while((node = listNext(iter))) {
        callback = (presence_callback)node->value;
        callback(stream, presence);
    }
    listReleaseIterator(iter);
}

static void _handle_xmpp_message(XmppStream *stream, XmppStanza *message) 
{
    listNode *node;
    message_callback callback;
    listIter *iter = listGetIterator(stream->message_callbacks, AL_START_HEAD);
    while( (node = listNext(iter)) ) {
        callback = (message_callback)node->value;
        callback(stream, message);
    }
    listReleaseIterator(iter);
}

static void _handle_stream_features(XmppStream *stream, XmppStanza *stanza) 
{
    XmppStanza *mechanisms, *bind, *session, *starttls;
    mechanisms = xmpp_stanza_get_child_by_name(stanza, "mechanisms");
    if(mechanisms) {
        _xmpp_stream_auth(stream, mechanisms);
        return;
    }
    starttls = xmpp_stanza_get_child_by_name(stanza, "starttls");
    if(starttls) {
        //TODO:FIXME LATER
        _xmpp_stream_starttls(stream, starttls);
        return;
    }
    bind = xmpp_stanza_get_child_by_name(stanza, "bind");
    if(bind) {
        _xmpp_stream_bind(stream, bind);
        return;
    }
    session = xmpp_stanza_get_child_by_name(stanza, "session");
    if(session) {
        _xmpp_stream_session(stream);
        return;
    }
}

static void _handle_stream_errors(XmppStream *stream, XmppStanza *stanza)
{
    logger_error("XMPP", "stream error, exit!");
    exit(1);
}

static void _handle_auth_success(XmppStream *stream, XmppStanza *stanza) 
{
    xmpp_stream_set_state(stream, XMPP_STREAM_SASL_AUTHED);
    xmpp_stream_open(stream);
}

static void _handle_auth_failure(XmppStream *stream, XmppStanza *stanza) 
{
    logger_error("XMPP", "sasl authentication failure");
    exit(1);
}

static void _handle_xmpp_iq(XmppStream *stream, XmppStanza *iq) 
{
    char *id, *xmlns;
    iq_callback callback;
    
    id = xmpp_stanza_get_id(iq);
    if(id) {
        callback = xmpp_get_iq_id_callback(stream, id);
        if(callback) callback(stream, iq);
    }
    xmlns = xmpp_stanza_get_ns(iq);
    if(xmlns) {
        callback = xmpp_get_iq_ns_callback(stream, id);
        if(callback) callback(stream, iq);
    }
}

static void _handle_stream_end(char *name, void * const userdata) 
{
    XmppStream *stream = (XmppStream *)userdata;
    //FIXME LATER
    logger_info("xmpp", "RECV: </stream:stream>");
    _xmpp_stream_closed(stream);
}

static void _xmpp_stream_closed(XmppStream *stream) 
{
    //TODO: WHAT'S HERE    
    //how to handle this??
}

static void _xmpp_stream_starttls(XmppStream *stream, XmppStanza *tlsFeature) 
{
    XmppStanza *startTLS;
    startTLS = _make_starttls(stream);
    xmpp_stream_set_state(stream, XMPP_STREAM_TLS_NEGOTIATING);
    xmpp_send_stanza(stream, startTLS);
    xmpp_stanza_release(startTLS);
}

static XmppStanza *_make_starttls(XmppStream *stream) 
{
    XmppStanza *starttls = xmpp_stanza_newtag("starttls");
    xmpp_stanza_set_ns(starttls, XMPP_NS_TLS);
    return starttls;
}

static void _xmpp_stream_auth(XmppStream * const stream, XmppStanza *mechanisms) 
{
    char *str;
    XmppStanza *auth, *authdata;
    auth = _make_sasl_auth("PLAIN");

    authdata = xmpp_stanza_new();

    str = sasl_plain(stream->jid, stream->pass);
    xmpp_stanza_set_text(authdata, str);
    zfree(str);

    xmpp_stanza_add_child(auth, authdata);
    xmpp_stanza_release(authdata);

    xmpp_send_stanza(stream, auth);

    xmpp_stream_set_state(stream, XMPP_STREAM_SASL_AUTHENTICATING);

    xmpp_stanza_release(auth);
}

static XmppStanza *_make_sasl_auth(const char *mechanism) 
{
    XmppStanza *auth = xmpp_stanza_new();
	xmpp_stanza_set_name(auth, "auth");
	xmpp_stanza_set_ns(auth, XMPP_NS_SASL);
	xmpp_stanza_set_attribute(auth, "mechanism", mechanism);
    return auth;
}

static void _xmpp_stream_bind(XmppStream *stream, XmppStanza *bind) 
{
    char *bind_id = "_xmpp_bind";
    XmppStanza *iq, *res, *text;

    //iq element
	iq = xmpp_stanza_newtag("iq");
	xmpp_stanza_set_type(iq, "set");
	xmpp_stanza_set_id(iq, bind_id);

    xmpp_add_iq_id_callback(stream, bind_id, _xmpp_stream_bind_callback);

    //bind element
	bind = xmpp_stanza_copy(bind);

    //res element
    res = xmpp_stanza_newtag("resource");

    //res text
    text = xmpp_stanza_new();
    xmpp_stanza_set_text(text, "smarta");

    xmpp_stanza_add_child(res, text);
    xmpp_stanza_add_child(bind, res);
	xmpp_stanza_add_child(iq, bind);

	/* send bind request */
	xmpp_send_stanza(stream, iq);

    xmpp_stream_set_state(stream, XMPP_STREAM_BINDING);

	xmpp_stanza_release(text);
	xmpp_stanza_release(res);
	xmpp_stanza_release(bind);
	xmpp_stanza_release(iq);
}

static void _xmpp_stream_bind_callback(XmppStream *stream, XmppStanza *iq) {
    xmpp_stream_set_state(stream, XMPP_STREAM_BINDED);
    //TODO: parse iq to get bind jid?
    _xmpp_stream_session(stream);
}

static void _xmpp_stream_session(XmppStream *stream) 
{
    char *session_id = "_xmpp_session";
    XmppStanza *iq, *session;

    iq = xmpp_stanza_new();

    xmpp_stanza_set_name(iq, "iq");
    xmpp_stanza_set_type(iq, "set");
    xmpp_stanza_set_id(iq, session_id);

    session = xmpp_stanza_new();
    xmpp_stanza_set_name(session, "session");
    xmpp_stanza_set_ns(session, XMPP_NS_SESSION);
    xmpp_stanza_add_child(iq, session);
    xmpp_stanza_release(session);

    xmpp_add_iq_id_callback(stream, session_id, _xmpp_stream_session_callback);
    xmpp_send_stanza(stream, iq);
    xmpp_stream_set_state(stream, XMPP_STREAM_SESSION_NEGOTIATING);

    xmpp_stanza_release(iq);
}

static void _xmpp_stream_session_callback(XmppStream *stream, XmppStanza *iq) 
{
    XmppStanza *presence;
    xmpp_stream_set_state(stream, XMPP_STREAM_ESTABLISHED),
    presence = xmpp_stanza_new();
    xmpp_stanza_set_name(presence, "presence");
    xmpp_send_stanza(stream, presence);
}

static void _remove_callback_from_list(list *callbacks, void *callback) 
{
    listNode *node = listSearchKey(callbacks, callback); 
    if(!node) {
        logger_error("xmpp", "try to a remove a callback that not exists.");
        return;
    }
    listDelNode(callbacks, node);
}

static int strequal(const char* s1, const char *s2) 
{
    return !strcmp(s1, s2);
}
