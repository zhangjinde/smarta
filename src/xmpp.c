
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "anet.h"
#include "sasl.h"
#include "xmpp.h"
#include "stanza.h"
#include "util.h"

static void xmpp_stream_starttls(XmppStream *stream);

static XmppStanza *_make_starttls(XmppStream *stream);

static void xmpp_stream_auth(XmppStream *const stream, XmppStanza *mechanisms);

static XmppStanza *_make_sasl_auth(const char *mechanism);

static void xmpp_stream_bind(XmppStream *stream, XmppStanza *bind); 

static void xmpp_stream_session(XmppStream *stream);

static void _handle_stream_start(
    char *name, char **attrs, 
    void * const userdata);

static void _handle_stream_stanza(
    XmppStanza * const stanza,
    void * const userdata);

static void _handle_stream_end(
    char *name,
    void * const userdata);

static void _log_open_tag(char **attrs);

static char *_get_stream_attribute(char **attrs, char *name);

XmppStream *xmpp_stream_new(int fd) {
    XmppStream *stream = NULL;
    stream = malloc(sizeof(XmppStream));

    stream->fd = fd;
    stream->state = XMPP_STREAM_CONNECTING;
    stream->parser = parser_new(_handle_stream_start,
          _handle_stream_end,
          _handle_stream_stanza,
          stream);

    return stream;
}

char *xmpp_stream_get_jid(XmppStream *stream) {
    return stream->jid;
}

void xmpp_stream_set_jid(XmppStream *stream, const char *jid) {
    stream->jid = strdup(jid);
}

char *xmpp_stream_get_pass(XmppStream *stream) {
    return stream->pass;
}
void xmpp_stream_set_pass(XmppStream *stream, const char *pass) {
    stream->pass = strdup(pass);
}

int xmpp_stream_open(XmppStream *stream) {
    
    xmpp_send_raw_string(stream, 
			 "<?xml version=\"1.0\"?>"			\
			 "<stream:stream to=\"%s\" "			\
			 "xml:lang=\"%s\" "				\
			 "version=\"1.0\" "				\
			 "xmlns=\"%s\" "				\
			 "xmlns:stream=\"%s\">", 
			 "nodehub.cn",
			 "en",
			 XMPP_NS_CLIENT,
			 XMPP_NS_STREAMS);

    return 0;

}

int xmpp_stream_feed(XmppStream *stream, char *buffer, int len) {
    return parser_feed(stream->parser, buffer, len);
}

static void _handle_stream_start(char *name, char **attrs, 
    void * const userdata) {

    char *id;
    XmppStream *stream = (XmppStream *)userdata;

    if (strcmp(name, "stream:stream") != 0) {
        printf("name = %s\n", name);
        xmpp_log(LOG_ERROR, "STREAM: Server did not open valid stream.");
        //TODO:fix me
        //xmpp_conn_disconnect(stream->conn);
    } else {
        _log_open_tag(attrs);
        
        if (stream->stream_id) free(stream->stream_id);

        id = _get_stream_attribute(attrs, "id");
        if (id) {
            stream->stream_id = strdup(id);
        }
    }
}

static void _handle_stream_end(char *name, void * const userdata) {
    //XmppStream *stream = (XmppStream *)userdata;
    /* stream is over */
    xmpp_log(LOG_DEBUG, "XMPP RECV: </stream:stream>");
    //conn_disconnect_clean(conn);
}

static void _handle_stream_stanza(XmppStanza * const stanza, void * const userdata) {
    XmppStream *stream = (XmppStream *)userdata;
    char *buf;
    size_t len;
    char *ns, *name, *type;
    XmppStanza *mechanisms, *bind, *session;

    printf("before to_text: %d\n", stanza);

    if (xmpp_stanza_to_text(stanza, &buf, &len) == 0) {
        xmpp_log(LOG_DEBUG, "XMPP RECV: %s", buf);
        free(buf);
    }
    printf("after to_text: %d\n", stanza);
    
    ns = xmpp_stanza_get_ns(stanza);
    name = xmpp_stanza_get_name(stanza);
    type = xmpp_stanza_get_type(stanza);
    printf("ns: %s, name: %s\n", ns, name);
    xmpp_log(LOG_DEBUG, "ns: %s, name: %s\n", ns, name);
    if(strcmp(name, "stream:features") == 0) {
        mechanisms = xmpp_stanza_get_child_by_name(stanza, "mechanisms");
        if(mechanisms) {
            xmpp_stream_auth(stream, mechanisms);
            xmpp_log(LOG_DEBUG, "auth sent\n");
            stream->state = XMPP_STREAM_SASL_AUTHENTICATING;
            return;
        }
        bind = xmpp_stanza_get_child_by_name(stanza, "bind");
        if(bind) {
            //TODO: 
            xmpp_stream_bind(stream, bind);
            return;
        }
        session = xmpp_stanza_get_child_by_name(stanza, "session");
        if(session) {
            //TODO: send session
            xmpp_stream_session(stream);
            return;
        }
        
        return;
    } else if(strcmp(name, "proceed")) {
        //TODO: TLS PROCEED

    }else if(strcmp(name, "success") == 0) {
        xmpp_log(LOG_DEBUG, "sasl auth success\n");
        //reopen stream
        xmpp_stream_open(stream);
    }
    //handle features

    //handler_fire_stanza(conn, stanza);
}

void xmpp_send_raw_string(XmppStream *stream, char *fmt, ...) {
    va_list ap;
    size_t len;
    char buf[1024]; /* small buffer for common case */
    char *bigbuf;

    va_start(ap, fmt);
    len = vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);

    if (len >= 1024) {
	/* we need more space for this data, so we allocate a big 
	 * enough buffer and print to that */
	len++; /* account for trailing \0 */
	bigbuf = malloc(len);
	if (!bigbuf) {
	    xmpp_log(LOG_DEBUG, "XMPP: Could not allocate memory for send_raw_string");
	    return;
	}
	va_start(ap, fmt);
	vsnprintf(bigbuf, len, fmt, ap);
	va_end(ap);

	xmpp_log(LOG_DEBUG, "XMPP SENT: %s", bigbuf);

	/* len - 1 so we don't send trailing \0 */
	xmpp_send_raw(stream, bigbuf, len - 1);

	free(bigbuf);
    } else {
	xmpp_log(LOG_DEBUG, "XMPP SENT: %s", buf);

	xmpp_send_raw(stream, buf, len);
    }
}

void xmpp_send_raw(XmppStream *stream,
    char *data, size_t len) {

    if (stream->state == XMPP_STREAM_DISCONNECTED) return;

    anetWrite(stream->fd, data, len);
}

void xmpp_send(XmppStream *stream, XmppStanza *stanza) {
    char *buf;
    size_t len;
    int ret;

    if (stream->state == XMPP_STREAM_DISCONNECTED) return;

    printf("stanza pointer before sent:%d\n", stream->parser->stanza);
    
	if ((ret = xmpp_stanza_to_text(stanza, &buf, &len)) == 0) {
	    xmpp_send_raw(stream, buf, len);
	    xmpp_log(LOG_DEBUG, "XMPP SENT %d: %s", len, buf);
	    free(buf);
	}

    printf("stanza pointer after sent:%d\n", stream->parser->stanza);
}

static void _log_open_tag(char **attrs) {
    char buf[4096];
    size_t len, pos;
    int i;
    
    if (!attrs) return;

    pos = 0;
    len = snprintf(buf, 4096, "<stream:stream");
    if (len < 0) return;
    
    pos += len;
    
    for (i = 0; attrs[i]; i += 2) {
        len = snprintf(&buf[pos], 4096 - pos, " %s='%s'",
                            attrs[i], attrs[i+1]);
        if (len < 0) return;
        pos += len;
    }

    len = snprintf(&buf[pos], 4096 - pos, ">");
    if (len < 0) return;

    xmpp_log(LOG_DEBUG, "XMPP RECV: %s", buf);
}

static void xmpp_stream_starttls(XmppStream *stream) {
    XmppStanza *startTLS;
    startTLS = _make_starttls(stream);
    xmpp_send(stream, startTLS);
    xmpp_stanza_release(startTLS);
}

static XmppStanza *_make_starttls(XmppStream *stream) {
    XmppStanza *starttls;
    /* build start stanza */
    starttls = xmpp_stanza_new();
    if (starttls) {
        xmpp_stanza_set_name(starttls, "starttls");
        xmpp_stanza_set_ns(starttls, XMPP_NS_TLS);
    }
    return starttls;
}

static void xmpp_stream_auth(XmppStream * const stream, XmppStanza *mechanisms) {
    char *str;
    XmppStanza *auth, *authdata;
    auth = _make_sasl_auth("PLAIN");

    authdata = xmpp_stanza_new();

    str = sasl_plain(stream->jid, stream->pass);
    xmpp_stanza_set_text(authdata, str);
    free(str);

    xmpp_stanza_add_child(auth, authdata);
    xmpp_stanza_release(authdata);

    xmpp_send(stream, auth);

    xmpp_stanza_release(auth);
}

static XmppStanza *_make_sasl_auth(const char *mechanism) {
    XmppStanza *auth = xmpp_stanza_new();
	xmpp_stanza_set_name(auth, "auth");
	xmpp_stanza_set_ns(auth, XMPP_NS_SASL);
	xmpp_stanza_set_attribute(auth, "mechanism", mechanism);
    return auth;
}

static void xmpp_stream_bind(XmppStream *stream, XmppStanza *bind) {
    //FIXME: add timer
    XmppStanza *iq, *res, *text;

    //iq element
	iq = xmpp_stanza_new();
	xmpp_stanza_set_name(iq, "iq");
	xmpp_stanza_set_type(iq, "set");
	xmpp_stanza_set_id(iq, "_xmpp_bind1");

    //bind element
	bind = xmpp_stanza_copy(bind);

    //res element
    res = xmpp_stanza_new();
    xmpp_stanza_set_name(res, "resource");

    //res text
    text = xmpp_stanza_new();
    xmpp_stanza_set_text(text, "smarta");

    xmpp_stanza_add_child(res, text);
    xmpp_stanza_add_child(bind, res);
	xmpp_stanza_add_child(iq, bind);

	/* send bind request */
	xmpp_send(stream, iq);

	xmpp_stanza_release(text);
	xmpp_stanza_release(res);
	xmpp_stanza_release(bind);
	xmpp_stanza_release(iq);
}

static void xmpp_stream_session(XmppStream *stream) {
    XmppStanza *iq, *session;

    iq = xmpp_stanza_new();

    xmpp_stanza_set_name(iq, "iq");
    xmpp_stanza_set_type(iq, "set");
    xmpp_stanza_set_id(iq, "_xmpp_session1");

    session = xmpp_stanza_new();
    xmpp_stanza_set_name(session, "session");
    xmpp_stanza_set_ns(session, XMPP_NS_SESSION);

    xmpp_stanza_add_child(iq, session);

    xmpp_send(stream, iq);

    xmpp_stanza_release(session);
    xmpp_stanza_release(iq);
}

static char *_get_stream_attribute(char **attrs, char *name) {
    int i;

    if (!attrs) return NULL;

    for (i = 0; attrs[i]; i += 2)
        if (strcmp(name, attrs[i]) == 0)
            return attrs[i+1];

    return NULL;
}
