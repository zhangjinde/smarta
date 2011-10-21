
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "anet.h"
#include "xmpp.h"
#include "stanza.h"
#include "util.h"

static void _on_stream_start(
    char *name, char **attrs, 
    void * const userdata);

static void _on_stream_stanza(
    XmppStanza *stanza,
    void * const userdata);

static void _on_stream_end(
    char *name,
    void * const userdata);

static void _log_open_tag(char **attrs);

static char *_get_stream_attribute(char **attrs, char *name);

XmppStream *xmpp_stream_new(int fd) {
    XmppStream *stream = NULL;
    stream = malloc(sizeof(XmppStream));

    stream->fd = fd;
    stream->state = XMPP_STREAM_CONNECTING;
    stream->parser = parser_new(_on_stream_start,
          _on_stream_end,
          _on_stream_stanza,
          stream);

    return stream;
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

static void _on_stream_start(char *name, char **attrs, 
    void * const userdata) {

    char *id;
    XmppStream *stream = (XmppStream *)userdata;

    if (strcmp(name, "stream:stream") != 0) {
        printf("name = %s\n", name);
        xmpp_log(LOG_ERROR, "conn: Server did not open valid stream.");
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

static void _on_stream_end(char *name,
                               void * const userdata) {
    //XmppStream *stream = (XmppStream *)userdata;

    /* stream is over */
    xmpp_log(LOG_DEBUG, "xmpp: RECV: </stream:stream>");
    //conn_disconnect_clean(conn);
}

static void _on_stream_stanza(XmppStanza *stanza,
                                  void * const userdata) {
    //XmppStream *stream = (XmppStream *)userdata;
    char *buf;
    size_t len;

    if (XmppStanzao_text(stanza, &buf, &len) == 0) {
        printf("RECV: %s\n", buf);
        xmpp_log(LOG_DEBUG, "xmpp: RECV: %s", buf);
        free(buf);
    }

    //handler_fire_stanza(conn, stanza);
}

void xmpp_send_raw_string(XmppStream *stream, char *fmt, ...) {
    va_list ap;
    size_t len;
    char buf[1024]; /* small buffer for common case */
    char *bigbuf;

    va_start(ap, fmt);
    len = xmpp_vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);

    if (len >= 1024) {
	/* we need more space for this data, so we allocate a big 
	 * enough buffer and print to that */
	len++; /* account for trailing \0 */
	bigbuf = malloc(len);
	if (!bigbuf) {
	    xmpp_log(LOG_DEBUG, "xmpp: Could not allocate memory for send_raw_string");
	    return;
	}
	va_start(ap, fmt);
	xmpp_vsnprintf(bigbuf, len, fmt, ap);
	va_end(ap);

	xmpp_log(LOG_DEBUG, "conn: SENT: %s", bigbuf);

	/* len - 1 so we don't send trailing \0 */
	xmpp_send_raw(stream, bigbuf, len - 1);

	free(bigbuf);
    } else {
	xmpp_log(LOG_DEBUG, "conn: SENT: %s", buf);

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

	if ((ret = XmppStanzao_text(stanza, &buf, &len)) == 0) {
	    xmpp_send_raw(stream, buf, len);
	    xmpp_log(LOG_DEBUG, "conn: SENT: %s", buf);
	    free(buf);
	}
}

static void _log_open_tag(char **attrs) {
    char buf[4096];
    size_t len, pos;
    int i;
    
    if (!attrs) return;

    pos = 0;
    len = xmpp_snprintf(buf, 4096, "<stream:stream");
    if (len < 0) return;
    
    pos += len;
    
    for (i = 0; attrs[i]; i += 2) {
        len = xmpp_snprintf(&buf[pos], 4096 - pos, " %s='%s'",
                            attrs[i], attrs[i+1]);
        if (len < 0) return;
        pos += len;
    }

    len = xmpp_snprintf(&buf[pos], 4096 - pos, ">");
    if (len < 0) return;

    xmpp_log(LOG_DEBUG, "xmpp: RECV: %s", buf);
}

static char *_get_stream_attribute(char **attrs, char *name) {
    int i;

    if (!attrs) return NULL;

    for (i = 0; attrs[i]; i += 2)
        if (strcmp(name, attrs[i]) == 0)
            return attrs[i+1];

    return NULL;
}
