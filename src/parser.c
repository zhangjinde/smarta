/* parser.c
** strophe XMPP client library -- xml parser handlers and utility functions
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <expat.h>

#include "xmpp.h"
#include "parser.h"

static void _start_element(void *userdata,
    const XML_Char *name,
    const XML_Char **attrs);

static void _end_element(void *userdata,
    const XML_Char *name);

static void _characters(void *userdata,
    const XML_Char *s,
    int len);

Parser *parser_new(parser_start_callback startcb,
                   parser_end_callback endcb,
                   parser_stanza_callback stanzacb,
                   void *userdata) {
    Parser *parser;

    parser = malloc(sizeof(Parser));

    parser->expat = NULL;
    parser->startcb = startcb;
    parser->endcb = endcb;
    parser->stanzacb = stanzacb;
    parser->userdata = userdata;
    parser->depth = 0;
    parser->stanza = NULL;

    parser_reset(parser);

    return parser;
}

int parser_feed(Parser *parser, char *chunk, int len) {
    return XML_Parse(parser->expat, chunk, len, 0);
}

/* shuts down and restarts XML parser.  true on success */
int parser_reset(Parser *parser) {
    if (parser->expat) {
        XML_ParserFree(parser->expat);
    }

    if (parser->stanza) {
        xmpp_stanza_release(parser->stanza);
    }

    parser->expat = XML_ParserCreate(NULL);

    parser->depth = 0;
    parser->stanza = NULL;

    XML_SetUserData(parser->expat, parser);
    XML_SetElementHandler(parser->expat, _start_element, _end_element);
    XML_SetCharacterDataHandler(parser->expat, _characters);

    return 1;
}

/* free a parser */
void parser_free(Parser *parser) {
    if (parser->expat) {
        XML_ParserFree(parser->expat);
    }

    free(parser);
}


static void _set_attributes(XmppStanza *stanza, const XML_Char **attrs) {
    int i;

    if (!attrs) return;

    for (i = 0; attrs[i]; i += 2) {
        xmpp_stanza_set_attribute(stanza, attrs[i], attrs[i+1]);
    }
}

static void _start_element(void *userdata,
    const XML_Char *name,
    const XML_Char **attrs) {

    Parser *parser = (Parser *)userdata;
    XmppStanza *child;

    xmpp_log(LOG_DEBUG, "start_element: %s\n", name);

    if (parser->depth == 0) {
        /* notify the owner */
        if (parser->startcb) {
            parser->startcb((char *)name, (char **)attrs, parser->userdata);
        }
    } else {
        /* build stanzas at depth 1 */
        if (!parser->stanza && parser->depth != 1) {
            /* something terrible happened */
            /* FIXME: shutdown disconnect */
            xmpp_log(LOG_ERROR, "parser: oops, where did our stanza go?");
        } else if (!parser->stanza) {
            /* starting a new toplevel stanza */
            parser->stanza = xmpp_stanza_new();
            xmpp_stanza_set_name(parser->stanza, name);
            _set_attributes(parser->stanza, attrs);
        } else {
            /* starting a child of parser->stanza */
            child = xmpp_stanza_new();
            xmpp_stanza_set_name(child, name);
            _set_attributes(child, attrs);

            /* add child to parent */
            xmpp_stanza_add_child(parser->stanza, child);
            
            /* the child is owned by the toplevel stanza now */
            xmpp_stanza_release(child);

            /* make child the current stanza */
            parser->stanza = child;
        }
    }

    parser->depth++;
    
}

static void _end_element(void *userdata, const XML_Char *name) {

    Parser *parser = (Parser *)userdata;

    parser->depth--;

    xmpp_log(LOG_DEBUG, "end_element: %s, depth: %d\n", name, parser->depth);

    if (parser->depth == 0) {
        /* notify the owner */
        if (parser->endcb) {
            parser->endcb((char *)name, parser->userdata);
        }
    } else {
        if (parser->stanza->parent) {
            /* we're finishing a child stanza, so set current to the parent */
            parser->stanza = parser->stanza->parent;
        } else {
            if (parser->stanzacb) {
                parser->stanzacb(parser->stanza, parser->userdata);
            }
            if(parser->stanza == NULL) {
                xmpp_log(LOG_ERROR, "assert failure: stanza is null!\n");
            }
            xmpp_log(LOG_DEBUG, "before release parser stanza\n");
            xmpp_stanza_release(parser->stanza);
            parser->stanza = NULL;
            xmpp_log(LOG_DEBUG, "release parser stanza\n");
        }
    }
}

static void _characters(void *userdata, const XML_Char *s, int len) {
    Parser *parser = (Parser *)userdata;
    XmppStanza *stanza;

    if (parser->depth < 2) return;

    /* create and populate stanza */
    stanza = xmpp_stanza_new();
    xmpp_stanza_set_text_with_size(stanza, s, len);

    xmpp_stanza_add_child(parser->stanza, stanza);
    xmpp_stanza_release(stanza);
}


