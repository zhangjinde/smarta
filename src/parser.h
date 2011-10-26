/* parser.h
** strophe XMPP client library -- parser structures and functions
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
 *  Internally used functions and structures.
 */

#ifndef __PARSER_H
#define __PARSER_H

#include <expat.h>
#include "stanza.h"

typedef void (*parser_start_callback)(char *name,
                                      char **attrs,
                                      void * const userdata);
typedef void (*parser_end_callback)(char *name, void * const userdata);

typedef void (*parser_stanza_callback)(
    XmppStanza * const stanza, void * const userdata);

typedef struct _Parser {
    XML_Parser expat;
    parser_start_callback startcb;
    parser_end_callback endcb;
    parser_stanza_callback stanzacb;
    void *userdata;
    int depth;
    XmppStanza *stanza;
} Parser;

Parser *parser_new(parser_start_callback startcb,
                     parser_end_callback endcb,
                     parser_stanza_callback stanzacb,
                     void *userdata);
void parser_free(Parser *parser);
int parser_reset(Parser *parser);
int parser_feed(Parser *parser, char *chunk, int len);

#endif /* __SMARTA_PARSER_H__ */
