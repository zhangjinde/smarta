/* 
** parser structures and functions
*/

#ifndef __PARSER_H
#define __PARSER_H

#include "expat.h"

#include "stanza.h"

typedef struct _Parser Parser;

typedef void (*parser_start_callback)(
    char *name,
    char **attrs,
    void * const userdata);

typedef void (*parser_end_callback)(
    char *name,
    void * const userdata);

typedef void (*parser_stanza_callback)(
    Stanza * const stanza,
    void * const userdata);

struct _Parser {
    XML_Parser expat;
    parser_start_callback startcb;
    parser_end_callback endcb;
    parser_stanza_callback stanzacb;
    void *userdata;
    int depth;
    Stanza *stanza;
};

Parser *parser_new(parser_start_callback startcb,
    parser_end_callback endcb,
    parser_stanza_callback stanzacb,
    void *userdata);

int parser_reset(Parser *parser);

int parser_feed(Parser *parser, char *chunk, int len);

void parser_free(Parser *parser);

#endif /* __PARSER_H */

