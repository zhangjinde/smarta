#ifndef __STANZA_H
#define __STANZA_H

#include "hash.h"

typedef enum {
    XMPP_STANZA_UNKNOWN = -1,
    XMPP_STANZA_TAG,
    XMPP_STANZA_TEXT,
    XMPP_STANZA_CDATA,
} XmppStanzaType;

typedef struct _XmppStanza {
    int ref;

    XmppStanzaType type;
    
    struct _XmppStanza *prev;
    struct _XmppStanza *next;
    struct _XmppStanza *children;
    struct _XmppStanza *parent;

    char *data;

    Hash *attributes;
} XmppStanza;

/*
**create a blank stanza
*/
XmppStanza *xmpp_stanza_new();


/*
**create a tag stanza
*/
XmppStanza *xmpp_stanza_tag(const char *name);
/*
** create a text stanza
*/
XmppStanza *xmpp_stanza_text(const char *data);

/*
** create a cdata stanza
*/
XmppStanza *xmpp_stanza_cdata(const char *data);

/** clone a stanza */
XmppStanza *xmpp_stanza_clone(XmppStanza * stanza);

/** copies a stanza and all children */
XmppStanza *xmpp_stanza_copy(XmppStanza * stanza);

/** free a stanza object and it's contents */
int xmpp_stanza_release(XmppStanza * stanza);

int xmpp_stanza_is_text(XmppStanza * stanza);

int xmpp_stanza_is_tag(XmppStanza * stanza);

/** marshall a stanza into text for transmission or display **/
int xmpp_stanza_to_text(XmppStanza *stanza, 
    char ** buf, size_t * buflen);

int xmpp_stanza_get_attributes(XmppStanza * const stanza,
    const char **attr, int attrlen);

XmppStanza *xmpp_stanza_get_children(XmppStanza * stanza);
XmppStanza *xmpp_stanza_get_child_by_name(XmppStanza * stanza, 
					     char * name);
XmppStanza *xmpp_stanza_get_child_by_ns(XmppStanza * stanza,
					   char * ns);
XmppStanza *xmpp_stanza_get_next(XmppStanza * stanza);
char *xmpp_stanza_get_attribute(XmppStanza * stanza,
				const char * name);

char *xmpp_attrs_get_value(char **attrs, char *name);

char * xmpp_stanza_get_ns(XmppStanza * stanza);
/* concatenate all child text nodes.  this function
 * returns a string that must be freed by the caller */

char *xmpp_stanza_get_text(XmppStanza * stanza);
char *xmpp_stanza_get_text_ptr(XmppStanza * stanza);
char *xmpp_stanza_get_name(XmppStanza * stanza);

int xmpp_stanza_add_child(XmppStanza *stanza, XmppStanza *child);
int xmpp_stanza_set_ns(XmppStanza * stanza, char * ns);
/* set_attribute adds/replaces attributes */
int xmpp_stanza_set_attribute(XmppStanza * stanza, 
			      const char * key,
			      const char * value);
int xmpp_stanza_set_name(XmppStanza *stanza,
			 const char * name);

int xmpp_stanza_set_text(XmppStanza *stanza,
			 char * text);

int xmpp_stanza_set_text_with_size(XmppStanza *stanza,
				   const char *text, 
				   size_t size);

/* common stanza helpers */
char *xmpp_stanza_get_type(XmppStanza * stanza);
char *xmpp_stanza_get_id(XmppStanza * stanza);
int xmpp_stanza_set_id(XmppStanza * stanza, 
		       char * id);
int xmpp_stanza_set_type(XmppStanza * stanza, 
			 char * type);

#endif /* _SMARTA_STANZA_H__ */
