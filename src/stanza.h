#ifndef _SMARTA_STANZA_H_
#define _SMARTA_STANZA_H_

#include "hash.h"

typedef struct _XmppStanza XmppStanza;

typedef enum {
    XMPP_STANZA_UNKNOWN,
    XMPP_STANZA_TEXT,
    XMPP_STANZA_TAG
} XmppStanzaType;

struct _XmppStanza {
    int ref;

    XmppStanzaType type;
    
    XmppStanza *prev;
    XmppStanza *next;
    XmppStanza *children;
    XmppStanza *parent;

    char *data;

    hash_t *attributes;
};

/** stanzas **/

/** allocate an initialize a blank stanza */
XmppStanza *xmpp_stanza_new();

/** clone a stanza */
XmppStanza *xmpp_stanza_clone(XmppStanza * const stanza);

/** copies a stanza and all children */
XmppStanza * xmpp_stanza_copy(const XmppStanza * const stanza);

/** free a stanza object and it's contents */
int xmpp_stanza_release(XmppStanza * const stanza);

int xmpp_stanza_is_text(XmppStanza * const stanza);
int xmpp_stanza_is_tag(XmppStanza * const stanza);

/** marshall a stanza into text for transmission or display **/
int xmpp_stanza_to_text(XmppStanza *stanza, 
			char ** const buf, size_t * const buflen);

XmppStanza *xmpp_stanza_get_children(XmppStanza * const stanza);
XmppStanza *xmpp_stanza_get_child_by_name(XmppStanza * const stanza, 
					     const char * const name);
XmppStanza *xmpp_stanza_get_child_by_ns(XmppStanza * const stanza,
					   const char * const ns);
XmppStanza *xmpp_stanza_get_next(XmppStanza * const stanza);
char *xmpp_stanza_get_attribute(XmppStanza * const stanza,
				const char * const name);
char * xmpp_stanza_get_ns(XmppStanza * const stanza);
/* concatenate all child text nodes.  this function
 * returns a string that must be freed by the caller */

char *xmpp_stanza_get_text(XmppStanza * const stanza);
char *xmpp_stanza_get_text_ptr(XmppStanza * const stanza);
char *xmpp_stanza_get_name(XmppStanza * const stanza);

int xmpp_stanza_add_child(XmppStanza *stanza, XmppStanza *child);
int xmpp_stanza_set_ns(XmppStanza * const stanza, const char * const ns);
/* set_attribute adds/replaces attributes */
int xmpp_stanza_set_attribute(XmppStanza * const stanza, 
			      const char * const key,
			      const char * const value);
int xmpp_stanza_set_name(XmppStanza *stanza,
			 const char * const name);
int xmpp_stanza_set_text(XmppStanza *stanza,
			 const char * const text);
int xmpp_stanza_set_text_with_size(XmppStanza *stanza,
				   const char * const text, 
				   const size_t size);

/* common stanza helpers */
char *xmpp_stanza_get_type(XmppStanza * const stanza);
char *xmpp_stanza_get_id(XmppStanza * const stanza);
int xmpp_stanza_set_id(XmppStanza * const stanza, 
		       const char * const id);
int xmpp_stanza_set_type(XmppStanza * const stanza, 
			 const char * const type);

/* unimplemented
int xmpp_stanza_set_to();
int xmpp_stanza_set_from();
*/

/* allocate and initialize a stanza in reply to another */
/* unimplemented
XmppStanza *xmpp_stanza_reply(const XmppStanza *stanza);
*/

/* stanza subclasses */
/* unimplemented
void xmpp_message_new();
void xmpp_message_get_body();
void xmpp_message_set_body();

void xmpp_iq_new();
void xmpp_presence_new();
*/

int XmppStanzao_text(const XmppStanza *stanza,
    char ** const buf, size_t * const buflen);

#endif /* _SMARTA_STANZA_H__ */
