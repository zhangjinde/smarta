#ifndef _SMARTA_STANZA_H_
#define _SMARTA_STANZA_H_

#include "hash.h"

typedef struct _xmpp_stanza_t xmpp_stanza_t;

typedef enum {
    XMPP_STANZA_UNKNOWN,
    XMPP_STANZA_TEXT,
    XMPP_STANZA_TAG
} xmpp_stanza_type_t;

struct _xmpp_stanza_t {
    int ref;

    xmpp_stanza_type_t type;
    
    xmpp_stanza_t *prev;
    xmpp_stanza_t *next;
    xmpp_stanza_t *children;
    xmpp_stanza_t *parent;

    char *data;

    hash_t *attributes;
};

/** stanzas **/

/** allocate an initialize a blank stanza */
xmpp_stanza_t *xmpp_stanza_new();

/** clone a stanza */
xmpp_stanza_t *xmpp_stanza_clone(xmpp_stanza_t * const stanza);

/** copies a stanza and all children */
xmpp_stanza_t * xmpp_stanza_copy(const xmpp_stanza_t * const stanza);

/** free a stanza object and it's contents */
int xmpp_stanza_release(xmpp_stanza_t * const stanza);

int xmpp_stanza_is_text(xmpp_stanza_t * const stanza);
int xmpp_stanza_is_tag(xmpp_stanza_t * const stanza);

/** marshall a stanza into text for transmission or display **/
int xmpp_stanza_to_text(xmpp_stanza_t *stanza, 
			char ** const buf, size_t * const buflen);

xmpp_stanza_t *xmpp_stanza_get_children(xmpp_stanza_t * const stanza);
xmpp_stanza_t *xmpp_stanza_get_child_by_name(xmpp_stanza_t * const stanza, 
					     const char * const name);
xmpp_stanza_t *xmpp_stanza_get_child_by_ns(xmpp_stanza_t * const stanza,
					   const char * const ns);
xmpp_stanza_t *xmpp_stanza_get_next(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_attribute(xmpp_stanza_t * const stanza,
				const char * const name);
char * xmpp_stanza_get_ns(xmpp_stanza_t * const stanza);
/* concatenate all child text nodes.  this function
 * returns a string that must be freed by the caller */

char *xmpp_stanza_get_text(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_text_ptr(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_name(xmpp_stanza_t * const stanza);

int xmpp_stanza_add_child(xmpp_stanza_t *stanza, xmpp_stanza_t *child);
int xmpp_stanza_set_ns(xmpp_stanza_t * const stanza, const char * const ns);
/* set_attribute adds/replaces attributes */
int xmpp_stanza_set_attribute(xmpp_stanza_t * const stanza, 
			      const char * const key,
			      const char * const value);
int xmpp_stanza_set_name(xmpp_stanza_t *stanza,
			 const char * const name);
int xmpp_stanza_set_text(xmpp_stanza_t *stanza,
			 const char * const text);
int xmpp_stanza_set_text_with_size(xmpp_stanza_t *stanza,
				   const char * const text, 
				   const size_t size);

/* common stanza helpers */
char *xmpp_stanza_get_type(xmpp_stanza_t * const stanza);
char *xmpp_stanza_get_id(xmpp_stanza_t * const stanza);
int xmpp_stanza_set_id(xmpp_stanza_t * const stanza, 
		       const char * const id);
int xmpp_stanza_set_type(xmpp_stanza_t * const stanza, 
			 const char * const type);

/* unimplemented
int xmpp_stanza_set_to();
int xmpp_stanza_set_from();
*/

/* allocate and initialize a stanza in reply to another */
/* unimplemented
xmpp_stanza_t *xmpp_stanza_reply(const xmpp_stanza_t *stanza);
*/

/* stanza subclasses */
/* unimplemented
void xmpp_message_new();
void xmpp_message_get_body();
void xmpp_message_set_body();

void xmpp_iq_new();
void xmpp_presence_new();
*/

#endif /* _SMARTA_STANZA_H__ */
