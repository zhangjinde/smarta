#ifndef __STANZA_H
#define __STANZA_H

#include "hash.h"

typedef enum {
    STANZA_UNKNOWN = -1,
    STANZA_TAG,
    STANZA_TEXT,
    STANZA_CDATA,
} StanzaType;

typedef struct _Stanza {
    int ref;

    StanzaType type;
    
    struct _Stanza *prev;
    struct _Stanza *next;
    struct _Stanza *children;
    struct _Stanza *parent;

    char *data;

    Hash *attributes;
} Stanza;

/*
**create a blank stanza
*/
Stanza *stanza_new();


/*
**create a tag stanza
*/
Stanza *stanza_tag(const char *name);
/*
** create a text stanza
*/
Stanza *stanza_text(const char *data);

/*
** create a cdata stanza
*/
Stanza *stanza_cdata(const char *data);

/** clone a stanza */
Stanza *stanza_clone(Stanza * stanza);

/** copies a stanza and all children */
Stanza *stanza_copy(Stanza * stanza);

/** free a stanza object and it's contents */
int stanza_release(Stanza * stanza);

int stanza_is_text(Stanza * stanza);

int stanza_is_tag(Stanza * stanza);

/** marshall a stanza into text for transmission or display **/
int stanza_to_text(Stanza *stanza, 
    char ** buf, size_t * buflen);

int stanza_get_attributes(Stanza * const stanza,
    const char **attr, int attrlen);

Stanza *stanza_get_children(Stanza * stanza);
Stanza *stanza_get_child_by_name(Stanza * stanza, 
					     char * name);
Stanza *stanza_get_child_by_ns(Stanza * stanza,
					   char * ns);
Stanza *stanza_get_next(Stanza * stanza);
char *stanza_get_attribute(Stanza * stanza,
				const char * name);

char *stanza_attrs_get_value(char **attrs, char *name);

char * stanza_get_ns(Stanza * stanza);
/* concatenate all child text nodes.  this function
 * returns a string that must be freed by the caller */

char *stanza_get_text(Stanza * stanza);

char *stanza_get_text_ptr(Stanza * stanza);

char *stanza_get_name(Stanza * stanza);

void stanza_add_child(Stanza *stanza, Stanza *child);

int stanza_set_ns(Stanza * stanza, char * ns);

/* set_attribute adds/replaces attributes */
int stanza_set_attribute(Stanza * stanza, 
			      const char * key,
			      const char * value);
int stanza_set_name(Stanza *stanza,
			 const char * name);

int stanza_set_text(Stanza *stanza,
			 char * text);

int stanza_set_text_with_size(Stanza *stanza,
				   const char *text, 
				   size_t size);

/* common stanza helpers */
char *stanza_get_type(Stanza * stanza);
char *stanza_get_id(Stanza * stanza);
int stanza_set_id(Stanza * stanza, 
		       char * id);
int stanza_set_type(Stanza * stanza, 
			 char * type);

#endif /* _SMARTA_STANZA_H__ */
