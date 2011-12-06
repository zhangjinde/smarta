/* 
** stanza.c - XMPP stanza object
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "xmpp.h"
#include "hash.h"
#include "logger.h"
#include "zmalloc.h"

Stanza *stanza_new()
{

    Stanza *stanza;

    stanza = zmalloc(sizeof(Stanza));

	stanza->ref = 1;
	stanza->type = STANZA_UNKNOWN;
	stanza->prev = NULL;
	stanza->next = NULL;
	stanza->children = NULL;
	stanza->parent = NULL;
	stanza->data = NULL;
	stanza->attributes = NULL;

    return stanza; 
}

Stanza *stanza_tag(const char *name) 
{
    Stanza *stanza = stanza_new();
    stanza->type = STANZA_TAG;
    stanza->data = zstrdup(name);
    return stanza;
}

Stanza *stanza_text(const char *text) 
{
    Stanza *stanza = stanza_new();
    stanza->type = STANZA_TEXT;
    stanza->data = zstrdup(text);
    return stanza;
}

Stanza *stanza_cdata(const char *data) 
{
    Stanza *stanza = stanza_new();
    stanza->type = STANZA_CDATA;
    stanza->data = zstrdup(data);
    return stanza;
}

Stanza *stanza_clone(Stanza *  stanza) {

    stanza->ref++;

    return stanza;
}

Stanza *stanza_copy(Stanza * stanza) {
    Stanza *copy, *child, *copychild, *tail;
    hash_iterator_t *iter;
    const char *key;
    void *val;

    copy = stanza_new();

    copy->type = stanza->type;

    if (stanza->data) {
        copy->data = zstrdup(stanza->data);
    }

    if (stanza->attributes) {
        copy->attributes = hash_new(8, zfree);
        iter = hash_iter_new(stanza->attributes);
        while ((key = hash_iter_next(iter))) {
            val = zstrdup((char *)hash_get(stanza->attributes, key));
            hash_add(copy->attributes, key, val);
        }
        hash_iter_release(iter);
    }

    tail = copy->children;
    for (child = stanza->children; child; child = child->next) {
        copychild = stanza_copy(child);
        copychild->parent = copy;

        if (tail) {
            copychild->prev = tail;
            tail->next = copychild;
        } else {
            copy->children = copychild;
        }
        tail = copychild;
    }

    return copy;

}

int stanza_release(Stanza *stanza) {
    int released = 0;
    Stanza *child, *tchild;
    
    /* release stanza */
    if (stanza->ref > 1) {
        stanza->ref--;
    } else {
        /* release all children */
        child = stanza->children;
        while (child) {
            tchild = child;
            child = child->next;
            stanza_release(tchild);
        }

        if (stanza->attributes) {
            hash_release(stanza->attributes);
        }
        if (stanza->data) {
            zfree(stanza->data);
        }
        zfree(stanza);
        released = 1;
    }

    return released;
}

int stanza_is_text(Stanza *stanza) {
    return (stanza && stanza->type == STANZA_TEXT);
}

int stanza_is_tag(Stanza *stanza) {
    return (stanza && stanza->type == STANZA_TAG);
}

/* small helper function */
static inline void _render_update(
               int *written, 
               int length,
			   int lastwrite,
			   size_t *left,
               char **ptr) {
    *written += lastwrite;

    if (*written > length) {
        *left = 0;
        *ptr = NULL;
    } else {
        *left -= lastwrite;
        *ptr = &(*ptr)[lastwrite];
    }
}

static int _render_stanza_recursive(Stanza *stanza,
			     char *buf, size_t buflen) {
    char *ptr = buf;
    size_t left = buflen;
    int ret, written;
    Stanza *child;
    hash_iterator_t *iter;
    const char *key;

    written = 0;

    if (stanza->type == STANZA_UNKNOWN) return -2;

    if (stanza->type == STANZA_TEXT) {
        if (!stanza->data) return -2;
        ret = snprintf(ptr, left, "%s", stanza->data);
        if (ret < 0) return -1;
        _render_update(&written, buflen, ret, &left, &ptr);
    } else if (stanza->type == STANZA_CDATA) {
        if (!stanza->data) return -2;
        ret = snprintf(ptr, left, "<![CDATA[%s]]>", stanza->data);
        if (ret < 0) return -1;
        _render_update(&written, buflen, ret, &left, &ptr);
    } else if (stanza->type == STANZA_TAG) {
        if (!stanza->data) { 
            return -2; 
        }
        /* write begining of tag and attributes */
        ret = snprintf(ptr, left, "<%s", stanza->data);
        if (ret < 0) return -1;
        _render_update(&written, buflen, ret, &left, &ptr);

        if (stanza->attributes && hash_num_keys(stanza->attributes) > 0) {
            iter = hash_iter_new(stanza->attributes);
            while ((key = hash_iter_next(iter))) {
            ret = snprintf(ptr, left, " %s=\"%s\"", key,
                       (char *)hash_get(stanza->attributes, key));
            if (ret < 0) return -1;
            _render_update(&written, buflen, ret, &left, &ptr);
            }
            hash_iter_release(iter);
        }

        if (!stanza->children) {
            /* write end if singleton tag */
            ret = snprintf(ptr, left, "/>");
            if (ret < 0) return -1;
            _render_update(&written, buflen, ret, &left, &ptr);
        } else {
            /* this stanza has child stanzas */

            /* write end of start tag */
            ret = snprintf(ptr, left, ">");
            if (ret < 0) return -1;
            _render_update(&written, buflen, ret, &left, &ptr);
            
            /* iterate and recurse over child stanzas */
            child = stanza->children;
            while (child) {
            ret = _render_stanza_recursive(child, ptr, left);
            if (ret < 0) return ret;

            _render_update(&written, buflen, ret, &left, &ptr);

            child = child->next;
            }

            /* write end tag */
            ret = snprintf(ptr, left, "</%s>", stanza->data);
            if (ret < 0) return -1;
            
            _render_update(&written, buflen, ret, &left, &ptr);
        }
    } else { /* stanza->type == STANZA_UNKNOWN*/
        logger_fatal("STANZA", "unknown xml stanza");
        return -3;
    }

    return written;
}

int stanza_to_text(
    Stanza * stanza,
    char **buf,
    size_t *buflen) {

    char *buffer, *tmp;
    size_t length;
    int ret;

    /* allocate a default sized buffer and attempt to render */
    length = 1024;
    buffer = zmalloc(length);

    ret = _render_stanza_recursive(stanza, buffer, length);
    if (ret < 0) return ret;

    if (ret > length - 1) {
        tmp = zrealloc(buffer, ret + 1);
        length = ret + 1;
        buffer = tmp;

        ret = _render_stanza_recursive(stanza, buffer, length);
        if (ret > length - 1) return -1;
    }
    
    buffer[length - 1] = 0;

    *buf = buffer;
    *buflen = ret;

    return 0;
}

int stanza_set_name(Stanza *stanza, const char *name) {
    if (stanza->type == STANZA_UNKNOWN) stanza->type = STANZA_TAG;
    if (stanza->type != STANZA_TAG) return -2;

    if (stanza->data) zfree(stanza->data);

    stanza->data = zstrdup(name);

    return 0;
}

char *stanza_get_name(Stanza *stanza) 
{
    if (stanza->type == STANZA_TEXT) return NULL;
    return stanza->data;
}

int stanza_get_attribute_count(Stanza *stanza) 
{
    if (stanza->attributes == NULL) {
        return 0;
    }
    return hash_num_keys(stanza->attributes);
}

int stanza_get_attributes(Stanza * const stanza,
			      const char **attr, int attrlen) {
    hash_iterator_t *iter;
    const char *key;
    int num = 0;

    if (stanza->attributes == NULL) {
        return 0;
    }

    iter = hash_iter_new(stanza->attributes);
    while ((key = hash_iter_next(iter)) != NULL && attrlen) {
        attr[num++] = key;
        attrlen--;
        if (attrlen == 0) {
            hash_iter_release(iter);
            return num;
        }
        attr[num++] = hash_get(stanza->attributes, key);
        attrlen--;
        if (attrlen == 0) {
            hash_iter_release(iter);
            return num;
        }
    }

    hash_iter_release(iter);
    return num;
}

int stanza_set_attribute(Stanza *stanza,
			     const char *key,
			     const char *value) {
    char *val;

    if (stanza->type != STANZA_TAG) return -2;

    if (!stanza->attributes) {
        stanza->attributes = hash_new(8, zfree);
    }

    val = zstrdup(value);

    hash_add(stanza->attributes, key, val);

    return 0;
}

int stanza_set_ns(Stanza *stanza, char *ns) {
    return stanza_set_attribute(stanza, "xmlns", ns);
}

void stanza_add_child(Stanza *stanza, Stanza *child) 
{
	Stanza *s;

    /* get a reference to the child */
    stanza_clone(child);

    child->parent = stanza;

    if (!stanza->children) {
        stanza->children = child;
    } else {
        s = stanza->children;
        while (s->next) s = s->next;
        s->next = child;
        child->prev = s;
    }
}

int stanza_set_text(Stanza *stanza, char *text) {
    
    if(stanza->type == STANZA_UNKNOWN) stanza->type = STANZA_TEXT;
    if (stanza->type != STANZA_TEXT) return -2;

    if (stanza->data) { 
        zfree(stanza->data);
    }

    stanza->data = zstrdup(text);

    return 0;
}

int stanza_set_text_with_size(Stanza *stanza,
				  const char *text,
				  size_t size)
{
    if(stanza->type == STANZA_UNKNOWN) stanza->type = STANZA_TEXT;
    if (stanza->type != STANZA_TEXT) return -2;

    if (stanza->data) zfree(stanza->data);
    stanza->data = zmalloc(size + 1);

    memcpy(stanza->data, text, size);
    stanza->data[size] = 0;

    return 0;
}

char *stanza_get_id(Stanza *stanza)
{
    if (stanza->type != STANZA_TAG) return NULL;

    if (!stanza->attributes) return NULL;

    return (char *)hash_get(stanza->attributes, "id");
}

char *stanza_get_ns(Stanza *stanza)
{
    if (stanza->type != STANZA_TAG)
	return NULL;

    if (!stanza->attributes)
	return NULL;

    return (char *)hash_get(stanza->attributes, "xmlns");
}

char *stanza_get_type(Stanza *stanza)
{
    if (stanza->type != STANZA_TAG)
	return NULL;
    
    if (!stanza->attributes)
	return NULL;

    return (char *)hash_get(stanza->attributes, "type");
}

Stanza *stanza_get_child_by_name(Stanza *stanza, char *name)
{
    Stanza *child;
    
    for (child = stanza->children; child; child = child->next) {
	if (child->type == STANZA_TAG &&
	    (strcmp(name, stanza_get_name(child)) == 0))
	    break;
    }

    return child;
}

Stanza *stanza_get_child_by_ns(Stanza *stanza, char *ns)
{
    Stanza *child;

    for (child = stanza->children; child; child = child->next) {
	if (stanza_get_ns(child) &&
	    strcmp(ns, stanza_get_ns(child)) == 0)
	    break;
    }
    
    return child;
}

Stanza *stanza_get_children(Stanza *stanza) 
{
    return stanza->children;
}

Stanza *stanza_get_next(Stanza *stanza)
{
    return stanza->next;
}

char *stanza_get_text(Stanza *stanza)
{
    size_t len, clen;
    Stanza *child;
    char *text;

    if (stanza->type == STANZA_TEXT) {
	if (stanza->data)
	    return zstrdup(stanza->data);
	else
	    return NULL;
    }

    len = 0;
    for (child = stanza->children; child; child = child->next)
	if (child->type == STANZA_TEXT)
	    len += strlen(child->data);

    if (len == 0) return NULL;

    text = (char *)zmalloc(len + 1);
    if (!text) return NULL;

    len = 0;
    for (child = stanza->children; child; child = child->next)
	if (child->type == STANZA_TEXT) {
	    clen = strlen(child->data);
	    memcpy(&text[len], child->data, clen);
	    len += clen;
	}

    text[len] = 0;

    return text;
}

char *stanza_get_text_ptr(Stanza *stanza)
{
    if (stanza->type == STANZA_TEXT)
	return stanza->data;
    return NULL;
}

int stanza_set_id(Stanza *stanza, char *id) 
{
    return stanza_set_attribute(stanza, "id", id);
}

int stanza_set_type(Stanza *stanza,
			char * const type)
{
    return stanza_set_attribute(stanza, "type", type);
}

char *stanza_get_attribute(Stanza *stanza,
				const char *name)
{
    if (stanza->type != STANZA_TAG) return NULL;
    
    if (!stanza->attributes) return NULL;

    return hash_get(stanza->attributes, name);
}

char *stanza_attrs_get_value(char **attrs, char *name) 
{
    int i;

    if (!attrs) return NULL;

    for (i = 0; attrs[i]; i += 2) {
        if (strcmp(name, attrs[i]) == 0) {
            return attrs[i+1];
        }
    }

    return NULL;
}

