/* 
** jid.c 
*/

#include <string.h>

#include "zmalloc.h"

char *jid_new(const char *node,
				   const char *domain,
				   const char *resource) {
    char *result;
    int len,nlen,dlen,rlen;

    /* jid must at least have a domain */
    if (domain == NULL) return NULL;

    /* accumulate lengths */
    dlen = strlen(domain);
    nlen = (node) ? strlen(node) + 1 : 0;
    rlen = (resource) ? strlen(resource) + 1 : 0;
    len = nlen + dlen + rlen;

    /* concat components */
    result = zmalloc(len + 1);
    if (result != NULL) {
	if (node != NULL) {
	    memcpy(result, node, nlen - 1);
	    result[nlen-1] = '@';
	}
    memcpy(result + nlen, domain, dlen);
	if (resource != NULL) {
	    result[nlen+dlen] = '/';
	    memcpy(result+nlen+dlen+1, resource, rlen - 1);
	}
	result[nlen+dlen+rlen] = '\0';
    }

    return result;
}

/** Create a bare JID from a JID.
 *  
 *  @param jid the JID
 *
 *  @return an allocated string with the bare JID or NULL on an error
 */
char *jid_bare(const char *jid) {
    char *result;
    const char *c;

    c = strchr(jid, '/');
    if (c == NULL) return zstrdup(jid);

    result = zmalloc(c-jid+1);
    if (result != NULL) {
        memcpy(result, jid, c-jid);
        result[c-jid] = '\0';
    }

    return result;
}

/** Create a node string from a JID.
 *  
 *  @param jid the JID
 *
 *  @return an allocated string with the node or NULL if no node is found
 *      or an error occurs
 */
char *jid_node(const char *jid) {
    char *result = NULL;
    const char *c;

    c = strchr(jid, '@');
    if (c != NULL) {
        result = zmalloc((c-jid) + 1);
	    memcpy(result, jid, (c-jid));
	    result[c-jid] = '\0';
    }

    return result;
}

/** Create a domain string from a JID.
 *
 *  @param jid the JID
 *
 *  @return an allocated string with the domain or NULL on an error
 */
char *jid_domain(const char *jid) {
    char *result = NULL;
    const char *c,*s;

    c = strchr(jid, '@');
    if (c == NULL) {
        /* no node, assume domain */
        c = jid;
    } else {
        /* advance past the separator */
        c++;
    }
    s = strchr(c, '/');
    if (s == NULL) {
        /* no resource */
        s = c + strlen(c);
    }
    result = zmalloc((s-c) + 1);
	memcpy(result, c, (s-c));
	result[s-c] = '\0';

    return result;
}

/** Create a resource string from a JID.
 *
 *  @param jid the JID
 *
 *  @return an allocated string with the resource or NULL if no resource 
 *      is found or an error occurs
 */
char *jid_resource(const char *jid) {
    char *result = NULL;
    const char *c;
    int len;

    c = strchr(jid, '/');
    if (c != NULL)  {
        c++;
        len = strlen(c);
        result = zmalloc(len + 1);
        memcpy(result, c, len);
        result[len] = '\0';
    }

    return result;
}

int jid_bare_compare(const char *jid1, const char *jid2) 
{
    return strcmp(jid_bare(jid1), jid_bare(jid2));
}

