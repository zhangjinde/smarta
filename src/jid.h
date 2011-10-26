#ifndef __JID_H
#define __JID_H

char *xmpp_jid_new(const char *node, 
    const char *domain, 
    const char *resource);

char *xmpp_jid_bare(const char *jid);

char *xmpp_jid_node(const char *jid);

char *xmpp_jid_domain(const char *jid);

char *xmpp_jid_resource(const char *jid);

#endif
