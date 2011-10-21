/* handler management */
void handler_fire_stanza(XmppConn * const conn,
			 XmppStanza * const stanza);
uint64_t handler_fire_timed(XmppConn *conn);
void handler_reset_timed(XmppConn *conn, int user_only);
void handler_add_timed(XmppConn * const conn,
		       xmpp_timed_handler handler,
		       const unsigned long period,
		       void * const userdata);
void handler_add_id(XmppConn * const conn,
		    xmpp_handler handler,
		    const char * const id,
		    void * const userdata);
void handler_add(XmppConn * const conn,
		 xmpp_handler handler,
		 const char * const ns,
		 const char * const name,
		 const char * const type,
		 void * const userdata);
