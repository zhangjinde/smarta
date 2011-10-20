/* 
** libstrophe XMPP client library -- basic usage example
**
** Copyright (C) 2011 nodehub.cn
**
*/

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "sds.h"
#include "adlist.h"
#include "xmpp.h"
#include "sched.h"
#include "smarta.h"

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SERVICE_BLOCK 2
#define IN_COMMADN_BLOCK 3

smarta_t smarta;

int version_handler(XmppConn * const conn, XmppStanza * const stanza, void * const userdata)
{
	XmppStanza *reply, *query, *name, *version, *text;
	char *ns;
	printf("Received version request from %s\n", xmpp_stanza_get_attribute(stanza, "from"));
	
	reply = xmpp_stanza_new();
	xmpp_stanza_set_name(reply, "iq");
	xmpp_stanza_set_type(reply, "result");
	xmpp_stanza_set_id(reply, xmpp_stanza_get_id(stanza));
	xmpp_stanza_set_attribute(reply, "to", xmpp_stanza_get_attribute(stanza, "from"));
	
	query = xmpp_stanza_new();
	xmpp_stanza_set_name(query, "query");
    ns = xmpp_stanza_get_ns(xmpp_stanza_get_children(stanza));
    if (ns) {
        xmpp_stanza_set_ns(query, ns);
    }

	name = xmpp_stanza_new();
	xmpp_stanza_set_name(name, "name");
	xmpp_stanza_add_child(query, name);
	
	text = xmpp_stanza_new();
	xmpp_stanza_set_text(text, "libstrophe example bot");
	xmpp_stanza_add_child(name, text);
	
	version = xmpp_stanza_new();
	xmpp_stanza_set_name(version, "version");
	xmpp_stanza_add_child(query, version);
	
	text = xmpp_stanza_new();
	xmpp_stanza_set_text(text, "1.0");
	xmpp_stanza_add_child(version, text);
	
	xmpp_stanza_add_child(reply, query);

	xmpp_send(conn, reply);
	xmpp_stanza_release(reply);
	return 1;
}

int message_handler(XmppConn * const conn, XmppStanza * const stanza, void * const userdata)
{
	XmppStanza *reply, *body, *text;
	char *intext, *replytext;
	
	if(!xmpp_stanza_get_child_by_name(stanza, "body")) return 1;
	if(!strcmp(xmpp_stanza_get_attribute(stanza, "type"), "error")) return 1;
	
	intext = xmpp_stanza_get_text(xmpp_stanza_get_child_by_name(stanza, "body"));
	
	printf("Incoming message from %s: %s\n", xmpp_stanza_get_attribute(stanza, "from"), intext);
	
	reply = xmpp_stanza_new();
	xmpp_stanza_set_name(reply, "message");
	xmpp_stanza_set_type(reply, xmpp_stanza_get_type(stanza)?xmpp_stanza_get_type(stanza):"chat");
	xmpp_stanza_set_attribute(reply, "to", xmpp_stanza_get_attribute(stanza, "from"));
	
	body = xmpp_stanza_new();
	xmpp_stanza_set_name(body, "body");
	
	replytext = malloc(strlen(" to you too!") + strlen(intext) + 1);
	strcpy(replytext, intext);
	strcat(replytext, " to you too!");
	
	text = xmpp_stanza_new();
	xmpp_stanza_set_text(text, replytext);
	xmpp_stanza_add_child(body, text);
	xmpp_stanza_add_child(reply, body);
	
	xmpp_send(conn, reply);
	xmpp_stanza_release(reply);
	free(replytext);
	return 1;
}

/* define a handler for connection events */
void conn_handler(XmppConn * const conn, const xmpp_conn_event_t status, 
		  const int error, xmpp_stream_error_t * const stream_error,
		  void * const userdata)
{
    if (status == XMPP_CONN_CONNECT) {
	XmppStanza* pres;
	fprintf(stdout, "DEBUG: smarta is connected\n");
	xmpp_handler_add(conn,version_handler, "jabber:iq:version", "iq", NULL, NULL);
	xmpp_handler_add(conn,message_handler, NULL, "message", NULL, NULL);
	
	/* Send initial <presence/> so that we appear online to contacts */
	pres = xmpp_stanza_new();
	xmpp_stanza_set_name(pres, "presence");
	xmpp_send(conn, pres);
	xmpp_stanza_release(pres);
    }
    else {
	fprintf(stderr, "DEBUG: disconnected\n");
	xmpp_stop(conn);
    }
}

void version() {
    printf("Smart agent version 0.1\n");
    exit(0);
}

void usage() {
    fprintf(stderr,"Usage: ./smarta [/path/to/smarta.conf]\n");
    exit(1);
}


void init_config() {
    smarta.isslave = 0;
    smarta.verbosity = 0;
    smarta.logfile = "smarta.log";
    smarta.daemonize = 0;
    smarta.services = listCreate();
}

int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = malloc(l);

    memcpy(p,s,l);
    return p;
}

void load_config(char *filename) {
    FILE *fp;
    char buf[CONFIGLINE_MAX+1], *err = NULL;
    int linenum = 0;
    sds line = NULL;
    int state = 0;
    service_t *service;

    if ((fp = fopen(filename,"r")) == NULL) {
        //redisLog(REDIS_WARNING, "Fatal error, can't open config file '%s'", filename);
        printf("Fatal error, can't open config file '%s'", filename);
        exit(1);
    }

    while(fgets(buf,CONFIGLINE_MAX+1,fp) != NULL) {
        sds *argv;
        int argc, j;

        linenum++;
        line = sdsnew(buf);
        line = sdstrim(line," \t\r\n");

        /* Skip comments and blank lines*/
        if (line[0] == '#' || line[0] == '\0') {
            sdsfree(line);
            continue;
        }

        /* Split into arguments */
        argv = sdssplitargs(line,&argc);
        sdstolower(argv[0]);

        /* Execute config directives */
        if (!strcasecmp(argv[0],"smarta") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SMARTA_BLOCK;
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            printf("smarta.name: %s\n", smarta.name);
            printf("smarta.server: %s\n", smarta.server);
            printf("smarta.apikey: %s\n\n", smarta.apikey);
            state = 0;
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            printf("service.name: %s\n", service->name);
            printf("service.period: %d\n", (int)service->period);
            printf("service.command: %s\n\n", service->command);
            listAddNodeTail(smarta.services, service);
            state = 0;
        } else if (!strcasecmp(argv[0],"service") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SERVICE_BLOCK;
            service = malloc(sizeof(service_t));
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            smarta.name = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"server") && argc == 2) {
            smarta.server = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"apikey") && argc == 2) {
            smarta.apikey = zstrdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            service->name = zstrdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"period") && argc == 2) {
            service->period = atoi(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"command") && argc == 2) {
            service->command = zstrdup(argv[1]);
        } else {
            err = "Bad directive or wrong number of arguments"; goto loaderr;
        }
        for (j = 0; j < argc; j++)
            sdsfree(argv[j]);
        free(argv);
        sdsfree(line);
    }
    fclose(fp);
    return;

loaderr:
    fprintf(stderr, "\n*** FATAL CONFIG FILE ERROR ***\n");
    fprintf(stderr, "Reading the configuration file, at line %d\n", linenum);
    fprintf(stderr, ">>> '%s'\n", line);
    fprintf(stderr, "%s\n", err);
    exit(1);
}

int main(int argc, char **argv) {
    XmppConn *conn;
    char *jid, *pass;

    init_config();

    if (argc == 2) {
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "-h") == 0 ||
            strcmp(argv[1], "--help") == 0) usage();
        load_config(argv[1]);
    } else {
        usage();
    } 

    jid = smarta.name;
    pass = smarta.apikey;

    /* init library */
    xmpp_initialize();

    /* create a connection */
    conn = xmpp_conn_new();

    /* setup authentication information */
    xmpp_conn_set_jid(conn, jid);
    xmpp_conn_set_pass(conn, pass);

    /* initiate connection */
    xmpp_connect_client(conn, NULL, 0, conn_handler, NULL);

    /* sched checks */
    sched_services(conn);

    /* enter the event loop - 
       our connect handler will trigger an exit */
    xmpp_run(conn);

    /* release our connection and context */
    xmpp_conn_release(conn);

    /* final shutdown of the library */
    xmpp_shutdown();

    return 0;
}

void xmpp_log(int level, const char *fmt, ...) {
    const char *levels[] = {"DEBUG", "INFO", "WARN", "ERROR"};
    time_t now = time(NULL);
    va_list ap;
    FILE *fp;
    char buf[64];
    char msg[MAX_LOGMSG_LEN];

    if (level < smarta.verbosity) return;

    fp = (smarta.logfile == NULL) ? stdout : fopen(smarta.logfile,"a");
    if (!fp) return;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    strftime(buf,sizeof(buf),"%d %b %H:%M:%S",localtime(&now));
    fprintf(fp,"%s[%s] %s\n",buf,levels[level],msg);
    fflush(fp);

    if (smarta.logfile) fclose(fp);
}
