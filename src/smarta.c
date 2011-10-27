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
#include <unistd.h>
#include <errno.h>
#include <sys/uio.h>

#include "ae.h"
#include "sds.h"
#include "anet.h"
#include "zmalloc.h"
#include "jid.h"
#include "xmpp.h"
#include "sched.h"
#include "logger.h"
#include "smarta.h"

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SERVICE_BLOCK 2
#define IN_COMMADN_BLOCK 3

Smarta smarta;

extern int log_level;

extern char *log_file;

static void smarta_run(); 

static void xmpp_read(aeEventLoop *el, int fd, void *privdata, int mask);

static int smarta_cron(struct aeEventLoop *eventLoop, long long id, void *clientData);

void version() {
    printf("Smart agent version 0.1\n");
    exit(0);
}

void usage() {
    fprintf(stderr,"Usage: ./smarta [/path/to/smarta.conf]\n");
    exit(1);
}

void smarta_init() {
    smarta.isslave = 0;
    smarta.verbosity = 0;
    smarta.daemonize = 0;
    smarta.services = listCreate();
    smarta.el = aeCreateEventLoop();
    aeCreateTimeEvent(smarta.el, 100, smarta_cron, NULL, NULL);
    srand(time(NULL)^getpid());
}

int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

void load_config(char *filename) {
    FILE *fp;
    char buf[CONFIGLINE_MAX+1], *err = NULL;
    int linenum = 0;
    sds line = NULL;
    int state = 0;
    Service *service;

    if ((fp = fopen(filename,"r")) == NULL) {
        //redisLog(REDIS_WARNING, "Fatal error, can't open config file '%s'", filename);
        fprintf(stderr, "Fatal error, can't open config file '%s'", filename);
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
            state = 0;
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            listAddNodeTail(smarta.services, service);
            state = 0;
        } else if (!strcasecmp(argv[0],"service") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SERVICE_BLOCK;
            service = zmalloc(sizeof(Service));
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            smarta.name = zstrdup(argv[1]);
            smarta.server = xmpp_jid_domain(smarta.name);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"server") && argc == 2) {
            if(smarta.server) {
                zfree(smarta.server);
            }
            smarta.server = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"apikey") && argc == 2) {
            smarta.apikey = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"logfile") && argc == 2) {
            if(strcmp(argv[1], "stdout")) {
                log_file = zstrdup(argv[1]);
            }
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"loglevel") && argc == 2) {
            if(strcasecmp(argv[1], "debug") == 0) {
                log_level = LOG_DEBUG;
            } else if(strcasecmp(argv[1], "info") == 0) {
                log_level = LOG_INFO;
            } else if(strcasecmp(argv[1], "warning") == 0) {
                log_level = LOG_WARNING;
            } else if(strcasecmp(argv[1], "error") == 0) {
                log_level = LOG_ERROR;
            } else if(strcasecmp(argv[1], "fatal") == 0) {
                log_level = LOG_FATAL;
            } else {
                fprintf(stderr, "unknown loglevel:%s", argv[1]);
                log_level = LOG_ERROR;
            }
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            service->name = zstrdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"period") && argc == 2) {
            service->period = atoi(argv[1]) * 60 * 1000;
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"command") && argc == 2) {
            service->command = zstrdup(argv[1]);
        } else {
            err = "Bad directive or wrong number of arguments"; goto loaderr;
        }
        for (j = 0; j < argc; j++)
            sdsfree(argv[j]);
        zfree(argv);
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
    int fd;
    char err[4096];
    char *domain; // *jid, *pass;
    XmppStream *stream;

    smarta_init();

    if (argc == 2) {
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "-h") == 0 ||
            strcmp(argv[1], "--help") == 0) usage();
        load_config(argv[1]);
    } else {
        usage();
    } 
    
    fd = anetTcpConnect(err, smarta.server, 5222);
    if (fd == -1) {
        fprintf(stderr, "Failed to connect %s\n", domain);
        exit(-1);
    }
    logger_debug("smarta", "sock_connect to %s, returned %d", domain, fd);
    /* create stream */
    stream = xmpp_stream_new(fd);
    xmpp_stream_set_jid(stream, smarta.name);
    xmpp_stream_set_pass(stream, smarta.apikey);
    smarta.stream = stream;
    
    aeCreateFileEvent(smarta.el, fd, AE_READABLE, xmpp_read, stream); //| AE_WRITABLE

    logger_debug("smarta", "attempting to connect to nodehub.cn");

    /* open stream */
    if(xmpp_stream_open(stream) < 0) {
        fprintf(stderr, "stream open failed");
        exit(1);
    }

    sched_run(smarta.el, smarta.services);

    smarta_run();

    return 0;
}

void xmpp_read(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    char buf[4096] = {0};

    XmppStream *stream = (XmppStream *)privdata;

    nread = read(fd, buf, 4096);
    if(nread <= 0) {
        //FIXME: DISCONNECTED.
        logger_error("smarta", "xmpp server is disconnected.");
    }
    logger_debug("socket", "RECV: %s", buf);
    xmpp_stream_feed(stream, buf, nread);
}

static void before_sleep(struct aeEventLoop *eventLoop) {
    if(smarta.stream->prepare_reset == 1) {
        logger_debug("smarta", "before sleep... reset parser");
        parser_reset(smarta.stream->parser);
        smarta.stream->prepare_reset = 0;
    }
}

static int smarta_cron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
    //TODO: check result of tasks and send xmpp message
    //printf("cron called \n");

    //send_message(conn, result);
    return 1000;
}

static void smarta_run() {
    aeSetBeforeSleepProc(smarta.el, before_sleep);
    aeMain(smarta.el);
    aeDeleteEventLoop(smarta.el);
}

void send_message(XmppStream *stream, sds result) {
    XmppStanza *reply, *body, *text;
    
	reply = xmpp_stanza_new();
	xmpp_stanza_set_name(reply, "message");
	xmpp_stanza_set_type(reply, "chat");
	xmpp_stanza_set_attribute(reply, "to", "erylee@nodehub.cn");
	
	body = xmpp_stanza_new();
	xmpp_stanza_set_name(body, "body");
	
	text = xmpp_stanza_new();
	xmpp_stanza_set_text(text, result);
	xmpp_stanza_add_child(body, text);
	xmpp_stanza_add_child(reply, body);
	
	xmpp_send_stanza(stream, reply);
	xmpp_stanza_release(reply);
}
