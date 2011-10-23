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
#include "adlist.h"
#include "xmpp.h"
#include "smarta.h"

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SERVICE_BLOCK 2
#define IN_COMMADN_BLOCK 3

Smarta smarta;

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
    smarta.logfile = "smarta.log";
    smarta.daemonize = 0;
    smarta.services = listCreate();
    smarta.el = aeCreateEventLoop();
    aeCreateTimeEvent(smarta.el, 100, smarta_cron, NULL, NULL);
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
            service = malloc(sizeof(Service));
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            smarta.name = strdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"server") && argc == 2) {
            smarta.server = strdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"apikey") && argc == 2) {
            smarta.apikey = strdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            service->name = strdup(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"period") && argc == 2) {
            service->period = atoi(argv[1]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"command") && argc == 2) {
            service->command = strdup(argv[1]);
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
    
    domain = "nodehub.cn";

    fd = anetTcpConnect(err, domain, 5222);
    if (fd == -1) {
        exit(-1);
    }
    xmpp_log(LOG_DEBUG, "sock_connect to %s, returned %d", domain, fd);
    /* create stream */
    stream = xmpp_stream_new(fd);
    xmpp_stream_set_jid(stream, smarta.name);
    xmpp_stream_set_pass(stream, smarta.apikey);
    
    aeCreateFileEvent(smarta.el, fd, AE_READABLE, xmpp_read, stream); //| AE_WRITABLE

    xmpp_log(LOG_DEBUG, "attempting to connect to nodehub.cn");

    /* open stream */
    if(xmpp_stream_open(stream) < 0) {
        printf("Stream open failed");
        exit(1);
    }

    smarta_run();

    return 0;
}

void xmpp_read(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    char buf[4096] = {0};

    printf("xmpp_read is callded\n");

    XmppStream *stream = (XmppStream *)privdata;

    nread = read(fd, buf, 4096);
    if(nread <= 0) {
        //FIXME: DISCONNECTED.
        xmpp_log(LOG_DEBUG, "xmpp server is disconnected");
        exit(1);
    }
    printf("nread: %d, data: %s\n", nread, buf);
    xmpp_stream_feed(stream, buf, nread);
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

static void before_sleep(struct aeEventLoop *eventLoop) {
    printf("sleep....\n");
    //NOTHING
}

static int smarta_cron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
    printf("cron called \n");
    return 1000;
}

static void smarta_run() {
    aeSetBeforeSleepProc(smarta.el, before_sleep);
    aeMain(smarta.el);
    aeDeleteEventLoop(smarta.el);
}
