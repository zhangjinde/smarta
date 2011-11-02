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
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <fcntl.h> //open

#include "ae.h"
#include "sds.h"
#include "anet.h"
#include "zmalloc.h"
#include "jid.h"
#include "xmpp.h"
#include "event.h"
#include "sched.h"
#include "slave.h"
#include "logger.h"
#include "smarta.h"
#include "version.h"

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SERVICE_BLOCK 2
#define IN_COMMAND_BLOCK 3

#define HEARTBEAT_TIMEOUT 800000

Smarta smarta;

extern int log_level;

extern char *log_file;

static void daemonize(); 

static void smarta_run(); 

static void conn_handler(XmppStream *stream, XmppStreamState state); 

static void command_handler(XmppStream *stream, XmppStanza *stanza); 

static int smarta_cron(aeEventLoop *eventLoop, long long id, void *clientData);

static int smarta_heartbeat(aeEventLoop *el, long long id, void *clientData); 

void version() {
    printf("Smart agent version %s\n", SMARTA_VERSION);
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
    smarta.daemonize = 1;
    smarta.pidfile = "/var/run/smarta.pid";
    smarta.events = hash_new(8, event_free);
    smarta.services = listCreate();
    smarta.commands = listCreate();
    smarta.cmdusage = NULL;
    smarta.slaves = listCreate();
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
    Command *command;

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
        argv = sdssplitargswithquotes(line, &argc);
        sdstolower(argv[0]);

        /* Execute config directives */
        if (!strcasecmp(argv[0],"smarta") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SMARTA_BLOCK;
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            state = 0;
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            listAddNodeTail(smarta.services, service);
            state = 0;
        } else if ((state == IN_COMMAND_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            listAddNodeTail(smarta.commands, command);
            state = 0;
        } else if (!strcasecmp(argv[0],"service") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SERVICE_BLOCK;
            service = zmalloc(sizeof(Service));
        } else if (!strcasecmp(argv[0],"command") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_COMMAND_BLOCK;
            command = zmalloc(sizeof(Command));
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
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"daemonize") && argc == 2) {
            if ((smarta.daemonize = yesnotoi(argv[1])) == -1) {
                err = "argument must be 'yes' or 'no'"; goto loaderr;
            }
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
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"pidfile") && argc == 2) {
            smarta.pidfile = strdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"collectd") && argc == 2) {
            smarta.collectd = atoi(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"masterport") && argc == 2) {
            smarta.masterport = atoi(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"slaveof") && argc == 3) {
            smarta.slaveip= strdup(argv[1]);
            smarta.slaveport = atoi(argv[2]);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"name") && argc >= 2) {
            service->name = sdsjoin(argv+1, argc-1);
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"period") && argc == 2) {
            service->period = atoi(argv[1]) * 60 * 1000;
        } else if ((state == IN_SERVICE_BLOCK) && !strcasecmp(argv[0],"command") && argc >= 2) {
            service->command = sdsjoin(argv+1, argc-1);
        } else if ((state == IN_COMMAND_BLOCK) && !strcasecmp(argv[0],"usage") && argc >= 2) {
            command->usage = sdsjoin(argv+1, argc-1);
        } else if ((state == IN_COMMAND_BLOCK) && !strcasecmp(argv[0],"shell") && argc >= 2) {
            command->shell = sdsjoin(argv+1, argc-1);
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

    if(smarta.daemonize) daemonize();
    
    /* create stream */
    stream = xmpp_stream_new();
    xmpp_stream_set_jid(stream, smarta.name);
    xmpp_stream_set_pass(stream, smarta.apikey);
    smarta.stream = stream;

    if(smarta.slaveip) {
        xmpp_stream_set_server(stream, smarta.slaveip);
        xmpp_stream_set_port(stream, smarta.slaveport);
    }

    /* open stream */
    if(xmpp_connect(smarta.el, stream) < 0) {
        logger_error("SMARTA", "xmpp connect failed.");
        exit(-1);
    }

    xmpp_add_conn_callback(stream, (conn_callback)conn_handler);
    
    xmpp_add_message_callback(stream, (message_callback)command_handler);

    fd = anetUdpServer(err, "127.0.0.1", smarta.collectd);

    if(fd < 0) {
        logger_error("SMARTA", "failed to open upd socket %d. err: %s", smarta.collectd, err);
        exit(-1);
    }

    aeCreateFileEvent(smarta.el, fd, AE_READABLE, sched_check_result, stream);

    if(smarta.masterport) {
        fd = anetTcpServer(err, smarta.masterport, NULL);
        if(fd < 0) {
            logger_error("SMARTA", "failed to open master socket %d. err: %s", smarta.masterport, err);
            exit(-1);
        }
        aeCreateFileEvent(smarta.el, fd, AE_READABLE, slave_accept_handler, NULL);
    }

    sched_run(smarta.el, smarta.services);

    smarta_run();

    return 0;
}

static void conn_handler(XmppStream *stream, XmppStreamState state) 
{
    if(state == XMPP_STREAM_DISCONNECTED) {
        if(smarta.heartbeat) aeDeleteTimeEvent(smarta.el, smarta.heartbeat);
        logger_error("SMARTA", "disconnected from server.");
    } else if(state == XMPP_STREAM_CONNECTING) {
        logger_info("SMARTA", "connecting to server...");
    } else if(state == XMPP_STREAM_TLS_NEGOTIATING) {
        logger_info("SMARTA", "tls negotiating...");
    } else if(state == XMPP_STREAM_TSL_OPENED) {
        logger_info("SMARTA", "tls opened.");
    } else if(state == XMPP_STREAM_SASL_AUTHENTICATING) {
        logger_info("SMARTA", "authenticating...");
    } else if(state == XMPP_STREAM_SASL_AUTHED) {
        logger_info("SMARTA", "authenticate successfully.");
    } else if(state == XMPP_STREAM_ESTABLISHED) {
        smarta.heartbeat = aeCreateTimeEvent(smarta.el, HEARTBEAT_TIMEOUT, smarta_heartbeat, stream, NULL);
        logger_info("SMARTA", "session established.");
        logger_info("SMARTA", "smarta is started successfully.");
    } else {
        //IGNORE
    }
}

static int smarta_heartbeat(aeEventLoop *el, long long id, void *clientData) 
{
    XmppStream *stream = (XmppStream *)clientData;
    XmppStanza *presence = xmpp_stanza_newtag("presence");
    xmpp_send_stanza(stream, presence);
    xmpp_stanza_release(presence);
    return HEARTBEAT_TIMEOUT;
}

static Command *find_command(char *usage)
{
    listNode *node;
    listIter *iter = listGetIterator(smarta.commands, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        Command *command = (Command *)node->value;
        if(!strcmp(command->usage, usage)) {
            return command;
        }
    }
    listReleaseIterator(iter);
    return NULL;
}

static sds execute(char *incmd)
{
    char buf[1024];
    Command *command;
    sds output = sdsempty();
    if(strcmp(incmd, "show events") == 0) {
        const char *key;
        Event *event;
        hash_iterator_t *iter = hash_iter_new(smarta.events);
        while((key = hash_iter_next(iter))) {
            event = hash_get(smarta.events, key);
            output = sdscatprintf(output, "%s %s - %s\n", 
                key, event->status, event->subject);
        }
        hash_iter_release(iter);
    } else if( (command = find_command(incmd) )) {
        FILE *fp = popen(command->shell, "r");
        if(!fp) {
            sdsfree(output);
            return NULL;
        }
        while(fgets(buf, 1023, fp)) {
            output = sdscat(output, buf);
        }
        pclose(fp);
    } else {
        if(smarta.cmdusage) {
            output = sdscat(output, smarta.cmdusage);
        } else {
            listNode *node;
            output = sdscatprintf(output, "Smarta %s, available commands:\nshow events\n", SMARTA_VERSION);
            listIter *iter = listGetIterator(smarta.commands, AL_START_HEAD);
            while((node = listNext(iter)) != NULL) {
                command = (Command *)node->value;
                output = sdscatprintf(output, "%s\n", command->usage);
            }
            listReleaseIterator(iter);
            smarta.cmdusage = sdsdup(output);
        }
    }
    return output;
}

static void command_handler(XmppStream *stream, XmppStanza *stanza) 
{
	XmppStanza *reply, *body, *text;
	char *incmd;
    sds output;
	
	if(!xmpp_stanza_get_child_by_name(stanza, "body")) return;
	if(!strcmp(xmpp_stanza_get_attribute(stanza, "type"), "error")) return;
	
	incmd = xmpp_stanza_get_text(xmpp_stanza_get_child_by_name(stanza, "body"));

    if(!strlen(incmd)) return;

    output = execute(incmd);

    if(!output) return;

    if(!sdslen(output)) {
        sdsfree(output);
        return;
    }
	
	reply = xmpp_stanza_newtag("message");
	xmpp_stanza_set_type(reply, xmpp_stanza_get_type(stanza) ? xmpp_stanza_get_type(stanza) : "chat");
	xmpp_stanza_set_attribute(reply, "to", xmpp_stanza_get_attribute(stanza, "from"));
	
	body = xmpp_stanza_newtag("body");
	
	text = xmpp_stanza_new();
	xmpp_stanza_set_text(text, output);
	xmpp_stanza_add_child(body, text);
	xmpp_stanza_add_child(reply, body);
	
	xmpp_send_stanza(stream, reply);
	xmpp_stanza_release(reply);
	sdsfree(output);
}

static void daemonize(void) {
    int fd;
    FILE *fp;

    if (fork() != 0) exit(0); /* parent exits */
    setsid(); /* create a new session */

    /* Every output goes to /dev/null. If Redis is daemonized but
     * the 'logfile' is set to 'stdout' in the configuration file
     * it will not log at all. */
    if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO) close(fd);
    }
    /* Try to write the pid file */
    fp = fopen(smarta.pidfile,"w");
    if (fp) {
        fprintf(fp,"%d\n",getpid());
        fclose(fp);
    }
}


static void before_sleep(struct aeEventLoop *eventLoop) {
    if(smarta.stream->prepare_reset == 1) {
        logger_debug("SMARTA", "before sleep... reset parser");
        parser_reset(smarta.stream->parser);
        smarta.stream->prepare_reset = 0;
    }
}

static int smarta_cron(struct aeEventLoop *eventLoop, long long id, void *clientData) {
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

