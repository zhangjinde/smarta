/* 
** Smarta agent.
**
** Copyright (C) 2011 nodebus.com
**
*/

#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "ae.h"
#include "sds.h"
#include "anet.h"
#include "jid.h"
#include "xmpp.h"
#include "event.h"
#include "slave.h"
#include "proxy.h"
#include "logger.h"
#include "smarta.h"
#include "zmalloc.h"
#include "version.h"

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SENSOR_BLOCK 2
#define IN_COMMAND_BLOCK 3

#define HEARTBEAT_TIMEOUT 800000

Smarta smarta;

extern int log_level;

extern char *log_file;

static void daemonize(void); 

static void smarta_run(void); 

static void smarta_xmpp_connect(void);

static void smarta_collectd_start(void);

static void smarta_masterd_start(void);

static void smarta_proxy_start(void);

static void sched_checks(void);

static int smarta_cron(aeEventLoop *eventLoop, 
    long long id, void *clientData);

//static int smarta_heartbeat(aeEventLoop *el, 
//    long long id, void *clientData); 

static void conn_handler(XmppStream *stream, 
    XmppStreamState state); 

static void presence_handler(XmppStream *stream,
    XmppStanza *presence);

static void command_handler(XmppStream *stream, 
    XmppStanza *stanza); 

static void roster_handler(XmppStream *stream,
    XmppStanza *iq);

static void handle_check_result(aeEventLoop *el,
    int fd, void *privdata, int mask);

static int check_sensor(struct aeEventLoop *el,
    long long id, void *clientdata);

static void smarta_emit_event(XmppStream *stream,
     Event *event);

static sds execute(char *incmd);

static void create_pid_file(void);

static int is_valid(const char *buf);

static int yesnotoi(char *s); 

static int strcompare(const void *s1, const void *s2); 

static void sortlines(void *array, unsigned int len);

static void version() 
{
    printf("Smart agent version %s\n", SMARTA_VERSION);
    exit(0);
}

static void usage() 
{
    fprintf(stderr,"Usage: ./smarta [/path/to/smarta.conf]\n");
    exit(1);
}

/*
** call in parent process
*/
static void smarta_prepare() 
{
    log_level = LOG_INFO;
    log_file = "smarta.log";
    smarta.isslave = 0;
    smarta.verbosity = 0;
    smarta.daemonize = 1;
    smarta.collectd = -1;
    smarta.collectd_port = 0;
    smarta.pidfile = "/var/run/smarta.pid";
    smarta.sensors = listCreate();
    smarta.commands = listCreate();
    smarta.cmdusage = NULL;
}

/*
** call in fork process
*/

static void smarta_init() 
{
    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    smarta.events = hash_new(8, (hash_free_func)event_free);
    smarta.slaves = listCreate();
    smarta.el = aeCreateEventLoop();
    aeCreateTimeEvent(smarta.el, 100, smarta_cron, NULL, NULL);
    srand(time(NULL)^getpid());
}


static void smarta_config(char *filename) {
    FILE *fp;
    char buf[CONFIGLINE_MAX+1], *err = NULL;
    int linenum = 0;
    sds line = NULL;
    int state = 0;
    Sensor *sensor;
    Command *command;

    if ((fp = fopen(filename,"r")) == NULL) {
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
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            listAddNodeTail(smarta.sensors, sensor);
            state = 0;
        } else if ((state == IN_COMMAND_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            listAddNodeTail(smarta.commands, command);
            state = 0;
        } else if (!strcasecmp(argv[0],"sensor") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SENSOR_BLOCK;
            sensor = zmalloc(sizeof(Sensor));
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
            smarta.collectd_port = atoi(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"proxy") && argc == 2) {
            smarta.proxyport = atoi(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"master") && argc == 2) {
            smarta.masterport = atoi(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"slaveof") && argc == 3) {
            smarta.slaveip= strdup(argv[1]);
            smarta.slaveport = atoi(argv[2]);
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0],"name") && argc >= 2) {
            sensor->name = sdsjoin(argv+1, argc-1);
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0],"period") && argc == 2) {
            sensor->period = atoi(argv[1]) * 60 * 1000;
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0],"command") && argc >= 2) {
            sensor->command = sdsjoin(argv+1, argc-1);
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

    smarta_prepare();

    if (argc == 2) {
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) version();
        if (strcmp(argv[1], "-h") == 0 ||
            strcmp(argv[1], "--help") == 0) usage();
        smarta_config(argv[1]);
    } else {
        usage();
    } 

    if(smarta.daemonize) daemonize();

    smarta_init();

    if(smarta.daemonize) create_pid_file();

    smarta_xmpp_connect();

    smarta_collectd_start();

    if(smarta.masterport)  smarta_masterd_start();

    if(smarta.proxyport) smarta_proxy_start();

    sched_checks();

    smarta_run();

    return 0;
}

static void smarta_xmpp_connect(void) 
{
    /* create stream */
    smarta.stream = xmpp_stream_new();
    xmpp_stream_set_jid(smarta.stream, smarta.name);
    xmpp_stream_set_pass(smarta.stream, smarta.apikey);
    if(smarta.server) {
        xmpp_stream_set_server(smarta.stream, smarta.server);
    }

    if(smarta.slaveip) {
        xmpp_stream_set_server(smarta.stream, smarta.slaveip);
        xmpp_stream_set_port(smarta.stream, smarta.slaveport);
    }

    /* open stream */
    if(xmpp_connect(smarta.el, smarta.stream) < 0) {
        logger_error("SMARTA", "xmpp connect failed.");
        exit(-1);
    }

    xmpp_add_conn_callback(smarta.stream, (conn_callback)conn_handler);
    
    xmpp_add_presence_callback(smarta.stream, (presence_callback)presence_handler);
    
    xmpp_add_message_callback(smarta.stream, (message_callback)command_handler);

    xmpp_add_iq_ns_callback(smarta.stream, "nodebus:iq:roster", (iq_callback)roster_handler);
}

static void smarta_collectd_start(void)
{
    int ret = -1;
    unsigned int size;
    struct sockaddr_in sa;

    smarta.collectd = anetUdpServer(smarta.neterr, "127.0.0.1", smarta.collectd_port);

	logger_info("SMARTA", "collected port: %d", smarta.collectd_port);

    if(smarta.collectd <= 0) {
        logger_error("SMARTA", "failed to open collectd socket %d. err: %s", 
            smarta.collectd_port, smarta.neterr);
        exit(-1);
    }

    if(!smarta.collectd_port) {
        //ret = getsockname(smarta.collectd, (struct sockaddr *)&sa, &size);
        //if(ret < 0) {
        //    logger_error("SMARTA", "failed to getsockname of collectd.");
        //    exit(-1);
        //}
        //logger_info("SMARTA", "collected on %s:%d", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        //smarta.collectd_port = ntohs(sa.sin_port);
    }

    aeCreateFileEvent(smarta.el, smarta.collectd, AE_READABLE, handle_check_result, smarta.stream);
}

static void smarta_proxy_start(void) 
{
    smarta.proxyfd = anetTcpServer(smarta.neterr, smarta.proxyport, NULL);
    if(smarta.proxyfd <= 0) {
        logger_error("SMARTA", "open proxy socket %d. err: %s",
            smarta.proxyport, smarta.neterr);
        exit(-1);
    }
    logger_info("SMARTA", "proxy on port %d", smarta.proxyport);
    aeCreateFileEvent(smarta.el, smarta.proxyfd, AE_READABLE, proxy_accept_handler, NULL);
}

static void smarta_masterd_start(void) 
{
    smarta.masterfd = anetTcpServer(smarta.neterr, smarta.masterport, NULL);
    if(smarta.masterfd < 0) {
        logger_error("SMARTA", "open master socket %d. err: %s",
            smarta.masterport, smarta.neterr);
        exit(-1);
    }
    logger_info("SMARTA", "master on port %d", smarta.masterport);
    aeCreateFileEvent(smarta.el, smarta.masterfd, AE_READABLE, slave_accept_handler, NULL);
}

//static int smarta_heartbeat(aeEventLoop *el, long long id, void *clientData) 
//{
//    XmppStream *stream = (XmppStream *)clientData;
//    XmppStanza *presence = xmpp_stanza_tag("presence");
//    xmpp_send_stanza(stream, presence);
//    xmpp_stanza_release(presence);
//    return HEARTBEAT_TIMEOUT;
//}

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
        //smarta.heartbeat = aeCreateTimeEvent(smarta.el, HEARTBEAT_TIMEOUT, smarta_heartbeat, stream, NULL);
        logger_info("SMARTA", "session established.");
        logger_info("SMARTA", "smarta is started successfully.");
    } else {
        //IGNORE
    }
}

static void roster_handler(XmppStream *stream, XmppStanza *iq) 
{
    Buddy *buddy;
    XmppStanza *query, *item;
    char *from, *jid, *type, *sub;

    type = xmpp_stanza_get_type(iq);
    from = xmpp_stanza_get_attribute(iq, "from");

    if (strcmp(type, "error") == 0) {
        logger_error("XMPP", "error roster stanza.");
        return;
    }

    if(!from || strcmp(from, "status.nodebus.com")) {
        logger_error("XMPP", "invalid from.");
        return;
    }

	query = xmpp_stanza_get_child_by_name(iq, "query");
	for (item = xmpp_stanza_get_children(query);
        item; item = xmpp_stanza_get_next(item)) {
        jid = xmpp_stanza_get_attribute(item, "jid");
        sub = xmpp_stanza_get_attribute(item, "subscription");
        if(strcmp(sub, "follow") == 0) {
            buddy = buddy_new();
            buddy->jid = zstrdup(jid);
            buddy->sub = SUB_BOTH;
            logger_info("SMARTA", "%s followed this node.", jid);
            hash_add(stream->roster, buddy->jid, buddy);
        } else if(strcmp(sub, "unfollow") == 0) {
            logger_info("SMARTA", "%s unfollowed this node.", jid);
            int i = 0, j = 0;
            listIter *iter;
            listNode *node;
            listNode *nodes[listLength(stream->presences)];
            iter = listGetIterator(stream->presences, AL_START_HEAD);
            while((node = listNext(iter))) {
                if(strncmp((char *)node->value, jid, strlen(jid)) == 0) {
                    nodes[i++] = node;
                }
            }
            listReleaseIterator(iter);
            for(j = 0; j < i; j++) {
                listDelNode(stream->presences, nodes[j]);
            }
            hash_drop(stream->roster, jid);
            //FIXME:
            //delete from stream->presences
        } else {
            logger_warning("XMPP", "unknown sub: '%s'", sub);
        }
    }
    //FIXME: send result
}

static void presence_handler(XmppStream *stream, XmppStanza *presence) 
{
    char *type, *from, *domain;
    type = xmpp_stanza_get_type(presence);
    from = xmpp_stanza_get_attribute(presence, "from");

    domain = xmpp_jid_domain(from);
    if(strcmp(domain, "nodebus.com")) { //not a buddy from nodebus.com
        return;
    }
    zfree(domain);
    
    if(!type || strcmp(type, "available") ==0) { //available
        //send events
        int i = 0;
        sds output = sdsempty();
        const char *key;
        Event *event;
        //FIXME LATER
        char *vector[1024];
        int vectorlen = 0;
        hash_iterator_t *iter = hash_iter_new(smarta.events);
        while((key = hash_iter_next(iter))) {
            event = hash_get(smarta.events, key);
            if(strcmp(event->status, "OK")) {
                vector[vectorlen++] = sdscatprintf(sdsempty(),
                    "%s %s - %s\n", key, event->status, event->subject);
                if(vectorlen >= 1024) break;
            }
        }
        hash_iter_release(iter);
        if(vectorlen == 0)  return;
        sortlines(vector, vectorlen);
        for(i = 0; i < vectorlen; i++) {
            output = sdscat(output, vector[i]);
            sdsfree(vector[i]);
        }

        xmpp_send_message(smarta.stream, from, output);
        
        sdsfree(output);
    }

}

static void command_handler(XmppStream *stream, XmppStanza *stanza) 
{
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

    xmpp_send_message(smarta.stream, xmpp_stanza_get_attribute(stanza, "from"), output);
	
	sdsfree(output);
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

static int strcompare(const void *s1, const void *s2) 
{
    return strcmp(*(const char **)s1, *(const char **)s2);
}

static void sortlines(void *lines, unsigned int len)
{
    qsort(lines, len, sizeof(char *), strcompare);
}

static sds execute(char *incmd)
{
    char buf[1024];
    Command *command;
    sds output = sdsempty();
    if(strcmp(incmd, "show events") == 0) {
        int i = 0;
        const char *key;
        Event *event;
        //FIXME LATER
        char *vector[1024];
        int vectorlen = 0;
        hash_iterator_t *iter = hash_iter_new(smarta.events);
        while((key = hash_iter_next(iter))) {
            event = hash_get(smarta.events, key);
            vector[vectorlen++] = sdscatprintf(sdsempty(), "%s %s - %s\n", 
                    key, event->status, event->subject);
            if(vectorlen >= 1024) break;
        }
        hash_iter_release(iter);
        if(vectorlen == 0) {
            output = sdscat(output, "no events");
            return output;
        }
        sortlines(vector, vectorlen);
        for(i = 0; i < vectorlen; i++) {
            output = sdscat(output, vector[i]);
            sdsfree(vector[i]);
        }
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

static void smarta_run() {
    aeSetBeforeSleepProc(smarta.el, before_sleep);
    aeMain(smarta.el);
    aeDeleteEventLoop(smarta.el);
}

static int smarta_cron(struct aeEventLoop *eventLoop,
    long long id, void *clientData) {
    return 1000;
}

static void sched_checks() {
    long taskid;
    int delay = 0;
    listNode *node;
    Sensor *sensor;
    listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        delay = (random() % 300) * 1000;
        sensor = (Sensor *)node->value;
        logger_debug("sched", "schedule sensor '%s' after %d seconds", 
            sensor->name, delay/1000);
        taskid = aeCreateTimeEvent(smarta.el, delay, check_sensor, sensor, NULL);
        sensor->taskid = taskid;
    }
    listReleaseIterator(iter);
}

int check_sensor(struct aeEventLoop *el, long long id, void *clientdata) {
    Sensor *sensor = (Sensor *)clientdata;
    pid_t pid = 0;
    pid = fork();
    if(pid == -1) {
        logger_error("SCHED", "fork error when check %s", sensor->name);
    } else if(pid == 0) { //subprocess
        int len;
        FILE *fp = NULL;
        char output[1024] = {0};
        sds result =sdsempty();
        sds raw_command = sdsnew("cd plugins ; ./");
        Sensor *sensor = (Sensor *)clientdata;
        raw_command = sdscat(raw_command, sensor->command);
        logger_debug("SCHED", "check sensor: '%s'", sensor->name);
        logger_debug("SCHED", "command: '%s'", raw_command);
        fp = popen(raw_command, "r");
        if(!fp) {
            logger_error("failed to open %s", sensor->command);
            exit(0);
        }
        while(fgets(output, 1023, fp)) {
            result = sdscat(result, output);
        }
        if((len = sdslen(result) && is_valid(result)) > 0) {
            sds data = sdscat(sensor->name, " ");
            data = sdscat(data, result);
            anetUdpSend("127.0.0.1", smarta.collectd_port, data, sdslen(data));
            sdsfree(data);
        }
        sdsfree(raw_command);
        sdsfree(result);
        pclose(fp);
        exit(0);
    } else {
        //FIXME: later
    }

    return sensor->period;
}

static int is_valid_event(Event *event) {

    if(!event) return 0;
    if(!event->status) return 0;
    if(!event->sensor) return 0;
    if(!event->subject) return 0;
    return 1;
}

void handle_check_result(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    Event *event;
    char buf[1024] = {0};
    nread = read(fd, buf, 1023);
    XmppStream *stream = (XmppStream *)privdata;
    if(nread <= 0) {
        logger_debug("COLLECTD", "no data");
        return;
    }
    logger_debug("COLLECTD", "RECV: %s", buf);
    if(stream->state == XMPP_STREAM_ESTABLISHED) {
        event = event_parse(buf);
        if(is_valid_event(event)) {
            //Old event will be released by hash_add
            hash_add(smarta.events, event->sensor, event);
            smarta_emit_event(stream, event);
        }
        //event_free(event);
    }
}

static char *event_to_string(Event *event) 
{
    sds s = sdscatprintf(sdsempty(), "%s %s - %s",
        event->sensor, event->status, event->subject);
    if(event->body && sdslen(event->body) > 0) {
        s = sdscatprintf(s, "\n%s", event->body);
    }
    return s;
}

static char *strcatnew(char *s1, char *s2) 
{
    int len1 = strlen(s1);
    int len2 = strlen(s2);
    char *key = zmalloc(len1 + len2 +1);
    memcpy(key, s1, len1);
    memcpy(key+len1, s2, len2); 
    *(key+len1+len2) = '\0'; 
    return key;
}

static int should_emit(XmppStream *stream, char *jid, Event *event) 
{
    int yes;
    char *key, *val, *status;
    key = strcatnew(jid, event->sensor); 
    val = zstrdup(event->status);
    if((status = hash_get(stream->events, key))) {
        if(strcmp(status, event->status)) {
            yes = 1;
        } else {
            yes = 0;
        }
    } else {
        if(strcmp(val, "OK"))  { 
            yes = 1; 
        } else {
            yes = 0;
        }
    }
    hash_add(stream->events, key, val);
    return yes;
}

static void smarta_emit_event(XmppStream *stream, Event *event) 
{
    char *buf;
    listNode *node;
    char *jid, *domain;
    XmppStanza *message, *body, *text;
    listIter *iter = listGetIterator(stream->presences, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        jid = (char *)node->value;
        domain =xmpp_jid_domain(jid); 
        if( !strcmp(domain, "nodebus.com") 
            && should_emit(stream, jid, event) ) {
            buf = event_to_string(event);
            message = xmpp_stanza_tag("message");
            xmpp_stanza_set_type(message, "chat");
            xmpp_stanza_set_attribute(message, "to", jid);

            body = xmpp_stanza_tag("body");
            text = xmpp_stanza_cdata(buf);
            xmpp_stanza_add_child(body, text);

            xmpp_stanza_add_child(message, body);

            xmpp_send_stanza(stream, message);
            xmpp_stanza_release(message);
            sdsfree(buf);
        } else if(!strcmp(domain, "event.nodebus.com") 
            && should_emit(stream, jid, event)) {
            XmppStanza *subject, *subject_text;
            XmppStanza *thread, *thread_text;

            buf = sdsempty();
            buf = sdscat(buf, event->status);
            buf = sdscat(buf, " - ");
            buf = sdscat(buf, event->subject);
            message = xmpp_stanza_tag("message");
            xmpp_stanza_set_type(message, "normal");
            xmpp_stanza_set_attribute(message, "to", jid);
        
            thread = xmpp_stanza_tag("thread");
            thread_text = xmpp_stanza_text(event->sensor);
            xmpp_stanza_add_child(thread, thread_text);
            xmpp_stanza_add_child(message, thread);
            
            subject = xmpp_stanza_tag("subject");
            subject_text = xmpp_stanza_text(buf);
            xmpp_stanza_add_child(subject, subject_text);
            xmpp_stanza_add_child(message, subject);

            body = xmpp_stanza_tag("body");
            text = xmpp_stanza_cdata(event->body);
            xmpp_stanza_add_child(body, text);

            xmpp_stanza_add_child(message, body);

            xmpp_send_stanza(stream, message);
            xmpp_stanza_release(message);
            sdsfree(buf);
        } else if(!strcmp(domain, "metric.nodebus.com")
            && event_has_heads(event)) {
            buf = event_metrics_to_string(event);
            if(buf && sdslen(buf) > 0) {
                message = xmpp_stanza_tag("message");
                xmpp_stanza_set_type(message, "normal");
                xmpp_stanza_set_attribute(message, "to", jid);
                xmpp_stanza_set_attribute(message, "thread", event->sensor);

                body = xmpp_stanza_tag("body");
                text = xmpp_stanza_text(buf);
                xmpp_stanza_add_child(body, text);
                xmpp_stanza_add_child(message, body);

                xmpp_send_stanza(stream, message);
                xmpp_stanza_release(message);
            }
            if(buf) sdsfree(buf);
        }
        zfree(domain);
    }
    listReleaseIterator(iter);
}

static int is_valid(const char *buf) 
{
    if(strncmp(buf, "OK", 2) == 0) return 1;
    if(strncmp(buf, "WARNING", 7) == 0) return 1;
    if(strncmp(buf, "CRITICAL", 8) == 0) return 1;
    return 0;
}

static void create_pid_file(void) {
    FILE *fp = fopen(smarta.pidfile,"w");
    if (fp) {
        fprintf(fp,"%d\n",(int)getpid());
        fclose(fp);
    }
}

static int yesnotoi(char *s) {
    if (!strcasecmp(s,"yes")) return 1;
    else if (!strcasecmp(s,"no")) return 0;
    else return -1;
}

