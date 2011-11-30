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

#if defined(__CYGWIN__)
	#include "plugin.h"
	#include <windows.h>
#endif

#define CONFIGLINE_MAX 1024
#define IN_SMARTA_BLOCK 1
#define IN_SENSOR_BLOCK 2
#define IN_COMMAND_BLOCK 3

#define HEARTBEAT 120000
#define HEARTBEAT_TIMEOUT 20000

Smarta smarta;

extern int log_level;

extern char *log_file;

static void setupSignalHandlers(void);

static void daemonize(void); 

static void smarta_run(void); 

static void smarta_xmpp_connect(void);

static void smarta_collectd_start(void);

static void smarta_masterd_start(void);

static void smarta_proxy_start(void);

static void sched_checks(void);

static char *cn(int status);

static int smarta_cron(aeEventLoop *eventLoop, 
    long long id, void *clientData);

static int smarta_heartbeat(aeEventLoop *el, 
    long long id, void *clientData); 

static int smarta_heartbeat_timeout(aeEventLoop *el, 
    long long id, void *clientData);

static void smarta_heartbeat_callback(XmppStream *stream, 
    XmppStanza *stanza);

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

#ifndef __CYGWIN__
static int is_valid(const char *buf);
#endif

static sds execute(char *incmd);

static void create_pid_file(void);

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
    smarta.shutdown_asap = 0;
    smarta.pidfile = "smarta.pid";
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

    setupSignalHandlers();

    smarta.events = hash_new(8, (hash_free_func)event_free);
    smarta.emitted = listCreate();
    smarta.slaves = listCreate();
	#ifdef __CYGWIN__
	smarta.plugins = listCreate();
	#endif
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
            if(strchr(argv[1], '@')) {
                smarta.name = sdsdup(argv[1]);
            } else {
                smarta.name = sdscat(sdsnew(argv[1]), "@nodebus.com");
            }
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
            } else {
                log_file = NULL;
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

#ifdef __CYGWIN__

Plugin *find_plugin(char *name)
{
	listNode *node;
	listIter *iter = listGetIterator(smarta.plugins, AL_START_HEAD);
	while((node = listNext(iter)) != NULL) {
		Plugin *plugin = (Plugin *)node->value;
		if(!strcmp(plugin->name, name)) {
			return plugin;
		}
	}
	listReleaseIterator(iter);
	return NULL;
}

void load_plugin_dll(TCHAR *dllName)
{
	HMODULE dll;
	Plugin *plugin;
	PluginInfo info;
    Command *command;
	char dllPath[4096];
	snprintf(dllPath, 4095, "plugins\\%s", dllName);
	dll = LoadLibraryA(dllPath);
	info = (PluginInfo)GetProcAddress(dll,"plugin_info");
	if(info){
		plugin = info();
		logger_info("PLUGIN", "load %s plugin, version: %s, usage: %s",
				plugin->name, plugin->vsn, plugin->usage);
		listAddNodeHead(smarta.plugins, plugin);
        command = zmalloc(sizeof(Command));
        command->usage = zstrdup(plugin->usage);
        command->fun = (void *)plugin->check;    
        listAddNodeHead(smarta.commands, command);
	}
}

void load_plugins(void)
{
	HANDLE hFind=INVALID_HANDLE_VALUE;
	WIN32_FIND_DATA ffd;
	hFind = FindFirstFile("plugins/*.dll", &ffd);
	if (hFind != INVALID_HANDLE_VALUE) {
		do {
			if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
				load_plugin_dll(ffd.cFileName);
			}
		} while (FindNextFile(hFind, &ffd));
		FindClose(hFind);
	}
}

#endif

static void sigtermHandler(int sig) {
    logger_info("SMARTA", "SIGTERM, scheduling shutdown...");
    smarta.shutdown_asap = 1;
}       

static void setupSignalHandlers(void) {
    struct sigaction act;

    /* When the SA_SIGINFO flag is set in sa_flags then sa_sigaction is used.
     * Otherwise, sa_handler is used. */
    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_NODEFER | SA_ONSTACK | SA_RESETHAND;
    act.sa_handler = sigtermHandler;
    sigaction(SIGTERM, &act, NULL);

    return;
}

static int pidfile_existed() {
    if(smarta.pidfile) {
    FILE *fp = fopen(smarta.pidfile, "r");
    return fp ? 1 : 0;
    }
    return 0;
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

    if(pidfile_existed()) {
        fprintf(stderr, "ERROR: smarta.pid existed, kill it first.\n");
        exit(1);
    }

    if(smarta.daemonize) daemonize();

    smarta_init();

    if(smarta.daemonize) create_pid_file();

	#ifdef __CYGWIN__
    //loading dll
    load_plugins();
	#endif

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
        ret = getsockname(smarta.collectd, (struct sockaddr *)&sa, (socklen_t *)&size);
        if(ret < 0) {
            logger_error("SMARTA", "failed to getsockname of collectd.");
            exit(-1);
        }
        logger_info("SMARTA", "collected on %s:%d", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
        smarta.collectd_port = ntohs(sa.sin_port);
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

static int smarta_heartbeat(aeEventLoop *el, long long id, void *clientData) 
{
    char *ping_id;
    XmppStream *stream = (XmppStream *)clientData;

    ping_id = xmpp_send_ping(stream);

    xmpp_add_iq_id_callback(stream, ping_id, smarta_heartbeat_callback);

    smarta.heartbeat_timeout = aeCreateTimeEvent(smarta.el, 
        HEARTBEAT_TIMEOUT, smarta_heartbeat_timeout, stream, NULL);

    sdsfree(ping_id);

    return HEARTBEAT;
}

static int smarta_heartbeat_timeout(aeEventLoop *el, long long id, void *clientData) 
{
    long timeout = (random() % 180) * 1000;
    XmppStream *stream = (XmppStream *)clientData;
    logger_info("XMPP", "heartbeat timeout.");
    xmpp_disconnect(el, stream);
    logger_info("XMPP", "reconnect after %d seconds", timeout/1000);
    aeCreateTimeEvent(el, timeout, xmpp_reconnect, stream, NULL);
    return AE_NOMORE;
}

static void smarta_heartbeat_callback(XmppStream *stream, XmppStanza *stanza)
{
    logger_debug("XMPP", "pong received");
    if(smarta.heartbeat_timeout != 0) {
        aeDeleteTimeEvent(smarta.el, smarta.heartbeat_timeout);
    }
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
        if(smarta.heartbeat != 0) {
            aeDeleteTimeEvent(smarta.el, smarta.heartbeat);
        }
        if(smarta.heartbeat_timeout != 0) {
            aeDeleteTimeEvent(smarta.el, smarta.heartbeat_timeout);
        }
        smarta.heartbeat = aeCreateTimeEvent(smarta.el, HEARTBEAT,
            smarta_heartbeat, stream, NULL);
        logger_info("SMARTA", "session established.");
        logger_info("SMARTA", "smarta is started successfully.");
    } else {
        //IGNORE
    }
}

static void roster_handler(XmppStream *stream, XmppStanza *iq) 
{
    Buddy *buddy;
    XmppStanza *presence;
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
            presence = xmpp_stanza_tag("presence");
            xmpp_stanza_set_type(presence, "subscribe");
            xmpp_stanza_set_attribute(presence, "to", jid);
            xmpp_send_stanza(stream, presence);
            xmpp_stanza_release(presence);
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
    XmppStanza *stanza;
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
            if(event->status != OK) {
                vector[vectorlen++] = sdscatprintf(sdsempty(), "%s %s - %s\n",
                    key, cn(event->status), event->title);
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
    } else if(strcmp(type, "probe") == 0) {
        stanza = xmpp_stanza_tag("presence");
        xmpp_send_stanza(stream, stanza);
        xmpp_stanza_release(stanza);
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
                    key, cn(event->status), event->title);
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
        #ifdef __CYGWIN__
    		int argc;
    		int i = 0;
    		sds *argv;
    		argv = sdssplitargswithquotes(incmd, &argc);
    		int size;
    		char result[4096];
    		Check check=(Check)command->fun;
            if( check(argc-1, argv+1, result, &size) >= 0) {
                output = sdscatlen(output, result, size);
            }
        	for (i = 0; i < argc; i++) {
        		sdsfree(argv[i]);
        	}
        	zfree(argv);
        #else
            FILE *fp = popen(command->shell, "r");
            if(!fp) {
                sdsfree(output);
                return NULL;
            }
            while(fgets(buf, 1023, fp)) {
                output = sdscat(output, buf);
            }
            pclose(fp);
        #endif
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
    if(smarta.shutdown_asap) {
        //TODO: ok???
        aeStop(smarta.el);
        if(smarta.daemonize) {
            unlink(smarta.pidfile);
        }
    }
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
        logger_info("sched", "schedule sensor '%s' after %d seconds",
            sensor->name, delay/1000);
        taskid = aeCreateTimeEvent(smarta.el, delay, check_sensor, sensor, NULL);
        sensor->taskid = taskid;
    }
    listReleaseIterator(iter);
}

int check_sensor(struct aeEventLoop *el, long long id, void *clientdata) {
    Sensor *sensor = (Sensor *)clientdata;
#ifdef __CYGWIN__
    int i,argc;
    sds *argv;
    Plugin *plugin;
    argv = sdssplitargswithquotes(sensor->command, &argc);
    int size;
    char result[4096] = {0};
    sdstolower(argv[0]);
    plugin = find_plugin(argv[0]);
    logger_info("SCHED", "sched sensor: %s", sensor->name);
	if(plugin) {
		logger_debug("SCHED", "find plugin:%s", argv[0]);
	    if( plugin->check(argc-1, argv+1, result, &size) >= 0 ) {
	       sds data = sdscatprintf(sdsempty(), "sensor/1.0 %s\n%s", sensor->name, result);
	       logger_debug("SCHED", "check result: %s", result);
	       anetUdpSend("127.0.0.1", smarta.collectd_port, data, sdslen(data));
	       sdsfree(data);
	    }
	}
	for (i = 0; i < argc; i++){
		sdsfree(argv[i]);
	}
	zfree(argv);
#else
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
            sds data = sdscatprintf(sdsempty(), "sensor/1.0 %s\n%s", sensor->name, result);
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
#endif
    return sensor->period;
}

static int is_valid_event(Event *event) {

    if(!event) return 0;
    if(event->status == UNKNOWN) return 0;
    if(!event->sensor) return 0;
    if(!event->title) return 0;
    return 1;
}

void handle_check_result(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    Event *event;
    char buf[4096] = {0};
    nread = read(fd, buf, 4095);
    XmppStream *stream = (XmppStream *)privdata;
    if(nread <= 0) {
        logger_debug("COLLECTD", "no data");
        return;
    }
    logger_debug("COLLECTD", "RECV: %s", buf);
    if(stream->state == XMPP_STREAM_ESTABLISHED) {
        event = event_feed(buf);
        if(is_valid_event(event)) {
            hash_add(smarta.events, zstrdup(event->sensor), event);
            smarta_emit_event(stream, event);
        }
    }
}

static char *cn(int status) 
{
    if(status == WARNING) {
        return "告警";
    }
    if(status == CRITICAL) {
        return "故障";
    }
    if(status == OK) {
        return "正常";
    }
    return "未知";
}

static char *event_to_string(Event *event) 
{
    sds s = sdscatprintf(sdsempty(), "%s %s - %s",
        event->sensor, cn(event->status), event->title);
    if(event->body && sdslen(event->body) > 0) {
        s = sdscatprintf(s, "\n\n%s", event->body);
    }
    return s;
}

Emitted *emitted_find(char *jid, char *sensor)
{
    listNode *node;
    listIter *iter;
    iter = listGetIterator(smarta.emitted, AL_START_HEAD);
    while((node = listNext(iter))) {
        Emitted *e = (Emitted *)node->value;
        if( (strcmp(e->jid, jid) == 0) && 
            (strcmp(e->sensor, sensor) == 0)) {
            return e;
        }

    }
    listReleaseIterator(iter);
    return NULL;
}

Emitted *emitted_new(char *jid, char *sensor, int status) 
{
    Emitted *e = zmalloc(sizeof(Emitted));
    e->jid = zstrdup(jid);
    e->sensor = zstrdup(sensor);
    e->status = status;
    return e;
}

static int should_emit(XmppStream *stream, char *jid, Event *event) 
{
    int yes;
    int status = event->status;
    Emitted *emitted = emitted_find(jid, event->sensor);
    if(emitted) {
        if(status == emitted->status) {
            yes = 0;
        } else {
            emitted->status = status;
            yes = 1; 
        }
    } else {
        if(status <=0) {
            yes = 0;
        } else {
            yes = 1;
        }
        emitted = emitted_new(jid, event->sensor, status);
        listAddNodeTail(smarta.emitted, emitted);
    }
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
            sds title = sdscatprintf(sdsempty(), "%s %s - %s",
                event->sensor, event_status(event),
                event->title);
            if(event->body) {
                buf = sdsnewlen(event->body, sdslen(event->body));
            }
            XmppStanza *subject, *subject_text;
            XmppStanza *thread, *thread_text;

            message = xmpp_stanza_tag("message");
            xmpp_stanza_set_type(message, "normal");
            xmpp_stanza_set_attribute(message, "to", jid);
        
            thread = xmpp_stanza_tag("thread");
            thread_text = xmpp_stanza_text(event->sensor);
            xmpp_stanza_add_child(thread, thread_text);
            xmpp_stanza_add_child(message, thread);
            
            subject = xmpp_stanza_tag("subject");
            subject_text = xmpp_stanza_text(title);
            xmpp_stanza_add_child(subject, subject_text);
            xmpp_stanza_add_child(message, subject);

            body = xmpp_stanza_tag("body");
            text = xmpp_stanza_cdata(buf);
            xmpp_stanza_add_child(body, text);

            xmpp_stanza_add_child(message, body);

            xmpp_send_stanza(stream, message);
            xmpp_stanza_release(message);
            sdsfree(title);
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

#ifndef __CYGWIN__
static int is_valid(const char *buf) 
{
    if(strncmp(buf, "OK", 2) == 0) return 1;
    if(strncmp(buf, "WARNING", 7) == 0) return 1;
    if(strncmp(buf, "CRITICAL", 8) == 0) return 1;
    return 0;
}
#endif
