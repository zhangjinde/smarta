/*
**
** smarta.c - smarta agent main.
**
** Copyright (c) 2011 nodebus.com.
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License version 2 as
** published by the Free Software Foundation.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
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
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "ae.h"
#include "sds.h"
#include "ctl.h"
#include "anet.h"
#include "jid.h"
#include "xmpp.h"
#include "sensor.h"
#include "slave.h"
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

static void smarta_presence_update();

static void sched_sensors(void);

static int smarta_cron(aeEventLoop *eventLoop, 
    long long id, void *clientData);

static int smarta_system_status(aeEventLoop *eventLoop,
    long long id, void *clientData);

static void conn_handler(Xmpp *xmpp, 
    XmppStreamState state); 

static void presence_handler(Xmpp *xmpp,
    Stanza *presence);

static void command_handler(Xmpp *xmpp, 
    Stanza *stanza); 

static void roster_handler(Xmpp *xmpp,
    Stanza *iq);

static void collectd_handler(aeEventLoop *el,
    int fd, void *privdata, int mask);

static int check_sensor(struct aeEventLoop *el,
    long long id, void *clientdata);

static void smarta_emit_status(Xmpp *xmpp, Sensor *sensor);

static sds execute(char *from, char *incmd);

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
    fprintf(stderr,"Usage:  ./smarta [/path/to/smarta.conf]\n"
		"\t./smarta status\n\t./smarta stop\n");
    exit(1);
}

/*
** call in parent process
*/
static void smarta_prepare() 
{
    log_level = LOG_INFO;
    log_file = "var/log/smarta.log";
    smarta.isslave = 0;
    smarta.verbosity = 0;
	smarta.lang = LANG_CN;
    smarta.daemonize = 1;
    smarta.collectd = -1;
    smarta.collectd_port = 0;
    smarta.shutdown_asap = 0;
    smarta.pidfile = "var/run/smarta.pid";
	smarta.sensorno = 1;
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

    smarta.emitted = listCreate();
    smarta.requests = listCreate();
	listSetFreeMethod(smarta.requests, ( void (*)(void *) )reqfree);
    smarta.slaves = listCreate();
	#ifdef __CYGWIN__
	smarta.plugins = listCreate();
	#endif
    smarta.el = aeCreateEventLoop();
    aeCreateTimeEvent(smarta.el, 100, smarta_cron, NULL, NULL);
	aeCreateTimeEvent(smarta.el, 1000, smarta_system_status, NULL, NULL);
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
			sensor->id = smarta.sensorno++; //add a id
            listAddNodeTail(smarta.sensors, sensor);
            state = 0;
        } else if ((state == IN_COMMAND_BLOCK) && !strcasecmp(argv[0], "}") && argc == 1) {
            listAddNodeTail(smarta.commands, command);
            state = 0;
        } else if (!strcasecmp(argv[0],"sensor") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_SENSOR_BLOCK;
            sensor = sensor_new(SENSOR_ACTIVE);
        } else if (!strcasecmp(argv[0],"command") && !strcasecmp(argv[1],"{") && argc == 2) {
            state = IN_COMMAND_BLOCK;
            command = zmalloc(sizeof(Command));
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"name") && argc == 2) {
            if(strchr(argv[1], '@')) {
                smarta.name = sdsdup(argv[1]);
            } else {
                smarta.name = sdscat(sdsnew(argv[1]), "@nodebus.com");
            }
            smarta.server = jid_domain(smarta.name);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"server") && argc == 2) {
            if(smarta.server) {
                zfree(smarta.server);
            }
            smarta.server = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"apikey") && argc == 2) {
            smarta.apikey = zstrdup(argv[1]);
        } else if ((state == IN_SMARTA_BLOCK) && !strcasecmp(argv[0],"lang") && argc == 2) {
			if(strcmp(argv[1], "cn") == 0) {
				smarta.lang = LANG_CN;
			} else {
				smarta.lang = LANG_EN;	
			}
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
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "name") && argc >= 2) {
            sensor->name = sdsjoin(argv+1, argc-1);
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "period") && argc == 2) {//deprecated later
            sensor->interval = atoi(argv[1]) * 60 * 1000;
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "interval") && argc == 2) {
            sensor->interval = atoi(argv[1]) * 60 * 1000;
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "attempts") && argc == 2) {
            sensor->max_attempts = atoi(argv[1]);
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "attempt") && !strcasecmp(argv[1], "interval") && argc == 3) {
            sensor->attempt_interval = atoi(argv[2]) * 60 * 1000;
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "nagios") && argc == 1) {
            sensor->nagios= 1;
        } else if ((state == IN_SENSOR_BLOCK) && !strcasecmp(argv[0], "command") && argc >= 2) {
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
	Plugin *retplugin = NULL;
	listIter *iter = listGetIterator(smarta.plugins, AL_START_HEAD);
	while((node = listNext(iter)) != NULL) {
		Plugin *plugin = (Plugin *)node->value;
		if(!strcmp(plugin->name, name)) {
			retplugin = plugin;
			break;
		}
	}
	listReleaseIterator(iter);
	return retplugin;
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
	
	if(argc == 1) {
        smarta_config("smarta.conf");
	} else if (argc == 2) {
        if (strcmp(argv[1], "-v") == 0 ||
            strcmp(argv[1], "--version") == 0) {
			version();
		}
        if (strcmp(argv[1], "-h") == 0 ||
            strcmp(argv[1], "--help") == 0) {
			usage();
		}
		if(strcmp(argv[1], "status") == 0) {
			smarta_ctl_status();
			exit(0);
		}
		if(strcmp(argv[1], "stop") == 0) {
			smarta_ctl_stop();
			exit(0);
		}
        smarta_config(argv[1]);
    } else {
        usage();
    } 

    if(pidfile_existed()) {
        fprintf(stderr, "ERROR: %s is existed, kill it first.\n", smarta.pidfile);
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

    sched_sensors();

    smarta_run();

    return 0;
}

static void smarta_xmpp_connect(void) 
{
    /* create xmpp */
	Xmpp *xmpp = NULL;
    smarta.xmpp = xmpp = xmpp_new(smarta.el);
    xmpp_set_jid(xmpp, smarta.name);
    xmpp_set_pass(xmpp, smarta.apikey);
    if(smarta.server) {
        xmpp_set_server(xmpp, smarta.server);
    }

    if(smarta.slaveip) {
        xmpp_set_server(xmpp, smarta.slaveip);
        xmpp_set_port(xmpp, smarta.slaveport);
    }

    /* xmpp connect */
    if(xmpp_connect(smarta.xmpp) < 0) {
        logger_error("SMARTA", "xmpp connect failed.");
        exit(-1);
    }

    xmpp_add_conn_callback(xmpp, (conn_callback)conn_handler);
    
    xmpp_add_presence_callback(xmpp, (presence_callback)presence_handler);
    
    xmpp_add_message_callback(xmpp, (message_callback)command_handler);

    xmpp_add_iq_ns_callback(xmpp, "nodebus:iq:roster", (iq_callback)roster_handler);
}

static void smarta_collectd_start(void)
{
    int ret = -1;
    struct sockaddr_in sa;
	socklen_t size = sizeof(sa);

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

    aeCreateFileEvent(smarta.el, smarta.collectd, AE_READABLE, collectd_handler, smarta.xmpp);
}

static void smarta_proxy_start(void) 
{
//    smarta.proxyfd = anetTcpServer(smarta.neterr, smarta.proxyport, NULL);
//    if(smarta.proxyfd <= 0) {
//        logger_error("SMARTA", "open proxy socket %d. err: %s",
//            smarta.proxyport, smarta.neterr);
//        exit(-1);
//    }
//    logger_info("SMARTA", "proxy on port %d", smarta.proxyport);
//    aeCreateFileEvent(smarta.el, smarta.proxyfd, AE_READABLE, proxy_accept_handler, NULL);
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

static void conn_handler(Xmpp *xmpp, XmppStreamState state) 
{
    if(state == XMPP_STREAM_DISCONNECTED) {
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
		int c;
        FILE *fp;
		int len = 0;
        char output[1024] = {0};
        fp = popen("bin/show_cfg", "r");
        if(fp) {
			while( ((c = fgetc(fp)) != EOF) && len < 1023 ) {
				output[len++] = c;
			}
			xmpp_send_body(xmpp, "info@status.nodebus.com", output);
			pclose(fp);
        }else {
            logger_error("SMARTA", "failed to open bin/show_cfg.");
		}
        logger_info("SMARTA", "session established.");
        logger_info("SMARTA", "smarta is started successfully.");
    } else {
        //IGNORE
    }
}

static void roster_handler(Xmpp *xmpp, Stanza *iq) 
{
    Buddy *buddy;
    Stanza *presence;
    Stanza *query, *item;
    char *from, *jid, *type, *sub;

    type = stanza_get_type(iq);
    from = stanza_get_attribute(iq, "from");

    if (strcmp(type, "error") == 0) {
        logger_error("XMPP", "error roster stanza.");
        return;
    }

    if(!from || strcmp(from, "status.nodebus.com")) {
        logger_error("XMPP", "invalid from.");
        return;
    }

	query = stanza_get_child_by_name(iq, "query");
	for (item = stanza_get_children(query);
        item; item = stanza_get_next(item)) {
        jid = stanza_get_attribute(item, "jid");
        sub = stanza_get_attribute(item, "subscription");
        if(strcmp(sub, "follow") == 0) {
            buddy = buddy_new();
            buddy->jid = zstrdup(jid);
            buddy->sub = SUB_BOTH;
            logger_info("SMARTA", "%s followed this node.", jid);
            hash_add(xmpp->roster, buddy->jid, buddy);
			//FIXME:
            presence = stanza_tag("presence");
            stanza_set_type(presence, "subscribe");
            stanza_set_attribute(presence, "to", jid);
            xmpp_send_stanza(xmpp, presence);
            stanza_release(presence);
        } else if(strcmp(sub, "unfollow") == 0) {
            logger_info("SMARTA", "%s unfollowed this node.", jid);
            int i = 0, j = 0;
            listIter *iter;
            listNode *node;
            listNode *nodes[listLength(xmpp->presences)];
            iter = listGetIterator(xmpp->presences, AL_START_HEAD);
            while((node = listNext(iter))) {
                if(strncmp((char *)node->value, jid, strlen(jid)) == 0) {
                    nodes[i++] = node;
                }
            }
            listReleaseIterator(iter);
            for(j = 0; j < i; j++) {
                listDelNode(xmpp->presences, nodes[j]);
            }
            hash_drop(xmpp->roster, jid);
        } else {
            logger_warning("XMPP", "unknown sub: '%s'", sub);
        }
    }
}

static void presence_handler(Xmpp *xmpp, Stanza *presence) 
{
    Stanza *stanza;
	sds phrase = NULL;
    char *type, *from, *domain;
    type = stanza_get_type(presence);
    from = stanza_get_attribute(presence, "from");

    domain = jid_domain(from);
    if(strcmp(domain, "nodebus.com")) { //not a buddy from nodebus.com
		zfree(domain);
        return;
    }
    
    if(!type || strcmp(type, "available") ==0) { //available
        //send events
        int i = 0;
        sds output = sdsempty();
        Status *status;
        //FIXME LATER
        int vlen = 0;
        char *vector[1024];

		listNode *node;
		listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
		while((node = listNext(iter)) != NULL) {
			status = ((Sensor *)node->value)->status;
			if(status && status->code > STATUS_OK) {
				phrase = i18n_phrase(smarta.lang, status);
                vector[vlen++] = sdscatprintf(sdsempty(), 
					"\n%s - %s\n", phrase, status->title);
				sdsfree(phrase);
                if(vlen >= 1024) break;
			}
		}
		listReleaseIterator(iter);

        if(vlen == 0)  return;
        sortlines(vector, vlen);
        for(i = 0; i < vlen; i++) {
            output = sdscat(output, vector[i]);
            sdsfree(vector[i]);
        }

        xmpp_send_body(smarta.xmpp, from, output);

        sdsfree(output);
    } else if(strcmp(type, "probe") == 0) {
        stanza = stanza_tag("presence");
        xmpp_send_stanza(xmpp, stanza);
        stanza_release(stanza);
    }

	zfree(domain);
}

static void command_handler(Xmpp *xmpp, Stanza *stanza) 
{
    sds output;
	char *from, *incmd;
	
	if(!stanza_get_child_by_name(stanza, "body")) return;
	if(!strcmp(stanza_get_attribute(stanza, "type"), "error")) return;
	
	from = stanza_get_attribute(stanza, "from");
	incmd = stanza_get_text(stanza_get_child_by_name(stanza, "body"));

    if(!strlen(incmd)) return;

    output = execute(from, incmd);

    if(!output) return;

    if(!sdslen(output)) {
        sdsfree(output);
        return;
    }

    xmpp_send_body(smarta.xmpp, from, output);
	
	sdsfree(output);
}

static Command *find_command(char *usage)
{
    listNode *node;
	Command *retcmd = NULL;
    listIter *iter = listGetIterator(smarta.commands, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        Command *cmd = (Command *)node->value;
        if(!strcmp(cmd->usage, usage)) {
			retcmd = cmd;
			break;
        }
    }
    listReleaseIterator(iter);
    return retcmd;
}

static int strcompare(const void *s1, const void *s2) 
{
    return strcmp(*(const char **)s1, *(const char **)s2);
}

static void sortlines(void *lines, unsigned int len)
{
    qsort(lines, len, sizeof(char *), strcompare);
}

static sds execute(char *from, char *incmd)
{
	int c = 0;
	int count = 0;
    char buf[1024] = {0};
    Command *command;
    sds output = sdsempty();
    if(strcmp(incmd, "show sensors") == 0) {
		char *s;
		char *tag;
		struct tm * t;	
		Sensor *sensor = NULL;
		Status *status = NULL;
		listNode *node = NULL;
		listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
		while((node = listNext(iter)) != NULL) {
			sensor = (Sensor *)node->value;
			status = sensor->status;
			tag = (sensor->type == SENSOR_PASSIVE) ? "P" : "";
			output = sdscatprintf(output, "\n%d. %s#%s", 
				sensor->id, tag, sensor->name);
			if(status) {
				t = localtime(&sensor->time);
				s = i18n_status(smarta.lang, status->code);
                output = sdscatprintf(output, "@%02d:%02d %s - %s\n",
					t->tm_hour, t->tm_min, s, status->title);
			} else {
				output = sdscat(output, "\n");
			}
		}
		listReleaseIterator(iter);
	} else if(strcmp(incmd, "show events") == 0) {
        int i = 0;
		char *tag;
		Sensor *sensor;
        Status *status;
		sds phrase = NULL;
        int vlen = 0;
        char *vector[1024];

		listNode *node;
		listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
		while((node = listNext(iter)) != NULL) {
			sensor = (Sensor *)node->value;
			status = sensor->status;
			if(status && status->code > STATUS_OK) {
				phrase = i18n_phrase(smarta.lang, status);
				tag = (sensor->type == SENSOR_PASSIVE) ? "P" : "";
                vector[vlen++] = sdscatprintf(sdsempty(), 
					"\n%s%s - %s\n", tag, phrase, status->title);
				sdsfree(phrase);
                if(vlen >= 1024) break;
			}
		}
		listReleaseIterator(iter);

        if(vlen == 0) {
            output = sdscat(output, "no events");
            return output;
        }
        sortlines(vector, vlen);
        for(i = 0; i < vlen; i++) {
            output = sdscat(output, vector[i]);
            sdsfree(vector[i]);
        }
    } else if(strcmp(incmd, "help") == 0 || 
		strcmp(incmd, "?") == 0) {
        if(smarta.cmdusage) {
            output = sdscat(output, smarta.cmdusage);
        } else {
            listNode *node;
            output = sdscatprintf(output, "Smarta %s, available commands:\n"
				"show sensors\nshow events\n", SMARTA_VERSION);
            listIter *iter = listGetIterator(smarta.commands, AL_START_HEAD);
            while((node = listNext(iter)) != NULL) {
                command = (Command *)node->value;
                output = sdscatprintf(output, "%s\n", command->usage);
            }
            listReleaseIterator(iter);
            smarta.cmdusage = sdsdup(output);
        }
	}else if( (command = find_command(incmd) )) {
		//FIXME: not work.
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
			int result;
			Request *req = reqnew(smarta.seqno++, from, command);
			result = reqcall(req, smarta.collectd_port);
			if(result >= 0) {
				listAddNodeTail(smarta.requests, req);
			}
        #endif
    } else {
		FILE *fp = fopen("var/data/status", "r");
		if(fp) {
            output = sdscatprintf(output, "command not found, try 'help' or '?'.\n\n"
				"Smarta %s, system current status:\n\n", SMARTA_VERSION);
			while( ((c = fgetc(fp)) != EOF) && count < 1023 ) {
				buf[count++] = c;
			}
			buf[count] = '\0';
			output = sdscat(output, buf);
			fclose(fp);
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
    if(smarta.xmpp->prepare_reset == 1) {
        logger_debug("SMARTA", "before sleep... reset parser");
        parser_reset(smarta.xmpp->parser);
        smarta.xmpp->prepare_reset = 0;
    }
}

static void smarta_run() {
    aeSetBeforeSleepProc(smarta.el, before_sleep);
    aeMain(smarta.el);
    aeDeleteEventLoop(smarta.el);
}

static int smarta_cron(aeEventLoop *eventLoop,
    long long id, void *clientData) {
    if(smarta.shutdown_asap) {
        //TODO: ok???
		logger_info("SMARTA", "shutdown.");
        aeStop(smarta.el);
        if(smarta.daemonize) {
            unlink(smarta.pidfile);
        }
    }
    return 1000;
}

static int smarta_system_status(aeEventLoop *eventLoop,
    long long id, void *clientData) {
    pid_t pid = 0;
    pid = fork();
    if(pid == -1) {
        logger_error("SCHED", "fork error when get system status");
    } else if(pid == 0) { //subprocess
        char *cmd = "bin/show_status > var/data/status";
		int status = system(cmd);
		exit(status);
    } else {
        //smarta process
    }
    return 60000;
}

static void sched_sensors() {
    long taskid;
    int delay = 0;
    Sensor *sensor;
    listNode *node;
    listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        sensor = (Sensor *)node->value;
		if(sensor->type == SENSOR_ACTIVE) {
			delay = (random() % 300);
			logger_info("SCHED", "schedule sensor '%s' after %d seconds",
				sensor->name, delay);
			taskid = aeCreateTimeEvent(smarta.el, delay*1000, check_sensor, sensor, NULL);
			sensor->taskid = taskid;
		}
    }
    listReleaseIterator(iter);
}

int check_sensor(struct aeEventLoop *el, long long id, void *clientdata) {
    Sensor *sensor = (Sensor *)clientdata;
#ifdef __CYGWIN__ //FIXME: not work now
    int i,argc;
    sds *argv;
    Plugin *plugin;
    argv = sdssplitargswithquotes(sensor->command, &argc);
    int size;
	int status;
    char result[4096] = {0};
    sdstolower(argv[0]);
    plugin = find_plugin(argv[0]);
    logger_info("SCHED", "sched sensor: %s", sensor->name);
	if(plugin) {
		logger_debug("SCHED", "find plugin:%s", argv[0]);
	    if( (status = plugin->check(argc-1, argv+1, result, &size)) >= 0 ) {
	        sds data = sdscatprintf(sdsempty(), "Sensor/%d %d %s\n%s",
				sensor->id, status, sensor->name, result);
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
	sensor_check(sensor, smarta.collectd_port);
#endif
    return AE_NOMORE;
}

Sensor *smarta_find_sensor_by_name(char *name)
{
	listNode *node;
	Sensor *sensor, *retsensor = NULL;
	listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
	while((node = listNext(iter)) != NULL) {
		sensor =(Sensor *)node->value; 
		if( !strcmp(sensor->name, name) ) {
			retsensor = sensor;
			break;
		}
	}
	listReleaseIterator(iter);
	return retsensor;
}

Sensor *smarta_find_sensor_by_id(int id)
{
	listNode *node;
	Sensor *sensor = NULL;
	listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
	while((node = listNext(iter)) != NULL) {
		if( ((Sensor *)node->value)->id == id ) {
			sensor = (Sensor *)node->value;
			break;
		}
	}
	listReleaseIterator(iter);
	return sensor;
}

static listNode *smarta_find_request(int reqid)
{
	Request *req;
	listIter *iter;
	listNode *node, *reqnode = NULL;
	iter = listGetIterator(smarta.requests, AL_START_HEAD);
	while((node = listNext(iter)) != NULL) {
		req = (Request *)node->value;
		if(req->id == reqid) {
			reqnode = node;
			break;
		}
	}
	listReleaseIterator(iter);
	return reqnode;
}

static void handle_sensor_result(Xmpp *xmpp, char *buf)
{
	int id = -1;
	int interval;
	char name[1024];
    Sensor *sensor;
	Status *status;
	char *ptr = buf;
	if(*buf == '$') {//passive
		ptr = sensor_parse_name(buf, name);
	} else if(isdigit(*buf)) {//active
		ptr = sensor_parse_id(buf, &id);
	}	
	if(!ptr) return;

	if(id == -1) { //passive 
		sensor = smarta_find_sensor_by_name(name);
		if(!sensor) {
			sensor = sensor_new(SENSOR_PASSIVE);
			sensor->id = smarta.sensorno++;
			sensor->name = sdsnew(name);
			listAddNodeTail(smarta.sensors, sensor);
		}
	} else { //active
		sensor = smarta_find_sensor_by_id(id);
		if(sensor) {
			sensor->taskid = 0;
			sensor->running = 0;
			sensor->check_finish_at = time(NULL);
		}
	}

	if(!sensor) return;

	interval = sensor->interval;

	status = sensor_parse_status(ptr);

	if(!status) { 
		logger_warning("SENSOR", "failed to parse status:\n%s", buf);
		//reschedule
		sensor->taskid = aeCreateTimeEvent(smarta.el, 
			interval*1000, check_sensor, sensor, NULL);
		return;
	}

	interval = sensor_set_status(sensor, status);

	if(xmpp->state == XMPP_STREAM_ESTABLISHED) {
		if(sensor->type == SENSOR_ACTIVE) {
			smarta_presence_update();
		}
		logger_debug("STATUS", "name: %s, attempts: %d, type: %d, code: %d",
			sensor->name, sensor->current_attempts, status->type, status->code);
		if(status->type == STATUS_PERMANENT) {
			smarta_emit_status(xmpp, sensor);
		}
	}
	//reschedule
	sensor->taskid = aeCreateTimeEvent(smarta.el, 
		interval, check_sensor, sensor, NULL);
}

static void handle_command_reply(Xmpp *xmpp, char *buf)
{
	int id;
	char *ptr;
	char *reply;
	Request *req;

	ptr = rep_parse_id(buf, &id);
	if(!ptr) return;

	listNode *node = smarta_find_request(id);
	if(!node) return;

	req = (Request *)node->value;
	reply = rep_parse(ptr);

	if(reply && xmpp->state == XMPP_STREAM_ESTABLISHED) {
		xmpp_send_body(xmpp, req->from, reply);
	}
	listDelNode(smarta.requests, node);
}

static void collectd_handler(aeEventLoop *el, int fd, void *privdata, int mask) {
    int nread;
    char buf[4096] = {0};
    nread = read(fd, buf, 4095);
    Xmpp *xmpp = (Xmpp *)privdata;
    if(nread <= 0) {
        logger_warning("COLLECTD", "no data");
        return;
    }
    logger_debug("COLLECTD", "RECV: \n%s", buf);
	
	if(strncasecmp(buf, "sensor/", 7) == 0) {//sensor 
		handle_sensor_result(xmpp, buf+7);
	} else if(strncasecmp(buf, "reply/", 6) == 0) {
		handle_command_reply(xmpp, buf+6);
	} else {
		logger_debug("COLLECTD", "bad data: \n%s", buf);
	}
}

void smarta_presence_update()
{
	int presence = STATUS_OK;
	Status *status;
    listNode *node;
    listIter *iter = listGetIterator(smarta.sensors, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
		status = ((Sensor *)node->value)->status;
		if(status && status->type == STATUS_PERMANENT 
			&& status->code > presence) {
			presence = status->code;
		}
    }
    listReleaseIterator(iter);
	if(presence != smarta.presence) {
		//send presence
		if(presence > STATUS_INFO) {
			xmpp_send_presence(smarta.xmpp, "xa", 
				i18n_status(smarta.lang, presence));
		} else {
			xmpp_send_presence(smarta.xmpp, "chat", 
				i18n_status(smarta.lang, presence));
		}
	}
	smarta.presence = presence;
}

Emitted *emitted_find(char *jid, int sensor)
{
    listNode *node;
    listIter *iter;
    iter = listGetIterator(smarta.emitted, AL_START_HEAD);
    while((node = listNext(iter))) {
        Emitted *e = (Emitted *)node->value;
        if( (strcmp(e->jid, jid) == 0) 
			&& (e->sensor == sensor) ) {
            return e;
        }

    }
    listReleaseIterator(iter);
    return NULL;
}

Emitted *emitted_new(char *jid, int sensor, int status) 
{
    Emitted *e = zmalloc(sizeof(Emitted));
    e->jid = zstrdup(jid);
    e->sensor = sensor;
    e->status = status;
    return e;
}

static int should_emit(Xmpp *xmpp, char *jid, Sensor *sensor) 
{
    int yes;
    int status = sensor->status->code;
	if(sensor->type == SENSOR_PASSIVE) return 1;

    Emitted *emitted = emitted_find(jid, sensor->id);
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
        emitted = emitted_new(jid, sensor->id, status);
        listAddNodeTail(smarta.emitted, emitted);
    }
    return yes;
}

static void smarta_emit_status(Xmpp *xmpp, Sensor *sensor) 
{
	Message *msg;
    listNode *node;
    sds body = NULL;
    char *jid, *domain;
	Status *status = sensor->status;
	sds phrase = i18n_phrase(smarta.lang, status);
    listIter *iter = listGetIterator(xmpp->presences, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        jid = (char *)node->value;
        domain = jid_domain(jid); 
        if( !strcmp(domain, "nodebus.com") 
            && should_emit(xmpp, jid, sensor) ) {
			 body = sdscatprintf(sdsempty(), "%s - %s",
				phrase, status->title);
			if(status->body && sdslen(status->body) > 0) {
				body = sdscatprintf(body, "\n\n%s", status->body);
			}
			xmpp_send_body(xmpp, jid, body);
            sdsfree(body);
        } else if(!strcmp(domain, "event.nodebus.com") 
            && should_emit(xmpp, jid, sensor)) {
            if(!status->body) {
				body = sdsempty();
            } else {
                body = sdsdup(status->body);
			}
			msg = message_new(jid, body);
            sds subject = sdscatprintf(sdsnew("EVENT/1.0 "), 
				"%d %s\n%s", status->code, phrase, status->title);
			msg->thread = sensor->name;
			msg->subject = subject;
            xmpp_send_message(xmpp, msg);
            message_free(msg);
            sdsfree(subject);
            sdsfree(body);
        } else if(!strcmp(domain, "metric.nodebus.com")
            && status_has_heads(status)) {
            body = status_metrics_string(status);
            if(body && sdslen(body) > 0) {
				msg = message_new(jid, body);
				msg->thread = sensor->name;
				xmpp_send_message(xmpp, msg);
				message_free(msg);
            }
            if(body) sdsfree(body);
        }
        zfree(domain);
    }
    listReleaseIterator(iter);
	sdsfree(phrase);
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

