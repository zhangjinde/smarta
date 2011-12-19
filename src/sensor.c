/*
**
** sensor.c - sensor and status functions
**
** Copyright (c) 2011 nodebus.com
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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#include "sds.h"
#include "anet.h"
#include "list.h"
#include "logger.h"
#include "sensor.h"
#include "zmalloc.h"

static char *status_tab[2][4] = 
	{ {"OK", "INFO", "WARNING", "CRITICAL"}, 
	  {"正常", "信息", "告警", "故障"} };

static char *unknow_tab[2] =
	{"UNKNOWN", "未知"};

static char *parse_status_heads(Status *status, char *buf);

static void parse_status_body(Status *event, char *buf);

static void linefree(void *s); 

static sds strsub(char *s, char *o, char *n);

Sensor *sensor_new(int type) 
{
	Sensor *sensor = zmalloc(sizeof(Sensor));
	sensor->id = 0;
	sensor->name = NULL;
	sensor->nagios = 0;
	sensor->type = type;
	sensor->interval = 300*60*1000;
	sensor->max_attempts = 0;
	sensor->current_attempts = 0;
	sensor->attempt_interval = 60*1000;
	sensor->taskid = 0;
	sensor->command = NULL;
	sensor->status = NULL;
	sensor->time = 0;
	sensor->flapping = 0;
	sensor->hiscursor = 0;
	memset(sensor->history, 0,
		sizeof(sensor->history));
	return sensor;
}

Status *status_new()
{
	Status *status = zmalloc(sizeof(Status));
	status->type = STATUS_PERMANENT;
	status->code = STATUS_OK;
	status->thread = NULL;
	status->phrase = NULL;
	status->title = NULL;
	status->heads = NULL;
	status->body = NULL;
	return status;
}

int status_has_heads(Status *status) 
{
	if(status->heads) {
		return listLength(status->heads);       
	}
	return 0;
}

sds status_heads_string(Status *status)
{
    listNode *node;
    sds buf = sdsempty();
    listIter *iter = listGetIterator(status->heads, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        buf = sdscat(buf, (char *)node->value);   
    }
    listReleaseIterator(iter);
    return buf;
}

sds status_metrics_string(Status *status)
{
    listNode *node;
    sds buf = sdsempty();
    listIter *iter = listGetIterator(status->heads, AL_START_HEAD);
    while((node = listNext(iter)) != NULL) {
        if(strncmp(node->value, "metric:", 7) == 0) {
            buf = sdscat(buf, (char *)(node->value + 7));   
        }
    }
    listReleaseIterator(iter);
    return buf;
}

static char *sensor_result_preparse(char *output, char *status)
{
	int i =0;
	char *p = output;
	char *s = status;
	while(p && *p) {
		if(*p == '-') {
			*s = '\0';
			p++; 
			break;
		}
		*s++ = *p++;
	}
	if( !(p && *p) ) return NULL;
	i = strlen(status) - 1; //remove blank space
	while( (i >= 0) && (status[i] == ' ') ) {
		status[i--] = '\0';
	}
	while(p && *p == ' ') p++;	
	return p;
}

void sensor_check(Sensor *sensor, int replyport)
{
    pid_t pid = 0;
    pid = fork();
    if(pid == -1) {
        logger_error("SCHED", "fork error when check %s", sensor->name);
    } else if(pid == 0) { //child process
		int c = 0, len=0;
		int presult = 0;
        FILE *fp = NULL;
		sds data = NULL; 
		char *sep = NULL;
		char *title = NULL;
		sds raw_command = NULL;
        char output[1024] = {0};
		char status[1024] = {0}; 

		setpgid(0, 0);

		//to get pclose result, otherwise got -1 and ECHILD error
		signal(SIGCHLD, SIG_DFL);

		if(sensor->nagios) {
			raw_command = sdsdup(sensor->command);
		} else {
			raw_command = sdscatprintf(sdsempty(), 
				"cd plugins ; ./%s", sensor->command);
		}
        logger_debug("SCHED", "check sensor: '%s', command: '%s'", 
			sensor->name, raw_command);
        fp = popen(raw_command, "r");
        if(!fp) {
            logger_error("SCHED", "failed to open %s", raw_command);
			goto internal_error;
        }
        while( ((c = fgetc(fp)) != EOF) && len < 1023 ) {
			output[len++] = c;
        }
		output[len] = '\0';
		if(sensor->nagios) {
			sep = strchr(output, '|');
			if(sep) {
				*sep = '\0';
				len = sep-output;
			}
		}
        presult = pclose(fp);
        if(presult >= 0){
			if(WEXITSTATUS(presult)==0 && WIFSIGNALED(presult)) {
				presult=128+WTERMSIG(presult);
			} else {
				presult=WEXITSTATUS(presult);
			}
		}
		//nagios unknown = 3
		if(sensor->nagios && presult == 3) presult = -1;
		logger_debug("SCHED", "presult: %d, output: \n%s", presult, output);
		if( !( (presult >= STATUS_OK) && (presult <= STATUS_CRITICAL) && (len > 0) ) ) {
			goto internal_error;
		}
		
		title = sensor_result_preparse(output, status);
		if(!title) {
			logger_warning("SCHED", "no title.");
			goto internal_error;
		}
		if(sensor->nagios) presult++ ;
		data = sdscatprintf(sdsnew("SENSOR/"), "%d %d #%s %s\n%s",
			sensor->id, presult, sensor->name, status, title);
		anetUdpSend("127.0.0.1", replyport, data, sdslen(data));
		sdsfree(data);
        sdsfree(raw_command);
        exit(0);
internal_error:
		data = sdscatprintf(sdsnew("SENSOR/"), "%d %d #%s %s\n%s",
			sensor->id, 127, sensor->name, "UNKNOWN", "Plugin Internal Error!");
		logger_debug("SCHED", "internal error: \n%s", data);
		anetUdpSend("127.0.0.1", replyport, data, sdslen(data));
		if(data) sdsfree(data);
		if(raw_command) sdsfree(raw_command);
        exit(-1);
    } else { //main process
		sensor->running = 1;
		sensor->check_begin_at = time(NULL);
    }
}

char *sensor_parse_name(char *buf, char *retname)
{
	char *ptr = buf;

	if( !(*ptr == '$') ) return NULL;
	ptr++;
	while(ptr && *ptr && (*ptr != '$'))	{
		*retname++ = *ptr++;
	}
	*retname = '\0';
	
	if( ptr && *ptr ) ptr++;
	
	return ptr;
}

char *sensor_parse_id(char *buf, int *id)
{
	int i = 0;
	char *ptr = buf;
	char sid[10] = {0};
	if(!isdigit(*ptr)) {
		*id = -1;
		return ++ptr;
	}
	if(isdigit(*ptr)) {
		while(isdigit(*ptr)) sid[i++] = *ptr++;
		sid[i] = '\0';
		*id = atoi(sid);
		return ptr;
	} 
	
	return NULL;
}

void sensor_flapping_detect(Sensor *sensor) 
{
	//TODO:			
}

static int is_permanent_ok(Status *status) 
{
	return (status->type == STATUS_PERMANENT
			&& status->code == STATUS_OK);
}

static int is_transient_ok(Status *status) 
{
	return (status->type == STATUS_TRANSIENT
			&& status->code == STATUS_OK);
}

static int is_permanent_nonok(Status *status)
{
	return ( status->type == STATUS_PERMANENT && 
			 (status->code > STATUS_OK ||
			 status->code == STATUS_UNKNOWN) );
}

static int is_transient_nonok(Status *status)
{
	return ( status->type == STATUS_TRANSIENT && 
			 (status->code > STATUS_OK ||
			 status->code == STATUS_UNKNOWN) );
}

//FIXME: fsm
static int status_transfer(Sensor *sensor, Status *new)
{
	Status *old = sensor->status;

	int ret = sensor->interval;

	if(is_permanent_ok(old)) {
		if(new->code == STATUS_OK) {
			new->type = STATUS_PERMANENT;
			ret = sensor->interval;
		} else {
			new->type = STATUS_TRANSIENT;
			ret = sensor->attempt_interval;
		}
		sensor->current_attempts = 0;
	} else if(is_transient_ok(old)) {
		if(new->code == STATUS_OK) {
			new->type = STATUS_PERMANENT;
			ret = sensor->interval;
			sensor->current_attempts = 0;
		} else {
			new->type = STATUS_TRANSIENT;
		}
	} else if(is_permanent_nonok(old)) {
		new->type = STATUS_PERMANENT;
		ret = sensor->interval;
	} else if(is_transient_nonok(old)) {
		if(new->code == STATUS_OK) {
			new->type = STATUS_TRANSIENT;
			ret = sensor->attempt_interval;
		} else  {
			if(sensor->current_attempts++ < sensor->max_attempts) {
				new->type = STATUS_TRANSIENT;
				ret = sensor->attempt_interval;
			} else {
				new->type = STATUS_PERMANENT;
				ret = sensor->interval;
			}
		}
	} else {
		logger_error("SENSOR", "assert failure, "
			"status code: %d type: %d", 
			old->type, old->code);
		new->type = STATUS_PERMANENT;
		ret = sensor->interval;	
	}

	return ret;
}

int sensor_set_status(Sensor *sensor, Status *status) 
{
	int interval = sensor->interval;
	if(sensor->status) {
		interval = status_transfer(sensor, status);
		status_free(sensor->status);
	} else {
		if(status->code == STATUS_WARNING) {
			status->type = STATUS_TRANSIENT;
			interval = sensor->attempt_interval;
		}
	}
	sensor->history[sensor->hiscursor] = status->code;
	if(++sensor->hiscursor >= HISTORY_SIZE) 
		sensor->hiscursor = 0;
	time(&sensor->time);
	sensor->status = status;
	return interval;
}

Status *sensor_parse_status(char *buf)
{
	int i=0;
	char code[4]={0};
	char *ptr = buf;
	char *eol;
	Status *status;
	while(*ptr == ' ') ptr++;
	if(!isdigit(*ptr)) return NULL;
	while( (i < 4) && (*ptr != ' ') ) code[i++] = *ptr++;
	if(i == 0) return NULL;
	
	status = status_new();
	status->code = atoi(code);
	
	eol = ++ptr;
	while(eol && *eol && *eol != '\n') eol++;
	if(!eol) goto error;
	status->phrase = sdsnewlen(ptr, eol-ptr);
	
	if(*eol) ptr = ++eol;
	while(eol && *eol && *eol != '\n') eol++;
	if(!eol) goto error;
	status->title = sdsnewlen(ptr, eol-ptr);

	if(*eol) ptr = ++eol;
	if(ptr && *ptr) {
		ptr = parse_status_heads(status, ptr);
	}
	if(ptr && *ptr) {
		parse_status_body(status, ptr);
	}
	return status;
error:
	status_free(status);
	return NULL;
}

static char *parse_status_heads(Status *status, char *buf)
{
    sds line;
    char *p = buf;
    int in_eof = 0;
    if(*buf == '\n') {//no heads
        return ++buf;
    }

    status->heads = listCreate();
    listSetFreeMethod(status->heads, linefree);
    
    while(p && *p) {
        if(*p == '\n') {
            if(in_eof) return ++p;
            line = sdsnewlen(buf, (p-buf)+1); //contain \n
            listAddNodeHead(status->heads, line);
            buf = ++p;
            in_eof = 1;
        } else {
            in_eof = 0;
            p++;
        }
    }
    
    return p;
}

static void parse_status_body(Status *status, char *buf)
{
    int len = 0;
    char *p = buf;
    while(p && *p) p++;
    len = p - buf;
    if(len) status->body = sdsnewlen(buf, len);
}

void status_free(Status *status)
{
	if(status->phrase) sdsfree(status->phrase);
	if(status->title) sdsfree(status->title);
	if(status->thread) sdsfree(status->thread);
	if(status->heads) listRelease(status->heads);
	if(status->body) sdsfree(status->body);
	zfree(status);
}


void sensor_free(Sensor *sensor) 
{
	if(sensor->name) sdsfree(sensor->name);
	if(sensor->command) sdsfree(sensor->command);
	if(sensor->status) status_free(sensor->status);
	zfree(sensor);
}

char *i18n_status(int lang, int status)
{
	if(status > STATUS_CRITICAL) 
		return unknow_tab[lang]; 
	return status_tab[lang][status];
}

sds i18n_phrase(int lang, Status *status)
{
	int code = status->code;
	sds phrase = status->phrase;
	if(lang != LANG_CN) 
		return sdsdup(phrase);
	if(code == STATUS_OK) 
		return strsub(phrase, "OK", "正常");		
	if(code == STATUS_INFO) 
		return strsub(phrase, "INFO", "信息");
	if(code == STATUS_WARNING) 
		return strsub(phrase, "WARNING", "告警");
	if(code == STATUS_CRITICAL) 
		return strsub(phrase, "CRITICAL", "故障");
	return sdsdup(phrase);
}

static void linefree(void *s) {
    sdsfree( (sds) s);
}

//FIXME: better replace?
static sds strsub(sds s, char *o, char *n) {
	char buffer[1024]={0};
	char *c;
	if (!(c = strstr(s, o))) 
		return sdsdup(s);
	strncpy(buffer, s, c-s);  
	buffer[c-s] = 0;
	sprintf(buffer+(c-s), "%s%s", n, c+strlen(o));
	return sdsnew(buffer);
}

