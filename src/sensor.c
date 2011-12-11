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
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
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
	sensor->nagios = 0;
	sensor->type = type;
	sensor->period = 300;
	sensor->taskid = 0;
	sensor->status = NULL;
	return sensor;
}

Status *status_new()
{
	Status *status = zmalloc(sizeof(Status));
	status->code = 0;
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
    } else if(pid == 0) { //subprocess
		char *sep = NULL;
		int c = 0, len=0;
		int presult = 0;
        FILE *fp = NULL;
        char output[1024] = {0};
		sds raw_command;
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
            exit(-1);
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
		if( (presult >= STATUS_OK) && (presult <= STATUS_CRITICAL) && (len > 0) ) {
			char *title;
			char status[1024] = {0}; 
			title = sensor_result_preparse(output, status);
			if(title) {
				if(sensor->nagios) presult++ ;
				sds data = sdscatprintf(sdsnew("SENSOR/"), "%d %d #%s %s\n%s",
					sensor->id, presult, sensor->name, status, title);
				anetUdpSend("127.0.0.1", replyport, data, sdslen(data));
				sdsfree(data);
			} else {
				logger_debug("SCHED", "failed to preparse result.");
			}
		}
        sdsfree(raw_command);
        exit(0);
    } else {
        //FIXME: later
    }
}

char *sensor_parse_id(char *buf, int *id)
{
	int i = 0;
	char *ptr = buf;
	char sid[10] = {0};
	if(*ptr == 'p') {
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

void sensor_set_status(Sensor *sensor, Status *status) 
{
	if(sensor->status) {
		status_free(sensor->status);
	}
	sensor->status = status;
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
	while(eol && *buf && *eol != '\n') eol++;
	if(!eol) goto error;
	status->phrase = sdsnewlen(ptr, eol-ptr);
	
	ptr = ++eol;
	while(eol && *buf && *eol != '\n') eol++;
	if(!eol) goto error;
	status->title = sdsnewlen(ptr, eol-ptr);

	ptr = ++eol;
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

