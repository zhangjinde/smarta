/*
**
** sensor.h - sensor and status headers
**
** Copyright (c) 2011 Ery Lee (ery.lee@gmail.com)
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

#ifndef __SENSOR_H
#define __SENSOR_H

#include "sds.h"
#include "list.h"
#include "time.h"

#include "cjob.h"

//status lang?
#define LANG_EN 0
#define LANG_CN 1

//status type
#define STATUS_TRANSIENT 1
#define STATUS_PERMANENT 2

//status code
#define STATUS_OK 0
#define STATUS_INFO 1
#define STATUS_WARNING 2
#define STATUS_CRITICAL 3
#define STATUS_UNKNOWN -1

//sensor type
#define SENSOR_ACTIVE 1
#define SENSOR_PASSIVE 2

//sensor sched
#define SCHED_PERIOD 0
#define SCHED_CRON 1

//event emitted by sensor
typedef struct _Status {
	//transient or permanent
	int type;
	/*status code */
	int code; 
	/* short description */
	char *phrase;
	/* not use now*/
	char *thread;
    char *title;
    list *heads;
    char *body;
} Status;

#define HISTORY_SIZE 20

#define FLAPPING_RATE 30

typedef struct _Sensor{
	int id;
	//1: true; 0: false
	int nagios;
	//active or passive
	int type;
	//peroid or cron
	int sched_type;
    char *name;
    long interval;
	//schedule
    long taskid;
	int running;
	time_t check_begin_at;
	time_t check_finish_at;
	//attempt
	int max_attempts;
	int current_attempts;
	int attempt_interval;
	//plugin command
    char *command;
	//last status
	Status *status;
	//update time
	time_t time;
	//time period
	TimePeriod *tp;
	//flap detect
	int flapping;
	int hiscursor;
	int history[HISTORY_SIZE];
} Sensor;

Sensor *sensor_new();

void sensor_check(Sensor *sensor, int replyport);

void sensor_free(Sensor *sensor);

Status *status_new();

int status_has_heads(Status *status);

sds status_heads_string(Status *status);

sds status_metrics_string(Status *status);

char *sensor_parse_name(char *buf, char *retname);

char *sensor_parse_id(char *buf, int *id);

void sensor_flapping_detect(Sensor *sensor);

Status *sensor_parse_status(char *buf);

//return next schedule interval
int sensor_set_status(Sensor *sensor, Status *status);

void status_free(Status *status);

char *i18n_status(int lang, int status);

sds i18n_phrase(int lang, Status *status);

#endif

