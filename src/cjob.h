#ifndef __CJOB_H
#define __CJOB_H

#include <bitstring.h>

#include "sds.h"

typedef int time_min;

#define SECONDS_PER_MINUTE 60

#define FIRST_MINUTE    0
#define LAST_MINUTE     59
#define MINUTE_COUNT    (LAST_MINUTE - FIRST_MINUTE + 1)

#define FIRST_HOUR      0
#define LAST_HOUR       23
#define HOUR_COUNT      (LAST_HOUR - FIRST_HOUR + 1)

#define FIRST_DOM       1
#define LAST_DOM        31
#define DOM_COUNT       (LAST_DOM - FIRST_DOM + 1)

#define FIRST_MONTH     1
#define LAST_MONTH      12
#define MONTH_COUNT     (LAST_MONTH - FIRST_MONTH + 1)

/* note on DOW: 0 and 7 are both Sunday, for compatibility reasons. */
#define FIRST_DOW       0
#define LAST_DOW        7
#define DOW_COUNT       (LAST_DOW - FIRST_DOW + 1)

#define PPC_NULL        ((char **)NULL)

#define CRON_OK         0
#define CRON_ERR        (-1)

typedef enum _CronErr {
	CRON_ERR_NONE = 0,
	CRON_ERR_MINUTE,
	CRON_ERR_HOUR,
	CRON_ERR_DOM,
	CRON_ERR_MONTH,
	CRON_ERR_DOW
} CronErr;

typedef struct _CronJob {
	int             sensorid;
	bitstr_t        bit_decl(minute, MINUTE_COUNT);
	bitstr_t        bit_decl(hour,   HOUR_COUNT);
	bitstr_t        bit_decl(dom,    DOM_COUNT);
	bitstr_t        bit_decl(month,  MONTH_COUNT);
	bitstr_t        bit_decl(dow,    DOW_COUNT);
	int             flags;
#define DOM_STAR        0x01
#define DOW_STAR        0x02
#define WHEN_REBOOT     0x04
#define MIN_STAR        0x08
#define HR_STAR         0x10
} CronJob;

CronJob *cronjob_new();

char *cronjob_err(int e);

int cronjob_feed(CronJob *job, int argc, sds *argv);

int cronjob_ready(CronJob *job);

void cronjob_free(CronJob *job);

#endif
