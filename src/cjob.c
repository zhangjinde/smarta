
#include <time.h>
#include <ctype.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "cjob.h"
#include "zmalloc.h"

#define TRUE            1

#define FALSE           0

static char *MonthNames[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	NULL
};

static char *DowNames[] = {
	"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun",
	NULL
};

static char *ecodes[] = 
{
	"no error",
	"bad minute",
	"bad hour",
	"bad day-of-month",
	"bad month",
	"bad day-of-week"
};

static int 
get_list(bitstr_t  *bits, /* one bit per flag, default=FALSE */
		int low, int high, /* bounds, impl. offset for bitstr */
		char *names[], /* NULL or *[] of names for these elements */
		char *s); /* arg */ 

static char*
get_range(bitstr_t	*bits,          /* one bit per flag, default=FALSE */
        int			low, 
		int			high,      /* bounds, impl. offset for bitstr */
        char		*names[],      /* NULL or names of elements */
        char		*s);          /* file being read */

static int
set_element(
		bitstr_t  *bits,
        int low,
        int high,
        int number);

static char *
get_number(int  *numptr,        /* where does the result go? */
        int     low,            /* offset applied to result if symbolic enum used */
        char    *names[],       /* symbolic names, if any, for enums */
        char    *s);          /* source */

CronJob *cronjob_new()
{
	CronJob *job = zmalloc(sizeof(CronJob));
	
	memset(job, 0, sizeof(CronJob));

	return job;
}

char *cronjob_err(int e)
{
	return ecodes[e];
}

//# m h dom mon dow
int cronjob_feed(CronJob *job, int argc, sds *argv)
{
	char *s;

	assert(argc == 5);

	//minutes
	s = argv[0];
	if (*s == '*') {
		job->flags |= MIN_STAR;
	}

	if( CRON_OK != get_list(job->minute, FIRST_MINUTE, LAST_MINUTE,
					PPC_NULL, s) ) {
		return CRON_ERR_MINUTE;
	}

	/* hours */
	s = argv[1];
	if(*s == '*') {
		job->flags |= HR_STAR;
	}

	if( CRON_OK != get_list(job->hour, FIRST_HOUR, LAST_HOUR,
					PPC_NULL, s) ) {
		return CRON_ERR_HOUR;
	}

	/* DOM (days of month)
	 */
	s = argv[2];
	if (*s == '*') {
		job->flags |= DOM_STAR;
	}
	if( CRON_OK != get_list(job->dom, FIRST_DOM, LAST_DOM,
				  PPC_NULL, s) ) {
		return CRON_ERR_DOM;
	}

	/* month */
	s = argv[3];
	if( CRON_OK != get_list(job->month, FIRST_MONTH, LAST_MONTH,
				  MonthNames, s) ) {
		return CRON_ERR_MONTH;
	}

	/* DOW (days of week) */
	s = argv[4];
	if (*s == '*') {
		job->flags |= DOW_STAR;
	}
	if( CRON_OK != get_list(job->dow, FIRST_DOW, LAST_DOW,
				  DowNames, s) ) {
		return CRON_ERR_DOW;
	}

	/* make sundays equivilent */
	if (bit_test(job->dow, 0) || bit_test(job->dow, 7)) {
		bit_set(job->dow, 0);
		bit_set(job->dow, 7);
	}
	return CRON_ERR_NONE;
}

//Credits: copy from cron.
int cronjob_ready(CronJob *job) 
{
	time_t now;
	struct tm *tm; 
	int minute, hour, dom, month, dow;

	now = time(NULL);

	tm = localtime(&now);
	
	/* make 0-based values out of these so we can use them as indicies
	 */
	minute = tm->tm_min -FIRST_MINUTE;
	hour = tm->tm_hour -FIRST_HOUR;
	dom = tm->tm_mday -FIRST_DOM;
	month = tm->tm_mon +1 /* 0..11 -> 1..12 */ -FIRST_MONTH;
	dow = tm->tm_wday -FIRST_DOW;

	/* the dom/dow situation is odd.  '* * 1,15 * Sun' will run on the
	 * first and fifteenth AND every Sunday;  '* * * * Sun' will run *only*
	 * on Sundays;  '* * 1,15 * *' will run *only* the 1st and 15th.  this
	 * is why we keep 'job->dow_star' and 'job->dom_star'.  yes, it's bizarre.
	 * like many bizarre things, it's the standard.
	 */
	if (bit_test(job->minute, minute) &&
		bit_test(job->hour, hour) &&
		bit_test(job->month, month) &&
		( ((job->flags & DOM_STAR) || (job->flags & DOW_STAR))
		  ? (bit_test(job->dow,dow) && bit_test(job->dom,dom))
		  : (bit_test(job->dow,dow) || bit_test(job->dom,dom)))) {
		return 1;
	}
	return 0;
}

void cronjob_free(CronJob *job)
{
	zfree(job);
}

static int
get_list(bitstr_t  *bits, /* one bit per flag, default=FALSE */
		int low, int high, /* bounds, impl. offset for bitstr */
		char *names[], /* NULL or *[] of names for these elements */
		char *s) /* arg */ 
{
        int done;

        /* list = range {"," range} */

        /* clear the bit string, since the default is 'off'.  */
        bit_nclear(bits, 0, (high-low+1));

        /* process all ranges */
        done = FALSE;
        while (!done) {
                s = get_range(bits, low, high, names, s);
				if(!s) return CRON_ERR;
                if (*s == ',')
					s++;
                else
					done = TRUE;
        }
        return CRON_OK;
}

static char *
get_range(bitstr_t	*bits,          /* one bit per flag, default=FALSE */
        int			low,
		int			high,      /* bounds, impl. offset for bitstr */
        char		*names[],      /* NULL or names of elements */
        char		*s)          /* file being read */
{
        /* range = number | number "-" number [ "/" number ] */
        int i;

        auto int num1, num2, num3;

        if (*s == '*') {
			/* '*' means "first-last" but can still be modified by /step */
			num1 = low;
			num2 = high;
        } else {
			if ( !(s = get_number(&num1, low, names, s))  ) {
				return NULL;
			}
			if (*s != '-') {
				/* not a range, it's a single number.  */
				if (CRON_OK != set_element(bits, low, high, num1)) 
					return NULL;
				return s;
			} 
			/* eat the dash */
			if (*++s == '\0')
				return NULL;
			/* get the number following the dash
			 */
			s = get_number(&num2, low, names, s);
			if (!s) {
				return NULL;
			}
        }

        /* check for step size
         */
        if (*s == '/') {
			/* eat the slash */
			if (*++s == '\0')
				return NULL;
			/* get the step size -- note: we don't pass the
			 * names here, because the number is not an
			 * element id, it's a step size.  'low' is
			 * sent as a 0 since there is no offset either.
			 */
			s = get_number(&num3, 0, PPC_NULL, s);
			if (*s == '\0' || num3 <= 0)
				return NULL;
        } else {
                /* no step.  default==1.*/
                num3 = 1;
        }

        /* range. set all elements from num1 to num2, stepping
         * by num3.  (the step is a downward-compatible extension
         * proposed conceptually by bob@acornrc, syntactically
         * designed then implmented by paul vixie).
         */
        for (i = num1;  i <= num2;  i += num3)
			if (CRON_OK != set_element(bits, low, high, i))
				return NULL;

        return s;
}

static char *
get_number(int  *numptr,        /* where does the result go? */
        int     low,            /* offset applied to result if symbolic enum used */
        char    *names[],       /* symbolic names, if any, for enums */
        char    *s)          /* source */
{
		
        char    temp[1024], *pc;
        int     ch, len, i, all_digits;

        /* collect alphanumerics into our fixed-size temp array
         */
        pc = temp;
        len = 0;
        all_digits = TRUE;
        while (isalnum(*s)) {
			if (++len >= 1024) {
				return NULL;
			}
			ch = *s++;
			*pc++ = ch;
			if (!isdigit(ch))
                all_digits = FALSE;
        }
        *pc = '\0';
        if (len == 0) {
            return NULL;
        }

        /* try to find the name in the name list
         */
        if (names) {
			for (i = 0; names[i] != NULL; i++) {
				if (!strcasecmp(names[i], temp)) {
					*numptr = i+low;
					return s;
				}
			}
        }

        /* no name list specified, or there is one and our string isn't
         * in it.  either way: if it's all digits, use its magnitude.
         * otherwise, it's an error.
         */
        if (all_digits) {
			*numptr = atoi(temp);
			return s;
        }
        return s;
}

static int
set_element(
		bitstr_t  *bits,
        int low,
        int high,
        int number)
{
	if (number < low || number > high)
		return CRON_ERR;

	bit_set(bits, (number-low));
	return CRON_OK;
}


