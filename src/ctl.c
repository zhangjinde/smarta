/*
**
** ctl.h - smarta control functions
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
#include <stdlib.h>
#include "smarta.h"

extern Smarta smarta;

void smarta_ctl_status() {
	char pid[20];
	FILE *fp = fopen(smarta.pidfile, "r");
	if(!fp) {
		fprintf(stderr, "Smarta is not running.\n");
		return;
	}
	fgets(pid, 20, fp);
	printf("Smarta is running as pid %s\n", pid);
}

void smarta_ctl_stop() 
{
	int status;
	FILE *fp = fopen(smarta.pidfile, "r");
	if(!fp) {
		fprintf(stderr, "Smarta is not running.\n");
		return;
	}
	sds cmd = sdscatprintf(sdsempty(), "kill `cat %s`", smarta.pidfile);
	status = system(cmd);
	if(status == 0) {
		printf("Smarta is stopped.\n");
	}
	sdsfree(cmd);
}

