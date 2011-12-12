/*
**
** cmd.h - command headers
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
#ifndef __CMD_H
#define __CMD_H

#include "sds.h"

typedef struct _Command {
    char *usage;
    char *shell;
    #ifdef __CYGWIN__
    void *fun; 
	#endif
} Command;

typedef struct _Request {
	int id;
	sds from;
	Command *cmd;
} Request;

Request *reqnew(int id, char *from, Command *cmd);

int reqcall(Request *req, int replyport);

void reqfree(Request *req);

char *rep_parse_id(char *buf, int *id);

sds rep_parse(char *buf);

#endif

