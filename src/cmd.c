/*
**
** cmd.c - command functions 
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
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#include "cmd.h"
#include "anet.h"
#include "logger.h"
#include "zmalloc.h"

/* why not req_new? I think reqnew is cool.*/
Request *reqnew(int id, char *from, Command *cmd)
{
	Request *p = zmalloc(sizeof(Request));
	p->id = id;
	p->from = sdsnew(from);
	p->cmd = cmd;
	return p;
}

void reqfree(Request *p) 
{
	if(p->from) sdsfree(p->from);
	zfree(p);
}

int reqcall(Request *req, int replyport) 
{
    pid_t pid = 0;
    pid = fork();
	Command *cmd = req->cmd;
    if(pid == -1) {
        logger_error("CMD", "fork error when cmd: %s", cmd->usage);
		return -1;
    } else if(pid == 0) {
		sds reply;
		int c, len=0, presult=0;
		char *sh = cmd->shell;
        char output[1024] = {0};

		//to get pclose result, otherwise got -1 and ECHILD error
		signal(SIGCHLD, SIG_DFL);

        FILE *fp = popen(sh, "r");
        if(!fp) {
            logger_error("CMD", "failed to open %s", sh);
			sds reply = sdscatprintf(sdsnew("REPLY/"), 
				"%d %d %s\nfailed to open '%s'",
				req->id, -1, req->from, sh);
			anetUdpSend("127.0.0.1", replyport, reply, sdslen(reply));
			sdsfree(reply);
            exit(-1);
        }
        while( ((c = fgetc(fp)) != EOF) && len < 1023 ) {
			output[len++] = c;
        }
		output[len] = '\0';
        presult = pclose(fp);
        if(presult >= 0){
			if(WEXITSTATUS(presult)==0 && WIFSIGNALED(presult)) {
				presult=128+WTERMSIG(presult);
			} else {
				presult=WEXITSTATUS(presult);
			}
		}
		if(presult == 127) {
			reply = sdscatprintf(sdsnew("REPLY/"), "%d %d %s\ncommand '%s' not found.",
				req->id, presult, req->from, sh);
		} else {
			reply = sdscatprintf(sdsnew("REPLY/"), "%d %d %s\n%s",
				req->id, presult, req->from, output);
		}	
		logger_debug("CMD", "send cmd reply: %s", reply);
		anetUdpSend("127.0.0.1", replyport, reply, sdslen(reply));
		sdsfree(reply);
        exit(0);
    } else {
        //FIXME: later
    }
	return 0;
}

char *rep_parse_id(char *buf, int *id) 
{
	int i = 0;
	char *p = buf;
	char sid[10] = {0};
	
	if(!isdigit(*p)) return NULL; 
	
	while(isdigit(*p)) sid[i++] = *p++;
	*id = atoi(sid);

	return p;
}

sds rep_parse(char *buf) 
{
	char *p = buf;
	while(p && *p && *p != '\n') p++;
	if(*p == '\n') 
		return sdsnew(p+1);
	return NULL;

}

