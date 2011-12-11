/*
**
** smarta.h - smarta main headers
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

#ifndef __SMARTA_H
#define __SMARTA_H

#include "ae.h"
#include "sds.h"
#include "list.h"
#include "hash.h"
#include "xmpp.h"
#include "cmd.h"

typedef struct _Emitted {
    char *jid;
    int sensor; //sensor id
    int status;
} Emitted;

typedef struct _Smarta {
    aeEventLoop *el;
    char *name;
    char *server;
    char *apikey;
	int lang;
	//max status
	int presence; 
    int isslave;
    char *pidfile;
    int collectd;
    int collectd_port;
    int daemonize;
    int shutdown_asap;
    char *masterhost;
    char *masterauth;
    list *sensors;
    list *commands;
	list *requests;
    char *cmdusage;
    list *slaves;
    char *logfile;
    int verbosity;
	//global sequnce no
	int seqno;

    Xmpp *xmpp;

    char neterr[1024];
    //global buddies
    list *buddies;

    //emitted
    list *emitted;
    
    //master/slave
    int masterfd;
    int masterport;
    char *slaveip;
    int slaveport;
    //proxy deprecated
    int proxyfd;
    int proxyport;
    //stats
    int stat_slaves;
	#ifdef __CYGWIN__
	list *plugins;
    #endif
} Smarta;

#endif
