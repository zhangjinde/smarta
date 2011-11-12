
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>

#include "ae.h"
#include "anet.h"
#include "list.h"
#include "logger.h"
#include "slave.h"
#include "smarta.h"
#include "zmalloc.h"

extern Smarta smarta;

static void proxy_conn_handler(aeEventLoop *el, int fd, void *privdata, int mask);

static int http_request(char *buf, int buflen, char *response, int *len);

void proxy_accept_handler(aeEventLoop *el, int listenfd, void *privdata, int mask)
{
    char ip[128];
    int port, fd;
    fd = anetTcpAccept(smarta.neterr, listenfd, ip, &port);
    if (fd == AE_ERR) {
        logger_warning("PROXY","Accepting client connection: %s", smarta.neterr);
        return;
    }
    logger_info("PROXY", "proxy %s:%d is connected.", ip, port);
    if (aeCreateFileEvent(smarta.el, fd, AE_READABLE,
        proxy_conn_handler, NULL) == AE_ERR) {
        close(fd);
    }
}

static void proxy_conn_handler(aeEventLoop *el, int fd, void *privdata, int mask) 
{ 
    int nread;
    char buf[4096] = {0};
    int length;
    char response[4096];
    nread = read(fd, buf, 4095);
    if(nread <= 0) {
        if(errno == EAGAIN) return;
        logger_info("PROXY", "proxy is disconnected.");
        aeDeleteFileEvent(smarta.el, fd, AE_READABLE);
        return;
    }
    logger_debug("PROXY", "%d data from request: \n%s", nread, buf);
    if(http_request(buf, nread, response, &length) == 0) {
        logger_debug("PROXY", "%d response received: \n%s", length, response);
        anetWrite(fd, response, length);
    }
    aeDeleteFileEvent(smarta.el, fd, AE_READABLE);
    close(fd);
}

static sds host_head(char *buf)
{
    char *start, *end;
    start = strstr(buf, "Host: ");
    if(start == NULL) {
        return NULL;
    }
    start += 6;
    end = strstr(start, "\r\n");
    if(end == NULL) {
        return NULL;
    }
    return sdsnewlen(start, end-start);
}

static int get_host_port(sds hosthead, char *host, int *port)
{
    char *sep;
    printf("hosthead: %s\n", hosthead);
    sep = strstr(hosthead, ":");
    if(sep == NULL) {
        strncpy(host, hosthead, sdslen(hosthead));
        *port = 80;
        return -1;
    }
    printf("hosthead: %s\n", hosthead);
    strncpy(host, hosthead, sep-hosthead);
    printf("host: %s\n", host);
    sscanf(sep+1,"%d", port); 
    printf("port: %d\n", *port);
    return 0;
}

static sds modify_http_status_line(char *buf, sds host) 
{
    char *p;
    sds newbuf;
    sds url = sdsnew("http://");
    url = sdscat(url, host);
    p = strstr(buf, url);
    if(!p) return NULL;
    newbuf = sdsempty();
    newbuf = sdscatlen(newbuf, buf, p - buf);
    newbuf = sdscat(newbuf, p+7+sdslen(host));
    return newbuf;
}

static int http_request(char *buf, int buflen, char *response, int *len) 
{
    int fd;
    int ret;
    int port;
    int nread;
    char err[1024];
    char host[128]={0};
    sds newbuf = NULL;
    sds hosthead = NULL;
    hosthead = host_head(buf);
    if(hosthead == NULL) {
        logger_warning("PROXY", "HOST is null");
        goto error;
    }
    ret = get_host_port(hosthead, host, &port);
    if(ret < 0) {
        logger_error("PROXY", "failed to parse host and port");
        goto error;
    }
    logger_info("PROXY", "connect %s:%d", host, port);
    fd = anetTcpConnect(err, host, port);
    if(fd < 0) {
        logger_error("PROXY", "failed to connet %s:%d", host, port);
        goto error;
    }
    newbuf = modify_http_status_line(buf, hosthead);
    if(newbuf == NULL) {
        logger_error("PROXY", "error to modify status line");
        goto error;
    }
    logger_debug("PROXY", "send http request: \n%s", newbuf);
    ret = anetWrite(fd, newbuf, sdslen(newbuf));
    if(ret < 0) {
        logger_error("PROXY", "failed to send data.");
        goto error;
    }
    
    nread = anetRead(fd, response, 4095);
    *len = nread;
    sdsfree(hosthead);
    sdsfree(newbuf);
    return 0;
error:
    if(hosthead != NULL) sdsfree(hosthead);
    if(newbuf != NULL) sdsfree(newbuf);
    return -1;
}

