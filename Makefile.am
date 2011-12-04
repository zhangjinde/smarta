AUTOMAKE_OPTIONS = subdir-objects

CFLAGS = -g -Wall

expat_CFLAGS = -I src/expat
expat_LIBS = libexpat.a

PARSER_CFLAGS=@PARSER_CFLAGS@
PARSER_LIBS=@PARSER_LIBS@

SMARTA_FLAGS = -I src/ \
	-I src/core \
	-I src/expat \
	-I src/xmpp
SMARTA_LIBS = $(PARSER_LIBS) -lssl

lib_LIBRARIES = libexpat.a

libexpat_a_CFLAGS=-DXML_DTD -DXML_NS -DXML_CONTEXT_BYTES=1024 -DXML_STATIC \
	-I src/expat
libexpat_a_SOURCES=src/expat/xmlparse.c src/expat/xmltok.c src/expat/xmlrole.c

noinst_PROGRAMS = smarta
smarta_SOURCES = src/core/ae.c src/core/tls.c \
    src/core/anet.c src/core/sds.c \
	src/core/list.c src/core/logger.c \
    src/core/md5.c src/core/sha1.c \
	src/core/hash.c src/core/zmalloc.c \
	src/xmpp/sasl.c src/xmpp/jid.c \
	src/xmpp/stanza.c src/xmpp/parser.c \
	src/xmpp/xmpp.c src/event.c \
	src/slave.c src/smarta.c src/ctl.c

smarta_CFLAGS = $(SMARTA_FLAGS)
smarta_LDADD = $(SMARTA_LIBS) 
 
