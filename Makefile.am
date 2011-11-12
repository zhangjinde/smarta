AUTOMAKE_OPTIONS = subdir-objects

CFLAGS = -g -Wall

builtin_CFLAGS = -I$(top_srcdir)/expat/lib
builtin_LIBS = libexpat.a

PARSER_CFLAGS=@PARSER_CFLAGS@
PARSER_LIBS=@PARSER_LIBS@

SMARTA_FLAGS = -I$(top_srcdir)
SMARTA_LIBS = $(PARSER_LIBS) -lssl

lib_LIBRARIES = libexpat.a

libexpat_a_CFLAGS=-DXML_DTD -DXML_NS -DXML_CONTEXT_BYTES=1024 -DXML_STATIC \
	-I$(top_srcdir)/expat/lib
libexpat_a_SOURCES=expat/lib/xmlparse.c expat/lib/xmltok.c expat/lib/xmlrole.c

## Examples
noinst_PROGRAMS = smarta
smarta_SOURCES = src/smarta.c \
	src/hash.c src/xmpp.c src/jid.c \
    src/md5.c src/sha1.c src/sasl.c \
	src/stanza.c src/zmalloc.c src/logger.c \
	src/parser.c src/sds.c src/list.c \
    src/ae.c src/anet.c src/slave.c \
    src/event.c src/proxy.c
smarta_CFLAGS = $(SMARTA_FLAGS)
smarta_LDADD = $(SMARTA_LIBS) 


