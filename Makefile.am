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
smarta_SOURCES = src/smarta.c src/auth.c src/conn.c src/ctx.c \
	src/event.c src/handler.c src/hash.c src/xmpp.c \
	src/jid.c src/md5.c src/sasl.c src/sha1.c \
	src/snprintf.c src/sock.c src/stanza.c \
	src/tls_openssl.c src/util.c src/parser.c \
    src/sched.c src/sds.c src/adlist.c
smarta_CFLAGS = $(SMARTA_FLAGS)
smarta_LDADD = $(SMARTA_LIBS) 

## Tests
TESTS = tests/check_parser
check_PROGRAMS = tests/check_parser
tests_check_parser_SOURCES = tests/check_parser.c
tests_check_parser_CFLAGS = @check_CFLAGS@ $(PARSER_CFLAGS) $(SMARTA_FLAGS) \
	-I$(top_srcdir)/src
tests_check_parser_LDADD = @check_LIBS@ $(SMARTA_LIBS)
