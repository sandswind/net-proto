#
#

PROJ=		proto
LIBPWD=     $(shell pwd)

CFLAGS+=	-std=gnu99 -Wall -Wextra
CFLAGS+=	-D_GNU_SOURCE -D_DEFAULT_SOURCE
CFLAGS+=	-I../include 

LIBS = $(LIBDIR)/libcmn.a -pthread


NODEBUG=	$(L4NODEBUG)

ifeq ($(NODEBUG),0)
CFLAGS+=	-g -ggdb3 -DDEBUG -fno-omit-frame-pointer
else
CFLAGS+=	-O2
endif

APPNAME=	test
APPOBJS=    test.o
LIBNAME=	lib$(PROJ)
OBJS=		net_utils.o net_detected.o net_http.o net_tls.o net_redis.o net_protocol.o
LIBDIR=		$(LIBPWD)/../lib
$(LIBNAME).la:	LDFLAGS+=	-rpath $(LIBDIR) -version-info 1:0:0

all: lib install

obj: $(OBJS)

lib: $(LIBNAME).la

%.lo: %.c
	libtool --mode=compile --tag CC $(CC) $(CFLAGS) -c $<

$(LIBNAME).la: $(shell echo $(OBJS) | sed 's/\.o/\.lo/g')
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) -o $@ $(notdir $^)

$(APPNAME): $(APPOBJS)
	libtool --mode=link --tag CC $(CC) $(LDFLAGS) $(LIBS) -g -o $(APPNAME) $(notdir $^)

install/%.la: %.la
	libtool --mode=install install -c $(notdir .libs/$@) $(LIBDIR)/$(notdir $@)

install: $(addprefix install/,$(LIBNAME).la)
	libtool --mode=finish $(LIBDIR)

clean:
	libtool --mode=clean rm
	rm -rf .libs *.o *.lo *.la

.PHONY: all obj lib install
