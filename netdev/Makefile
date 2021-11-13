#
#

PROJ=		netdev
LIBPWD=     $(shell pwd)

CFLAGS+=	-std=gnu99 -Wall -Wextra
CFLAGS+=	-D_GNU_SOURCE -D_DEFAULT_SOURCE
#CFLAGS+=	-I../include
CFLAGS+=	-I../include 

CFLAGS+= -I/$HOME/PF_RING/userland/lib \
	-I /$HOME/PF_RING/kernel \
	-I /$HOME/PF_RING/kernel/linux

LIBS = $(LIBDIR)/libcmn.a $(LIBDIR)/libproto.a $(LIBDIR)/libnetdev.a -lpfring -lpcap -pthread


NODEBUG=	$(L4NODEBUG)

ifeq ($(NODEBUG),0)
CFLAGS+=	-g -ggdb3 -DDEBUG -fno-omit-frame-pointer
else
CFLAGS+=	-O2
endif

APPNAME=	test
APPOBJS=    test.o
LIBNAME=	lib$(PROJ)
OBJS=		nd_pfring.o nd_pcap.o nd_xdp.o
LIBDIR=		$(LIBPWD)/../lib
$(LIBNAME).la:	LDFLAGS+=	-rpath $(LIBDIR) -version-info 1:0:0

all: lib test install

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
