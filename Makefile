
# Variables
PKGS = fuse libxml-2.0 libcurl
FLAGS ?= $(shell pkg-config ${PKGS} --cflags)
LIBS ?= $(shell pkg-config ${PKGS} --libs) -lpthread
OBJS = boxfs.o boxapi.o boxpath.o boxhttp.o boxopts.o boxjson.o boxcache.o boxutils.o
PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
DEPS = vincenthz/libjson drotiro/libapp
STATIC_LIBS = ./libapp/libapp/libapp.a ./libjson/libjson.a

.PHONY: clean install check_pkg deps

# Targets
boxfs:  PKGS += libapp libjson
boxfs:  check_pkg $(OBJS) 
	@echo "Building  $@"
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

static: check_pkg deps $(OBJS)
	@echo "Building  boxfs (static linking)"
	$(CC) $(FLAGS) $(CFLAGS) $(LDFLAGS) -o boxfs $(OBJS) $(LIBS) $(STATIC_LIBS)


.c.o:
	@echo Compiling $<
	$(CC) $(FLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) *~ boxfs

install: boxfs
	install -s boxfs $(BINDIR)
	install boxfs-init $(BINDIR)

deps:
	@$(foreach i,$(DEPS), (test -d `basename $i` || git clone https://github.com/$i) && make -C `basename $i`; )

# Check required programs
PKG_CONFIG_VER := $(shell pkg-config --version 2>/dev/null)
check_pkg:
ifndef PKG_CONFIG_VER
	@echo " *** Please install pkg-config"
	@exit 1
endif

# Dependencies
# (gcc -MM *.c  -D_FILE_OFFSET_BITS=64)
boxapi.o: boxapi.c boxapi.h boxpath.h boxjson.h boxhttp.h boxopts.h boxutils.h boxcache.h
boxcache.o: boxcache.c boxcache.h boxutils.h
boxfs.o: boxfs.c boxapi.h
boxhttp.o: boxhttp.c boxhttp.h boxapi.h boxopts.h boxutils.h
boxjson.o: boxjson.c boxjson.h
boxopts.o: boxopts.c boxapi.h boxopts.h
boxpath.o: boxpath.c boxpath.h boxjson.h boxapi.h boxopts.h boxutils.h
boxutils.o: boxutils.c boxutils.h
