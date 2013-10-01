
# Variables
PKGS = fuse libxml-2.0 libcurl libzip libapp
FLAGS = $(shell pkg-config ${PKGS} --cflags) -g ${CFLAGS}
LIBS = $(shell pkg-config ${PKGS} --libs) 
OBJS = boxfs.o boxapi.o boxpath.o boxhttp.o boxopts.o
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

# Targets
boxfs:  check_pkg $(OBJS) 
	@echo "Building  $@"
	$(CC) $(FLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

.c.o:
	@echo Compiling $<
	$(CC) $(FLAGS) -c $< -o $@

.PHONY: clean install check_pkg
	
clean:
	rm -f $(OBJS) *~ boxfs

install: boxfs
	install -s boxfs $(BINDIR)

# Check required programs
PKG_CONFIG_VER := $(shell pkg-config --version 2>/dev/null)
check_pkg:
ifndef PKG_CONFIG_VER
	@echo " *** Please install pkg-config"
	@exit 1
endif

# Dependencies
boxapi.o:	boxapi.c boxapi.h boxpath.h boxhttp.h boxopts.h
boxfs.o:	boxfs.c boxapi.h
boxpath.o:	boxpath.c boxpath.h
boxhttp.o:	boxhttp.c boxhttp.h boxopts.h
boxopts.o:	boxopts.c boxopts.h

