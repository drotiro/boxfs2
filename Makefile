PKGS = fuse libxml-2.0 libcurl
FLAGS = $(shell pkg-config ${PKGS} --cflags) -g ${CFLAGS}
LIBS = $(shell pkg-config ${PKGS} --libs) -lapp -lzip
OBJS = boxfs.o boxapi.o boxpath.o boxhttp.o boxopts.o
PREFIX = /usr/local
BINDIR = $(PREFIX)/bin

boxfs:  $(OBJS)
	@echo "Building  $@"
	@gcc -o $@ $(OBJS) $(LIBS)

boxapi.o:	boxapi.c boxapi.h boxpath.h boxhttp.h boxopts.h
boxfs.o:	boxfs.c boxapi.h
boxpath.o:	boxpath.c boxpath.h
boxhttp.o:	boxhttp.c boxhttp.h boxopts.h
boxopts.o:	boxopts.c boxopts.h

.c.o:
	@echo Compiling $<
	@gcc $(FLAGS) -c $< -o $@

.PHONY: clean install 
	
clean:
	rm -f $(OBJS) *~ boxfs

install: boxfs
	install -s boxfs $(BINDIR)

