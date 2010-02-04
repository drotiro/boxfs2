PKGS = fuse libxml-2.0 libcurl
FLAGS = `pkg-config ${PKGS} --cflags` -g ${CFLAGS}
LIBS = `pkg-config ${PKGS} --libs` 
OBJS = boxfs.o boxapi.o boxpath.o boxhttp.o
BINDIR = /usr/local/bin

boxfs:  $(OBJS)
	gcc -o $@ $(LIBS) $(OBJS)

boxapi.o:	boxapi.c boxapi.h boxpath.h boxhttp.h
boxfs.o:	boxfs.c boxapi.h
boxpath.o:	boxpath.c boxpath.h
boxhttp.o:	boxhttp.c boxhttp.h

.c.o:
	gcc $(FLAGS) -c $< -o $@

.PHONY: clean install 
	
clean:
	rm -f $(OBJS) *~ boxfs

install: boxfs
	cp boxfs $(BINDIR)
	strip $(BINDIR)/boxfs

