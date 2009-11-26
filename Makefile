PKGS = fuse libxml-2.0
FLAGS = `pkg-config ${PKGS} --cflags` -g
LIBS = `pkg-config ${PKGS} --libs` 
OBJS = boxfs.o boxapi.o boxpath.o
BINDIR = /usr/local/bin

boxfs:  $(OBJS)
	gcc -o $@ $(LIBS) $(OBJS)

boxapi.o:	boxapi.c boxapi.h boxpath.h
boxfs.o:	boxfs.c boxapi.h
boxpath.o:	boxpath.c boxpath.h

.c.o:
	gcc $(FLAGS) -c $< -o $@

.PHONY: clean install 
	
clean:
	rm -f $(OBJS) *~ boxfs

install: boxfs
	cp boxfs $(BINDIR)
	strip $(BINDIR)/boxfs

