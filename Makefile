FLAGS = `pkg-config fuse --cflags` `xml2-config --cflags` -g
LIBS = `pkg-config fuse --libs` `xml2-config --libs`
OBJS = boxfs.o boxapi.o
BINDIR = /usr/local/bin

.c.o:
	gcc $(FLAGS) -c $< -o $@


boxfs:	$(OBJS)
	gcc -o $@ $(LIBS) $(OBJS)

.PHONY: clean install dist
	
clean:
	rm -f $(OBJS) *~ boxfs

install: boxfs
	cp boxfs $(BINDIR)
	strip $(BINDIR)/boxfs

dist:	boxfs
	cd .. && tar czvf dist/boxfs-`date +%Y%m%d`.tgz boxfs/*.[ch] boxfs/Makefile

