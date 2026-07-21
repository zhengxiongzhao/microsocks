# if you want to change/override some variables, do so in a file called
# config.mak, which is gets included automatically if it exists.

prefix = /usr/local
bindir = $(prefix)/bin

PROG = microsocks
SRCS =  sockssrv.c server.c sblist.c sblist_delete.c
OBJS = $(SRCS:.c=.o)

LIBS = -lpthread

# gnu11 (not c99): we now use C11 <stdatomic.h> for the thread "done"
# flag to fix a data race that "volatile int" does not prevent on
# weakly ordered architectures (ARM, MIPS, ...).
CFLAGS += -Wall -std=gnu11

INSTALL = ./install.sh

-include config.mak

all: $(PROG)

install: $(PROG)
	$(INSTALL) -D -m 755 $(PROG) $(DESTDIR)$(bindir)/$(PROG)

clean:
	rm -f $(PROG)
	rm -f $(OBJS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) $(PIC) -c -o $@ $<

$(PROG): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

.PHONY: all clean install

