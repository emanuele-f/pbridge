CFLAGS := -std=gnu99 -Wall -fPIC -g

PBRIDGE_LIB = pbridge.a
SOURCES = pbridge.c utils.c
HEADERS = pbridge.h utils.h includes.h defines.h
OBJS = $(SOURCES:.c=.o)
EXECUTABLES = example target license

.PHONY: all
all: ${PBRIDGE_LIB} $(EXECUTABLES)

clean:
	rm -f *.o ${PBRIDGE_LIB} $(EXECUTABLES)

$(PBRIDGE_LIB): $(OBJS)
	ar rcs ${PBRIDGE_LIB} $(OBJS)

example: example.c $(PBRIDGE_LIB)
	$(CC) $(CFLAGS) -o $@ $^

license: license.c $(PBRIDGE_LIB)
	$(CC) $(CFLAGS) -o $@ $^

target: target.c
	$(CC) $(CFLAGS) -o $@ $^
