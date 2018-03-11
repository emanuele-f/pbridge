CFLAGS := -std=gnu99 -Wall -fPIC -g

PBRIDGE_LIB = libpbridge.a
SOURCES = pbridge.c utils.c
HEADERS = pbridge.h utils.h includes.h defines.h
OBJS = $(SOURCES:.c=.o)
EXECUTABLES = license
LDLIBS := -lcapstone

.PHONY: all clean examples
all: ${PBRIDGE_LIB} $(EXECUTABLES) examples

examples:
	cd examples && make

clean:
	rm -f *.o ${PBRIDGE_LIB} $(EXECUTABLES)
	cd examples && make clean

$(PBRIDGE_LIB): $(OBJS)
	ar rcs ${PBRIDGE_LIB} $(OBJS)
	cd examples && make clean

license: license.c $(PBRIDGE_LIB)
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $^
