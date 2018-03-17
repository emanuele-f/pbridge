CFLAGS := -std=gnu99 -Wall -fPIC -g

PBRIDGE_LIB = libpbridge.a
SOURCES = pbridge.c utils.c
HEADERS = pbridge.h utils.h includes.h defines.h
OBJS = $(SOURCES:.c=.o)
LDLIBS := -lcapstone

.PHONY: all clean examples
all: ${PBRIDGE_LIB} examples

examples:
	cd examples && make

clean:
	rm -f *.o ${PBRIDGE_LIB}
	cd examples && make clean

$(PBRIDGE_LIB): $(OBJS)
	ar rcs ${PBRIDGE_LIB} $(OBJS)
	cd examples && make clean
