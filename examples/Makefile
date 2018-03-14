CFLAGS := -std=gnu99 -Wall -fPIC -g -I.. -L..
LDLIBS := -lpbridge -lcapstone -lpthread

OBJS = $(SOURCES:.c=.o)
EXECUTABLES = invoke_exported_function target replace_call write_test breakpoint_test

.PHONY: all clean
all: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
