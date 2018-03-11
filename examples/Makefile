CFLAGS := -std=gnu99 -Wall -fPIC -g -I.. -L..
LDLIBS := -lpbridge -lcapstone

OBJS = $(SOURCES:.c=.o)
EXECUTABLES = invoke_exported_function target replace_call

.PHONY: all clean
all: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
