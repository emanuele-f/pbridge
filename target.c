#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

int callme(const char *str) {
  int rv;

  if(strcmp(str, "Ciao") == 0)
    rv = 1;
  else
    rv = 2;

  puts(str);
  return rv;
}

int main(int argc, char **arv) {
  for (;;) {
    printf("%d\n", getpid());
    sleep(1);
  }
  return 0;
}
