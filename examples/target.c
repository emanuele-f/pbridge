#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

//#define MULTITHREAD

int callme(const char *str) {
  int rv;

  if(strcmp(str, "Ciao") == 0)
    rv = 1;
  else
    rv = 2;

  puts(str);
  return rv;
}

#ifdef MULTITHREAD
static void* thread_routine(void* args) {
  for (;;) {
    printf("T.%d\n", getpid());
    sleep(1);
  }

  return NULL;
}
#endif

int main(int argc, char **arv) {
#ifdef MULTITHREAD
  pthread_t thread;

  if(pthread_create(&thread, NULL, thread_routine, NULL)) {
    perror("pthread_create");
    return -1;
  }
#endif

  for (;;) {
    printf("%d\n", getpid());
    sleep(1);
  }
  return 0;
}
