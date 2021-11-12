//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include "lightssl.h"

// dummy
void ls_init() {
  printf("hi from lib\n");
}
