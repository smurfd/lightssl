//                                                                            //
// Very simple handshake
#include "vsh.h"

//
// Server main
int main() {
  int s = vsh_init("127.0.0.1", "9998", true);
  sock *cli = NULL;

  if (vsh_listen(s, cli) < 0) {printf("Thread creating problems\n"); exit(0);}
  vsh_end(s);
}
