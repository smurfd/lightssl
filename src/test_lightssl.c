//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "lightssl.h"
#include "lighthash.h"

int main(void) {
  char* out;
  const char* in = "smurfd";
  const char* rh = "555cfc37fc24d4971de9b091ef"\
                   "13401b8c5cb8b5b55804da571f"\
                   "b201cbb4fc5d147ac6f5286564"\
                   "56651606546ca42a1070bdfd79"\
                   "d024f3b97dd1bdac7e70f3d1";

  out = (char*) malloc(100);
  strcpy(out, lh_new(in));
  ls_init();

  // the hash of rh and the generated one match?
  assert(lh_verify(out, rh));
  printf("The hashes match!\nRealHash:  %s\nGenerated: %s\n", rh, out);

/*
  // For documentation, client and server example
  // Needs separate files
  struct sockaddr *cli = NULL;
  int s = ls_srv_init("127.0.0.1", "12345");
  int c = ls_srv_listen(s, cli);
  ls_srv_send(c, "hey");

  char *data;
  data = (char*) malloc(1024);
  int cl = ls_cli_init("127.0.0.1", "12345");
  printf("Rec from server: %s %d\n", ls_cli_recv(c, data), cl);
  return 0;
*/
}
