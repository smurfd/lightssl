//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include "lightbig.h"
#include "lightssl.h"
#include "lighthash.h"
#include "lightcrypt.h"

int main(int argc, char **argv) {
  b08 avail[] = {TLSCIPHER};
  b08 select[] = {TLSCIPHERAVAIL};
  b08 compress = TLSCOMPRESSION;

  if (argc == 2 && argv) {
    if (strcmp(argv[1], "server") == 0) {
      struct sockaddr *cli = NULL;
      int s = lightssl_srv_init("127.0.0.1", "12345");

      lightssl_srv_listen(s, cli);
    } else if (strcmp(argv[1], "client") == 0) {
      struct hello *hs_cli;
      struct hello *hs_srv_recv;
      int cl;

      hs_cli = (struct hello*) malloc(sizeof(struct hello));
      lightssl_hs_set_hello(hs_cli, false, TLSVERSION, 1337, avail,
          select, compress, 13371337);
      cl = lightssl_cli_init("127.0.0.1", "12345");
      lightssl_hs_send_hi(cl, false, hs_cli);
      hs_srv_recv = (struct hello*) malloc(sizeof(struct hello));
      lightssl_hs_recv_hi(cl, false, hs_srv_recv);
      lightssl_print_hello(hs_srv_recv);
      lightssl_cli_end(cl);
      free(hs_srv_recv);
      free(hs_cli);
    } else if (strcmp(argv[1], "big") == 0) {
      bigint_t *ac, *ad, *a1;
      big_set("21739871283971298371298371289371298371298371298371298"\
          "371293", &ac);
	     assert(strcmp("21739871283971298371298371289371298371298371298"\
          "371298371293", big_get(ac)) == 0);

      big_set("000123000", &ac);
	    assert(strcmp("123000", big_get(ac)) == 0);

      big_set("000", &ac);
	    assert(strcmp("0", big_get(ac)) == 0);
      big_set("", &ac);
	    assert(strcmp("0", big_get(ac)) == 0);

      big_init(&a1);
      big_set("11111111111111111111111111111111111111111111111111111"\
          "111111000", &ac);
      big_set("33333333333333333333333333333333333333333333333333333"\
          "333333789", &ad);
      big_add(ac, ad, &a1);
	    assert(strcmp("44444444444444444444444444444444444444444444444"\
          "444444444444789", big_get(a1)) == 0);

      big_init(&a1);
      big_set("512", &ac);
      big_set("512", &ad);
      big_add(ac, ad, &a1);
	    assert(strcmp("1024", big_get(a1)) == 0);

      big_init(&a1);
      big_set("2048", &ac);
      big_set("8", &ad);
      big_mul(ac, ad, &a1);
      assert(strcmp("16384", big_get(a1)) == 0);

      big_init(&a1);
      big_set("1024", &ac);
      big_set("16", &ad);
      big_mul(ac, ad, &a1);
	    assert(strcmp("16384", big_get(a1)) == 0);

      big_init(&a1);
      big_set("11111119111231231231111123123131313132344232342342232"\
          "13131564345654345643456543", &ac);
      big_set("92222132222222222222222555555555555555555555555555555"\
          "55555555555555555555555555555555555222212", &ad);
      big_mul(ac, ad, &a1);
      assert(strcmp(
          "102469109581282686939166314728295487301952988652058052952"\
          "481719288409956302066542765911881078061201441897003710374"\
          "267475414724684347478177534235632998732352403188701303331"\
          "16", big_get(a1)) == 0);

      big_init(&a1);
      big_set("92222132222222222222222555555555555555555555555555555"\
          "55555555555555555555555555555555555222212", &ac);
      big_set("11111119111231231231111123123131313132344232342342232"\
          "13131564345654345643456543", &ad);
      big_add(ac, ad, &a1);
      assert(strcmp("92222132222222233333341666786786786666678678686"\
          "86868789978789789778768687119901209901198678755",
          big_get(a1)) == 0);

      big_init(&a1);
      big_set("600", &ac);
      big_set("22", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("578", big_get(a1)) == 0);

      big_init(&a1);
      big_set("578", &ac);
      big_set("22", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("556", big_get(a1)) == 0);

      big_init(&a1);
      big_set("268", &ac);
      big_set("122", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("146", big_get(a1)) == 0);

      big_init(&a1);
      big_set("600", &ac);
      big_set("22", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("27", big_get(a1)) == 0);

      big_init(&a1);
      big_set("10", &ac);
      big_set("3", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("3", big_get(a1)) == 0);

      big_init(&a1);
      big_set("10", &ac);
      big_set("3", &ad);
      big_mod(ac, ad, &a1);
      assert(strcmp("1", big_get(a1)) == 0);

      big_set("100", &ac);
      big_set("63", &ad);
      big_mod(ac, ad, &a1);
      assert(strcmp("37", big_get(a1)) == 0);

      big_init(&a1);
      big_set("10000", &ac);
      big_set("3", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("3333", big_get(a1)) == 0);

      big_init(&a1);
      big_set("97783168081539600805195362086833632135046007441292693"\
          "645370130530607805355644243164623752694677180743783866721"\
          "110324463092282923155195553231284779451989130560241037445"\
          "839460215375857597677332187354870290870376682705989540881"\
          "6333758974", &ac);
      big_set("11579208923731619542357098500868790785326998466564056"\
          "4039457584007908834671663", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("84447192140330707113963255284567556577780406282"\
          "036509216346035040359412893309935964430990836169086995487"\
          "13958186537951429186564022152176310381675487752022988",
          big_get(a1)) == 0);

      big_init(&a1);
      big_set("21421309181006835649040465816202741246597952501982834"\
           "33145230849083913577835915686366844006617905592092527870"\
           "8336624472863330807213114639693592192652215296", &ac);
      big_set("30953315888675608130655810741954660905628439105539661"\
           "42338474990806716218932404114491826217170609713718596845"\
           "01495959243504375826593903825855039186828533479855976344"\
           "36140403892213583177172042680359040655465719887405112118"\
           "17241307384", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("-3095331588867560813065581074195466090562843910"\
          "553966142338474990806716218932382693182645210334960673252"\
          "780642273712994482541775431607585950059552732506975641696"\
          "095003547861333300433039008867643563040734739358874100817"\
          "619624589092088", big_get(a1)) == 0);

      big_init(&a1);
      big_set("40425171602695061535417084613063632117673617386981676"\
          "717219818820800468173859275479075849450530805379691992351"\
          "315868656162334512467400352144711959302632181372814650771"\
          "184515342087210644071835189688768694403662543843232206210"\
          "706", &ac);
      big_set("11579208923731619542357098500868790785326998466564056"\
          "4039457584007908834671663", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("34911859582949198387415456937390592393911583298"\
          "899102349220489672627077936133742737249064266497792495935"\
          "4861526030969502847027596217666059704067859675",
          big_get(a1))==0);

      big_init(&a1);
      big_set("-5", &ac);
      big_set("0", &ad);
      big_add(ac, ad, &a1);
      assert(strcmp("-5", big_get(a1)) == 0);

      big_init(&a1);
      big_set("0", &ac);
      big_set("3", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("-3", big_get(a1)) == 0);

      big_init(&a1);
      big_set("-5", &ac);
      big_set("-5", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("0", big_get(a1)) == 0);

      big_init(&a1);
      big_set("-5", &ac);
      big_set("-5", &ad);
      big_add(ac, ad, &a1);
      assert(strcmp("10", big_get(a1)) == 0);

      big_init(&a1);
      big_set("37286503443888916570650794096490365355343842882500054"\
          "693645072639621059063465", &ac);
      big_set("2", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("18643251721944458285325397048245182677671921441"\
          "250027346822536319810529531732", big_get(a1)) == 0);

      big_init(&a1);
      big_set("65341020041517633956166170261014086368942546761318486551877808671514674964848", &ac);
      big_set("50451069195798561467404814747673821484327437904322077487579775336394159706815", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("1", big_get(a1)) == 0);

      big_init(&a1);
      big_set("1033825265601884880289390121057699170251474247826968447777142314672936145", &ac);
      big_set("65845858570411792093988305973951861612314445177569119332670172212419499", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("967979407031473088195401815083747308639159802649399328444472142460516646",
          big_get(a1)) == 0);

      big_init(&a1);
      big_set("43770350598605623884688535000634442901375162537234380696226857770", &ac);
      big_set("998689668015619845290232924195546972680041504057103240236666837", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("43", big_get(a1)) == 0);

      big_init(&a1);
      big_set("43770350598605623884688535000634442901375162537234380696226857770", &ac);
      big_set("998689668015619845290232924195546972680041504057103240236666837", &ad);
      big_sub(ac, ad, &a1);
      assert(strcmp("42771660930590004039398302076438895928695121033177277455990190933",
          big_get(a1)) == 0);

      big_init(&a1);
      big_set("2131266212947449665405236708312726175673823430288479731233067054703025450131"\
          "593775345799632714362864292670109702312040306070201792271107175502373632466160", &ac);
      big_set("115792089237316195423570985008687907853269984665640564039457584007908834671663", &ad);
      big_div(ac, ad, &a1);
      assert(strcmp("18405974250791985306898387292513446207790260853623256697871975478881952846046",
          big_get(a1)) == 0);

      printf("OK!\n");
    } else if (strcmp(argv[1], "crypt") == 0) {
      lightcrypt_init();
    } else if (strcmp(argv[1], "hash") == 0) {
      const char* in = "smurfd";
      const char* rh = "555cfc37fc24d4971de9b091ef13401b8c5cb8b5b55804da571fb201c"\
          "bb4fc5d147ac6f528656456651606546ca42a1070bdfd79d024f3b97dd1bdac7e70f3d1";
      char *out = (char*) malloc(100);

      strcpy(out, lighthash_new(in));

      // the hash of rh and the generated one match?
      assert(lighthash_verify(out, rh));
      free(out);
      printf("OK!\n");
    }
  }
}
