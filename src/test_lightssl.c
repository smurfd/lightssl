//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
      struct hello *hs_cli, *hs_srv_recv;
      int cl;

      hs_cli = malloc(sizeof(struct hello));
      lightssl_hs_set_hello(
        hs_cli, false, TLSVERSION, 1337, avail, select, compress, 13371337);
      cl = lightssl_cli_init("127.0.0.1", "12345");
      lightssl_hs_send_hi(cl, false, hs_cli);
      hs_srv_recv = malloc(sizeof(struct hello));
      lightssl_hs_recv_hi(cl, false, hs_srv_recv);
      lightssl_print_hello(hs_srv_recv);
      lightssl_cli_end(cl);
      free(hs_srv_recv);
      free(hs_cli);
    } else if (strcmp(argv[1], "big") == 0) {
      bigint_t *ac, *ad, *a1;
      int add_t = 5;
      int sub_t = 16;
      int mul_t = 3;
      int div_t = 14;
      int mod_t = 2;
      int hex_t = 1;
      int nrt = add_t + sub_t + mul_t + div_t + mod_t + hex_t;
      char **a = malloc(nrt * MAXSTR);
      char **b = malloc(nrt * MAXSTR);
      char **c = malloc(nrt * MAXSTR);
      char *cc = malloc(MAXSTR);

      big_init_m(3, &ac, &ad, &a1);
      big_alloc_max_m(3, &ac, &ad, &a1);

      // Sanity checks
      cc = "21739871283971298371298371289371298371298371298371298371293";
      big_set(cc, &ac);
      big_resize(&ac, ac->len, ac->len);
      big_assert_str(cc, &ac);
      big_end_m(3, &ac, &ad, &a1);

      // add
      a[0] = "11111111111111111111111111111111111111111111111111111111111000";
      b[0] = "33333333333333333333333333333333333333333333333333333333333789";
      c[0] = "44444444444444444444444444444444444444444444444444444444444789";

      a[1] = "512";
      b[1] = "512";
      c[1] = "1024";

      a[2] = "92222132222222222222222555555555555555555555555555555555555555555"
             "55555555555555555555555222212";
      b[2] = "11111119111231231231111123123131313132344232342342232131315643456"
             "54345643456543";
      c[2] = "92222132222222233333341666786786786666678678686868687899787897897"
             "78768687119901209901198678755";

      a[3] = "-5";
      b[3] = "0";
      c[3] = "-5";

      a[4] = "-5";
      b[4] = "-5";
      c[4] = "-10";

      // mul
      a[5] = "2048";
      b[5] = "8";
      c[5] = "16384";

      a[6] = "1024";
      b[6] = "16";
      c[6] = "16384";

      a[7] = "11111119111231231231111123123131313132344232342342232131315643456"
             "54345643456543";
      b[7] = "92222132222222222222222555555555555555555555555555555555555555555"
             "55555555555555555555555222212";
      c[7] = "10246910958128268693916631472829548730195298865205805295248171928"
             "84099563020665427659118810780612014418970037103742674754147246843"
             "4747817753423563299873235240318870130333116";

      // sub
      a[8] = "600";
      b[8] = "22";
      c[8] = "578";

      a[9] = "578";
      b[9] = "22";
      c[9] = "556";

      a[10] = "268";
      b[10] = "122";
      c[10] = "146";

      a[11] = "3095331588867560813065581074195466090562843910553966142338474990"
              "8067162189324041144918262171706097137185968450149595924350437582"
              "6593903825855039186828533479855976344361404038922135831771720426"
              "8035904065546571988740511211817241307384";
      b[11] = "2142130918100683564904046581620274124659795250198283433145230849"
              "0839135778359156863668440066179055920925278708336624472863330807"
              "213114639693592192652215296";
      c[11] = "3095331588867560813065581074195466090562843910553966142338474990"
              "8067162189323826931826452103349606732527806422737129944825417754"
              "3160758595005955273250697564169609500354786133330043303900886764"
              "3563040734739358874100817619624589092088";

      a[12] = "0";
      b[12] = "3";
      c[12] = "-3";

      a[13] = "-5";
      b[13] = "-5";
      c[13] = "0";

      a[14] = "1033825265601884880289390121057699170251474247826968447777142314"
              "672936145";
      b[14] = "6584585857041179209398830597395186161231444517756911933267017221"
              "2419499";
      c[14] = "9679794070314730881954018150837473086391598026493993284444721424"
              "60516646";

      a[15]
        = "43770350598605623884688535000634442901375162537234380696226857770";
      b[15] = "998689668015619845290232924195546972680041504057103240236666837";
      c[15]
        = "42771660930590004039398302076438895928695121033177277455990190933";

      a[16] = "600";
      b[16] = "22";
      c[16] = "578";

      a[17] = "578";
      b[17] = "22";
      c[17] = "556";

      a[18] = "268";
      b[18] = "122";
      c[18] = "146";

      a[19] = "3095331588867560813065581074195466090562843910553966142338474990"
              "8067162189324041144918262171706097137185968450149595924350437582"
              "6593903825855039186828533479855976344361404038922135831771720426"
              "8035904065546571988740511211817241307384";
      b[19] = "2142130918100683564904046581620274124659795250198283433145230849"
              "0839135778359156863668440066179055920925278708336624472863330807"
              "213114639693592192652215296";
      c[19] = "3095331588867560813065581074195466090562843910553966142338474990"
              "8067162189323826931826452103349606732527806422737129944825417754"
              "3160758595005955273250697564169609500354786133330043303900886764"
              "3563040734739358874100817619624589092088";

      a[20] = "0";
      b[20] = "3";
      c[20] = "-3";

      a[21] = "-5";
      b[21] = "-5";
      c[21] = "0";

      a[22] = "1033825265601884880289390121057699170251474247826968447777142314"
              "672936145";
      b[22] = "6584585857041179209398830597395186161231444517756911933267017221"
              "2419499";
      c[22] = "9679794070314730881954018150837473086391598026493993284444721424"
              "60516646";

      a[23]
        = "43770350598605623884688535000634442901375162537234380696226857770";
      b[23] = "998689668015619845290232924195546972680041504057103240236666837";
      c[23]
        = "42771660930590004039398302076438895928695121033177277455990190933";

      // div
      a[24] = "600";
      b[24] = "22";
      c[24] = "27";

      a[25] = "10";
      b[25] = "3";
      c[25] = "3";

      a[26] = "10000";
      b[26] = "3";
      c[26] = "3333";

      a[27] = "65341020041517";
      b[27] = "504510691";
      c[27] = "129513";

      a[28] = "6534102004151763395616617026101408636894254676131848655187780867"
              "1514674964848";
      b[28] = "5045106919579856146740481474767382148432743790432207748757977533"
              "6394159706815";
      c[28] = "1";

      a[29] = "3728650344388891657065079409649036535534384288250005469364507263"
              "9621059063465";
      b[29] = "2";
      c[29] = "1864325172194445828532539704824518267767192144125002734682253631"
              "9810529531732";

      a[30]
        = "43770350598605623884688535000634442901375162537234380696226857770";
      b[30] = "998689668015619845290232924195546972680041504057103240236666837";
      c[30] = "43";

      a[31] = "3728650344388891657065079409649036535534384288250005469364507263"
              "9621059063465";
      b[31] = "2";
      c[31] = "1864325172194445828532539704824518267767192144125002734682253631"
              "9810529531732";

      a[32] = "2131266212947449665405236708312726175673823430288479731233067054"
              "7030254501315937753457996327143628642926701097023120403060702017"
              "92271107175502373632466160";
      b[32] = "1157920892373161954235709850086879078532699846656405640394575840"
              "07908834671663";
      c[32] = "1840597425079198530689838729251344620779026085362325669787197547"
              "8881952846046";

      a[33] = "300923130364674303566064152685592960036419222958287034092357419";
      b[33] = "521205221864955451187670066261363906193068031158944893620680";
      c[33] = "577";

      // These below causes Heap corruption
      a[34] = "9778316808153960080519536208683363213504600744129269364537013053"
              "0607805355644243164623752694677180743783866721110324463092282923"
              "1551955532312847794519891305602410374458394602153758575976773321"
              "873548702908703766827059895408816333758974";
      b[34] = "1157920892373161954235709850086879078532699846656405640394575840"
              "07908834671663";
      c[34] = "8444719214033070711396325528456755657778040628203650921634603504"
              "0359412893309935964430990836169086995487139581865379514291865640"
              "22152176310381675487752022988";

      a[35] = "4042517160269506153541708461306363211767361738698167671721981882"
              "0800468173859275479075849450530805379691992351315868656162334512"
              "4674003521447119593026321813728146507711845153420872106440718351"
              "89688768694403662543843232206210706";
      b[35] = "1157920892373161954235709850086879078532699846656405640394575840"
              "07908834671663";
      c[35] = "3491185958294919838741545693739059239391158329889910234922048967"
              "2627077936133742737249064266497792495935486152603096950284702759"
              "6217666059704067859675";

      a[36] = "5724866722627202679010101389421076414326669602920611575071713042"
              "922106"
              "5424281642194297583507908841202690181999089254620888612657267382"
              "819989"
              "2805209973836912683769389081833793526045749043779551723092789457"
              "008596"
              "7472671657395676286312921561565668225928075588420652996123225739"
              "090359"
              "7957727047009041264559872202397082418283611487416327341366184686"
              "752004"
              "0575418435707781840063581235797865427874795486784310587289817150"
              "338046"
              "772311631729871169564273615042361442701520";
      b[36] = "1157920892373161954235709850086879078532699846656405640394575840"
              "07908834671663";
      c[36] = "4944091397205963765708411424106925233697000468365999994551946484"
              "588281"
              "2412626436520656581340647641280845597492267708668734678555150939"
              "572188"
              "4686558000584532417549711510034295580773994554519036948894143948"
              "558964"
              "4122971282395492746299450802229785683869879533639236211831449687"
              "993802"
              "9217367116588887294380396011739119074927005929821315301479120799"
              "485417"
              "49035857752315481732903160988470021";

      a[37] = "600";
      b[37] = "22";
      c[37] = "27";

      // mod
      a[38] = "10";
      b[38] = "3";
      c[38] = "1";

      a[39] = "100";
      b[39] = "63";
      c[39] = "37";

      // hex
      a[40] = "0x123";
      b[40] = "0xa23";
      c[40] = "0xb85c9";

      big_init_m(3, &ac, &ad, &a1);
      big_alloc_max_m(3, &ac, &ad, &a1);
      for (int i = 0; i < nrt; i++) {
        big_set(a[i], &ac);
        big_set(b[i], &ad);
        if (i < add_t) {
          // Addition tests
          big_add(ac, ad, &a1);
          big_assert_str(c[i], &a1);
        } else if (i < add_t + mul_t) {
          // Multiplication tests
          big_mul(ac, ad, &a1);
          big_assert_str(c[i], &a1);
        } else if (i < add_t + sub_t + mul_t) {
          // Subtraction tests
          big_sub(ac, ad, &a1);
          big_assert_str(c[i], &a1);
        } else if (i < add_t + sub_t + mul_t + div_t) {
          // Division tests
          if (i == add_t + sub_t + mul_t + div_t - 1) {
            for (int ii = 0; ii < 50000; ii++) {
              big_div(ac, ad, &a1);
              big_assert_str(c[i], &a1);
            }
          } else {
            big_div(ac, ad, &a1);
            big_assert_str(c[i], &a1);
          }
        } else if (i < add_t + sub_t + mul_t + div_t + mod_t) {
          // Modulo tests
          big_mod(ac, ad, &a1);
          big_assert_str(c[i], &a1);
        } else if (i < nrt) {
          // Hex tests
          big_mul(ac, ad, &a1);
          (*a1).base = HEX;
          big_assert_str(c[i], &a1);
        }
        // sleep 0.03 seconds
        usleep(300000);
      }
      // big_free_m(3, &ac, &ad, &a1);
      // big_final_m(3, &ac, &ad, &a1);
      free(c);
      free(b);
      free(a);
      printf("OK\n");
    } else if (strcmp(argv[1], "crypt") == 0) {
      lc_init();
      printf("OK!\n");
    } else if (strcmp(argv[1], "hash") == 0) {
      const char *in = "smurfd";
      const char *rh = "555cfc37fc24d4971de9b091ef13401b8c5cb8b5b55804da571fb20"
      "1cbb4fc5d147ac6f528656456651606546ca42a1070bdfd79d024f3b97dd1bdac7e70f3d1";
      char *out = malloc(100);

      strcpy(out, lighthash_new(in));

      // the hash of rh and the generated one match?
      assert(lighthash_verify(out, rh));
      free(out);
      printf("OK!\n");
    }
  }
}
