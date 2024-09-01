#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include "../lightaes.h"
#include "../lightdefs.h"
#include "../lighthash.h"
#include "../lightciphers.h"
#include "../lightcrypto.h"
#include "../lighttools.h"
#include "../lightkeys.h"
static uint8_t plain[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  iv[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, aeskey[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

void test_aesgcm(void) {
  const char *vf = "gcm_test_vectors.bin";
  uint8_t *vd;
  aes_init_keygen_tables();
  if (load_file_into_ram(vf, &vd) < 0) {
    printf("Cant load the test vector file\n");
    exit(0);
  }
  if(verify_gcm(vd)) {
    printf("NIST AES-GCM validation test suite: FAILED!\n");
    free(vd);
    exit(0);
  }
  free(vd);
  printf(".");
}

void test_aescbc(void) {
  uint8_t out[BBL] = {0}, in[BBL];
  ciph_crypt(out, plain, aeskey, iv, true, false);
  ciph_crypt(in, out, aeskey, iv, true, true);
  assert(memcmp(plain, in, BBL * sizeof(uint8_t)) == 0);
  printf(".");
}

void test_aescfb(void) {
  uint8_t out[BBL] = {0}, in[BBL];
  ciph_crypt(out, plain, aeskey, iv, false, false);
  ciph_crypt(in, out, aeskey, iv, false, true);
  assert(memcmp(plain, in, BBL * sizeof(uint8_t)) == 0);
  printf(".");
}

void test_certkey(void) {
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257], data[LEN], c[8192];
  uint8_t s2[] = "smurfd and more stuff", s3[257];
  crypto_handle_cert(data, "../.build/ca.key");
  crypto_handle_asn(c, "../.build/ca256.cms");
  base64dec(s3, s0, strlen(s0));
  base64enc(s1, s2, strlen("smurfd and more stuff"));
  assert(strcmp(s1, s0) == 0);
  printf(".");
}

void test_certcli(void) {
  int s = crypto_init("127.0.0.1", "9998", false);
  if (s >= 0) {
    u64 dat[BLOCK], cd[BLOCK];
    key k1, k2;
    head h;
    crypto_transfer_key(s, false, &h, &k1);
    k2 = crypto_gen_keys(h.g, h.p);
    crypto_transfer_key(s, true, &h, &k2);
    crypto_gen_share(&k1, &k2, h.p, false);
    printf("share : 0x%.16llx\n", k1.shar);
    for (u64 i = 0; i < 12; i++) {
      dat[i] = (u64)i; cryption(dat[i], k1, &cd[i]);
    }
    crypto_transfer_data(s, cd, &h, true, 11);
    crypto_end(s);
  }
  // locally generate two keypairs
  srand(time(0));
  crypto_gen_keys_local();
  printf(".");
}

void test_certsrv(void) {
  int s = crypto_init("127.0.0.1", "9998", true);
  sock *cli = NULL;
  if (crypto_srv_listen(s, cli) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  crypto_end(s);
  printf(".");
}

void test_hash3(void) {
  uint8_t *smurfd = (uint8_t*)"smurfd";
  char s[256] = {0};
  hash_new(s, smurfd);
  assert(strcmp(s, "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8\
986549e169dcee3280bed61cda25f20") == 0);
  assert(strcmp(s, "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8\
986549e169dcee3280bed61cdffffff") != 0); // Assume failure
  printf(".");
}

void test_hash3big(void) {
  uint8_t *plain = (uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt\
 ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip e\
x ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pa\
riatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";
  char s[256] = {0};
  hash_new(s, plain);
  assert(strcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0f09") == 0);
  assert(strcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0fff") != 0); // Assume failure
  printf(".");
}

void test_hash3shk(void) {
  uint8_t res[] = {0x0d, 0xcf, 0xbc, 0x11, 0xbd, 0xd2, 0x43, 0x82, 0x4b, 0x31, 0xe5, 0x13, 0x5b, 0x8f, 0x83, 0xfa, 0x1c,
       0x11, 0x8d, 0xd7, 0x6a, 0xc0, 0xea, 0xaf, 0xee, 0x19, 0x10, 0x17, 0x0b, 0xa5, 0x61, 0x89, 0xa5, 0x8d, 0x21, 0x2a,
       0xa2, 0xb4, 0x2d, 0xfe, 0xbd, 0x1b, 0x8c, 0xdd, 0x08, 0xa4, 0xc4, 0xd5, 0xae, 0xcb, 0xfa, 0x0c, 0x33, 0x60, 0x0f,
       0x39, 0x78, 0x8b, 0x75, 0x81, 0xb5, 0xbb, 0x4f, 0x42}, in1[1024], in2[1024], out1[512], out2[512];
  char s[] = "smurfd";
  memcpy(in1, s, 6 * sizeof(uint8_t)); memcpy(in2, s, 6 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 6); hash_shake_new(out2, 64, in2, 6);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0); assert(memcmp(out2, res, 64 * sizeof(uint8_t)) == 0);
  printf(".");
}

void test_hash3shkbig(void) {
  uint8_t res[] = {0x75, 0x74, 0x60, 0x89, 0x24, 0x0d, 0x9e, 0x39, 0xff, 0xf1, 0xb4, 0xba, 0x58, 0x13, 0x0a, 0xf5, 0xb9,
       0x74, 0x4f, 0x41, 0x2a, 0x9d, 0xff, 0x73, 0x84, 0x70, 0xd1, 0x24, 0x72, 0x53, 0xd3, 0x2c, 0xe7, 0xfe, 0x5a, 0xef,
       0x0d, 0x43, 0xda, 0x15, 0x5f, 0x29, 0x08, 0x58, 0xa4, 0x2e, 0xa0, 0x41, 0xd3, 0x9a, 0x6b, 0xfd, 0x04, 0x21, 0xd4,
       0x49, 0x8e, 0xa4, 0x95, 0xbd, 0x41, 0x3a, 0x9f, 0x58}, in1[1024], in2[1024], out1[512], out2[512];
  char s[130] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et\
 dolore magna aliqua. Ut eni";
  memcpy(in1, s, 130 * sizeof(uint8_t)); memcpy(in2, s, 130 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 130); hash_shake_new(out2, 64, in2, 130);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0); assert(memcmp(out2, res, 64 * sizeof(uint8_t)) == 0);
  printf(".");
}

void test_hash3shkref(void) {
  uint8_t res[] = {0xf6, 0x49, 0x68, 0x85, 0x8b, 0x5c, 0xd8, 0xa6, 0x4f, 0xfd, 0xd9, 0x2e, 0x8c, 0x72, 0xda, 0x03, 0x87,
       0xc5, 0x68, 0x9b, 0x56, 0x2e, 0x96, 0x28, 0x86, 0x04, 0xdf, 0x95, 0x31, 0x5f, 0xee, 0xfa, 0x5a, 0xe9, 0xf0, 0x59,
       0x6b, 0x0b, 0x3d, 0x47, 0xcd, 0x61, 0xac, 0x67, 0x6a, 0xd1, 0xfb, 0x20, 0xcf, 0x3d, 0x92, 0xab, 0x2b, 0x68, 0xda,
       0xa4, 0x89, 0x31, 0xcc, 0x58, 0xd6, 0xd7, 0x23, 0xc7}, in1[1024], in2[1024], out1[512], out2[512];
  char s[] = "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3";
  memcpy(in1, s, 20 * sizeof(uint8_t)); memcpy(in2, s, 20 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 20); hash_shake_new(out2, 64, in2, 20);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0); assert(memcmp(out2, res, 64 * sizeof(uint8_t)) == 0);
  printf(".");
}

void test_keysmake(void) {
  uint8_t pubkey[BYTES + 1] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  printf(".");
}

void test_keyssecr(void) {
  uint8_t pubkey[BYTES + 1] = {0}, sec[BYTES] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  printf(".");
}

void test_keyssign(void) {
  uint8_t sig[BYTES * 2] = {0}, pubkey[BYTES + 1] = {0}, sec[BYTES] = {0}, privkey[BYTES] = {0}, h[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  assert(keys_sign(privkey, h, sig));
  printf(".");
}

void test_keyssvrfy(void) {
  uint8_t sig[BYTES * 2] = {0}, pubkey[BYTES + 1] = {0}, sec[BYTES] = {0}, privkey[BYTES] = {0}, h[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  assert(keys_sign(privkey, h, sig));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
  printf(".");
}

void test_keyswrite(void) {
  uint8_t pubkey[BYTES + 1] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  keys_write("../.build/ca-own.key", privkey, 2);
  printf(".");
}

int main(void) {
  test_aesgcm();
  test_aescbc();
  test_aescfb();
  test_hash3();
  test_hash3big();
  test_hash3shk();
  test_hash3shkbig();
  test_hash3shkref();
  test_keysmake();
  test_keyssecr();
  test_keyssign();
  test_keyssvrfy();
  test_keyswrite();
  printf("\nOK\n");
}
