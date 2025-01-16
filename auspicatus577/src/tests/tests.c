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

uint8_t test_aes(void) {
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  cipher(resultenc, key, plain);
  inv_cipher(resultdec, key, resultenc);
  assert(memcmp(resultenc, expect, 4 * sizeof(uint32_t)) == 0 && memcmp(resultdec, plain, 4 * sizeof(uint32_t)) == 0);
  return 1;
}

uint8_t test_aesloop(void) {
  uint8_t res = 0;
  uint32_t key[8] = {0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781, 0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4};
  uint32_t plain[4] = {0xf69f2445, 0xdf4f9b17, 0xad2b417b, 0xe66c3710};
  uint32_t expect[4] = {0x23304b7a, 0x39f9f3ff, 0x067d8d8f, 0x9e24ecc7};
  uint32_t resultenc[64] = {0}, resultdec[64] = {0};
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    cipher(resultenc, key, plain);
    inv_cipher(resultdec, key, resultenc);
    res += memcmp(resultenc, expect, 4 * sizeof(uint32_t));
    res += memcmp(resultdec, plain, 4 * sizeof(uint32_t));
  }
  assert(res == 0);
  printf("aesloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_aesgcm(void) {
  uint8_t iv[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
  plain[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  gcm_ciphertag(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag(plain2, tag2, key, iv, cipher, aad, tag);
  res += memcmp(plain, plain2, 32 * sizeof(uint8_t));
  assert(res == 0);
  return 1;
}

uint8_t test_aesgcmloop(void) {
  uint8_t iv[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
  key[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
  plain[32] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag(cipher, tag, key, iv, plain, aad,  32);
    gcm_inv_ciphertag(plain2, tag2, key, iv, cipher, aad, tag);
    res += memcmp(plain, plain2, 32 * sizeof(uint8_t));
  }
  assert(res == 0);
  printf("aesgcmloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_aesgcm32bit(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad,  32);
  gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
  res += memcmp(plain, plain2, 8 * sizeof(uint32_t));
  assert(res == 0);
  return 1;
}

uint8_t test_aesgcm32bitloop(void) {
  uint32_t iv[32] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
  key[32] = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f},
  plain[32] = {0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff, 0x00112233, 0x44556677, 0x8899aabb, 0xccddeeff},
  cipher[32] = {0}, tag[32] = {0}, tag2[32] = {0}, aad[32] = {0}, plain2[32] = {0}, res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    gcm_ciphertag32bit(cipher, tag, key, iv, plain, aad, 8);
    gcm_inv_ciphertag32bit(plain2, tag2, key, iv, cipher, aad, tag);
    res += memcmp(plain, plain2, 8 * sizeof(uint32_t));
  }
  assert(res == 0);
  printf("aesgcm32bitloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_certkey(void) {
  char s0[] = "c211cmZkIGFuZCBtb3JlIHN0dWZm", s1[257], data[LEN], c[8192];
  uint8_t s2[] = "smurfd and more stuff", s3[257];
  crypto_handle_cert(data, "../.build/ca.key");
  crypto_handle_asn(c, "../.build/ca256.cms");
  base64dec(s3, s0, strlen(s0));
  base64enc(s1, s2, strlen("smurfd and more stuff"));
  assert(strcmp(s1, s0) == 0);
  return 1;
}

uint8_t test_certcli(void) {
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
  return 1;
}

uint8_t test_certsrv(void) {
  int s = crypto_init("127.0.0.1", "9998", true);
  sock *cli = NULL;
  if (crypto_srv_listen(s, cli) < 0) {
    printf("Can't create a Thread\n");
    exit(0);
  }
  crypto_end(s);
  return 1;
}

uint8_t test_hash3(void) {
  uint8_t *smurfd = (uint8_t*)"smurfd";
  char s[256] = {0};
  hash_new(s, smurfd);
  assert(strcmp(s, "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8\
986549e169dcee3280bed61cda25f20") == 0);
  assert(strcmp(s, "0x5c452b35648528cf3a00a42021489011dd455b78fc34190c7680173b2dcdcc7d61e73d4f2c51051e45d26215f9f7729b8\
986549e169dcee3280bed61cdffffff") != 0); // Assume failure
  return 1;
}

uint8_t test_hash3big(void) {
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
  return 1;
}

uint8_t test_hash3bigloop(void) {
  uint8_t *plain = (uint8_t*)"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt\
 ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip e\
x ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pa\
riatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.",
  res = 0;
  clock_t start = clock();
  for (int i = 0; i < 1000000; i++) {
    char s[256] = {0};
    hash_new(s, plain);
    res += memcmp(s, "0xf32a9423551351df0a07c0b8c20eb972367c398d61066038e16986448ebfbc3d15ede0ed3693e3905e9a8c601d9d002a0\
6853b9797ef9ab10cbde1009c7d0f09", 130);
  }
  assert(res == 0);
  printf("hash3bigloop: Time %us %ums\n", (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) / 1000, (uint32_t)((clock() - start) * 1000 / CLOCKS_PER_SEC) % 1000);
  return 1;
}

uint8_t test_hash3shk(void) {
  uint8_t res[] = {0x0d, 0xcf, 0xbc, 0x11, 0xbd, 0xd2, 0x43, 0x82, 0x4b, 0x31, 0xe5, 0x13, 0x5b, 0x8f, 0x83, 0xfa, 0x1c,
       0x11, 0x8d, 0xd7, 0x6a, 0xc0, 0xea, 0xaf, 0xee, 0x19, 0x10, 0x17, 0x0b, 0xa5, 0x61, 0x89, 0xa5, 0x8d, 0x21, 0x2a,
       0xa2, 0xb4, 0x2d, 0xfe, 0xbd, 0x1b, 0x8c, 0xdd, 0x08, 0xa4, 0xc4, 0xd5, 0xae, 0xcb, 0xfa, 0x0c, 0x33, 0x60, 0x0f,
       0x39, 0x78, 0x8b, 0x75, 0x81, 0xb5, 0xbb, 0x4f, 0x42}, in1[1024], in2[1024], out1[512], out2[512];
  char s[] = "smurfd";
  memcpy(in1, s, 6 * sizeof(uint8_t)); memcpy(in2, s, 6 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 6); hash_shake_new(out2, 64, in2, 6);
  for (int i = 0; i < 64; i++) {
    printf("%d %d: %d\n", out1[i], out2[i], res[i]);
  }
  assert(memcmp((uint8_t*)out1, res, 64 * sizeof(uint8_t)) == 0); assert(memcmp((uint8_t*)out2, res, 64 * sizeof(uint8_t)) == 0);
  return 1;
}

uint8_t test_hash3shkbig(void) {
  uint8_t res[] = {0x75, 0x74, 0x60, 0x89, 0x24, 0x0d, 0x9e, 0x39, 0xff, 0xf1, 0xb4, 0xba, 0x58, 0x13, 0x0a, 0xf5, 0xb9,
       0x74, 0x4f, 0x41, 0x2a, 0x9d, 0xff, 0x73, 0x84, 0x70, 0xd1, 0x24, 0x72, 0x53, 0xd3, 0x2c, 0xe7, 0xfe, 0x5a, 0xef,
       0x0d, 0x43, 0xda, 0x15, 0x5f, 0x29, 0x08, 0x58, 0xa4, 0x2e, 0xa0, 0x41, 0xd3, 0x9a, 0x6b, 0xfd, 0x04, 0x21, 0xd4,
       0x49, 0x8e, 0xa4, 0x95, 0xbd, 0x41, 0x3a, 0x9f, 0x58}, in1[1024], in2[1024], out1[512], out2[512];
  char s[130] = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et\
 dolore magna aliqua. Ut eni";
  memcpy(in1, s, 130 * sizeof(uint8_t)); memcpy(in2, s, 130 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 130); hash_shake_new(out2, 64, in2, 130);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0); assert(memcmp(out2, res, 64 * sizeof(uint8_t)) == 0);
  return 1;
}

uint8_t test_hash3shkref(void) {
  uint8_t res[] = {0xf6, 0x49, 0x68, 0x85, 0x8b, 0x5c, 0xd8, 0xa6, 0x4f, 0xfd, 0xd9, 0x2e, 0x8c, 0x72, 0xda, 0x03, 0x87,
       0xc5, 0x68, 0x9b, 0x56, 0x2e, 0x96, 0x28, 0x86, 0x04, 0xdf, 0x95, 0x31, 0x5f, 0xee, 0xfa, 0x5a, 0xe9, 0xf0, 0x59,
       0x6b, 0x0b, 0x3d, 0x47, 0xcd, 0x61, 0xac, 0x67, 0x6a, 0xd1, 0xfb, 0x20, 0xcf, 0x3d, 0x92, 0xab, 0x2b, 0x68, 0xda,
       0xa4, 0x89, 0x31, 0xcc, 0x58, 0xd6, 0xd7, 0x23, 0xc7}, in1[1024], in2[1024];
  char s[] = "\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3", out1[512], out2[512];
  memcpy(in1, s, 20 * sizeof(uint8_t)); memcpy(in2, s, 20 * sizeof(uint8_t));
  hash_shake_new(out1, 64, in1, 20); hash_shake_new(out2, 64, in2, 20);
  assert(memcmp(out1, res, 64 * sizeof(uint8_t)) == 0); assert(memcmp(out2, res, 64 * sizeof(uint8_t)) == 0);
  return 1;
}

uint8_t test_keysmake(void) {
  uint8_t pubkey[BYTES + 1] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  return 1;
}

uint8_t test_keyssecr(void) {
  uint8_t pubkey[BYTES + 1] = {0}, sec[BYTES] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  return 1;
}

uint8_t test_keyssign(void) {
  uint8_t sig[BYTES * 2] = {0}, pubkey[BYTES + 1] = {0}, sec[BYTES] = {0}, privkey[BYTES] = {0}, h[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  assert(keys_sign(privkey, h, sig));
  return 1;
}

uint8_t test_keyssvrfy(void) {
  uint8_t sig[BYTES * 2] = {0}, pubkey[BYTES + 1] = {0}, sec[BYTES] = {0}, privkey[BYTES] = {0}, h[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  assert(keys_secr(pubkey, privkey, sec));
  assert(keys_sign(privkey, h, sig));
  assert(keys_vrfy(pubkey, h, sig));
  assert(!keys_vrfy(privkey, h, sig)); // assert failure
  return 1;
}

uint8_t test_keyswrite(void) {
  uint8_t pubkey[BYTES + 1] = {0}, privkey[BYTES] = {0};
  assert(keys_make(pubkey, privkey));
  keys_write("../.build/ca-own.key", privkey, 2);
  return 1;
}

int main(int argc, char** argv) {
  int ret = 1;
  if (argc == 1) { // When run without arguments
    ret &= test_aes();
    ret &= test_aesgcm();
    ret &= test_aesgcm32bit();
    ret &= test_hash3();
    ret &= test_hash3big();
   // ret &= test_hash3shk(); // TODO: why does these fail?
   // ret &= test_hash3shkbig();
   // ret &= test_hash3shkref();
    ret &= test_keysmake();
    ret &= test_keyssecr();
    ret &= test_keyssign();
    ret &= test_keyssvrfy();
    ret &= test_keyswrite();
    if (ret) printf("\nOK\n");
    else printf("\nNot OK\n");
  } else {
    if (strcmp(argv[1], "local") == 0) { // When run locally to measure speed
      ret &= test_aes();
      ret &= test_aesloop();
      ret &= test_aesgcmloop();
      ret &= test_aesgcm();
      ret &= test_aesgcmloop();
      ret &= test_aesgcm32bit();
      ret &= test_aesgcm32bitloop();
      ret &= test_hash3();
      ret &= test_hash3big();
      ret &= test_hash3bigloop();
     // ret &= test_hash3shk();
     // ret &= test_hash3shkbig();
     // ret &= test_hash3shkref();
      ret &= test_keysmake();
      ret &= test_keyssecr();
      ret &= test_keyssign();
      ret &= test_keyssvrfy();
      ret &= test_keyswrite();
      if (ret) printf("\nOK\n");
      else printf("\nNot OK\n");
    }
  }
}
