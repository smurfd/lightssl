#ifndef LIGHTKEYS_DEFS_H
#define LIGHTKEYS_DEFS_H 1

#include <math.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

bit ecdh_p = {0x00000425, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x08000000};
bit ecdh_b = {0x00000001, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
bit ecdh_x = {0xa01c8972, 0xe2945283, 0x4dca88c7, 0x988b4717, 0x494776fb, 0xbbd1ba39, 0xb4ceb08c, 0x47da304d, 0x93b205e6, 0x43709584, 0x01841ca4, 0x60248048, 0x0012d5d4, 0xac9ca297, 0xf8103fe4, 0x82189631, 0x59923fbc, 0x026eb7a8};
bit ecdh_y = {0x3ef1c7a3, 0x01cd4c14, 0x591984f6, 0x320430c8, 0x7ba7af1b, 0xb620b01a, 0xf772aedc, 0x4fbebbb9, 0xac44aea7, 0x9d4979c0, 0x006d8a2c, 0xffc61efc, 0x9f307a54, 0x4dd58cec, 0x3bca9531, 0x4f4aeade, 0x7f4fbf37, 0x0349dc80};
bit ecdh_n = {0x637c1001, 0x5cfe778f, 0x1e91deb4, 0xe5d63938, 0xb630d84b, 0x917f4138, 0xb391a8db, 0xf19a63e4, 0x131850e1, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x02000000};
int ecdh_a = 0;
int ecdh_h = 4;
int ecdh_DEGR = 571;
int ecdh_PRIV = 72;

#endif
