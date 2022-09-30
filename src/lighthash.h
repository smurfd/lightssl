//                                                                            //
#ifndef LIGHTHASH_H
#define LIGHTHASH_H 1

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "lightdefs.h"

void lighthash_init();
char *lighthash_new(const char *in);
void lighthash_finalize(b08 *digest);
void lighthash_update(const b08 *msg, u08 len);
void lighthash_transform(const b08 *msg, u08 blocknb);
bool lighthash_verify(const char *hash, const char *ver_hash);

#endif
