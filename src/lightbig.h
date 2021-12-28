//                                                                            //
#include <stdbool.h>

#ifndef LIGHTBIG_H
#define LIGHTBIG_H 1

#define BIGLEN 2048

struct big_t {
  char *d;    // store the digits
  int length; // length of the number
  bool neg;   // positive or negative?
};

typedef struct big_t bigint_t;

int big_cmp(bigint_t **b1, bigint_t **b2);
void big_print(bigint_t **b);
void big_init(bigint_t **b);
void big_set(bigint_t **b, char* str);
void big_set_size(bigint_t **b, char* str, uint64_t size);
void big_set_negative(bigint_t **b1, bigint_t **r);
void big_cls(bigint_t **b);
void big_end(bigint_t **b);
void big_add(bigint_t **b1, bigint_t **b2, bigint_t **r);
void big_crop_zeros(bigint_t **b1, bigint_t **r);
void big_sub(bigint_t **b1, bigint_t **b2, bigint_t **r);
void big_mul(bigint_t **b1, bigint_t **b2, bigint_t **r);
void big_div(bigint_t **b1, bigint_t **b2, uint64_t *co);
void big_mod(bigint_t **b1, bigint_t **b2, bigint_t **r);

#endif
