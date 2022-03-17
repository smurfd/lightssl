//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdbool.h>
#include "lightbig.h"
#include "lightdefs.h"

// TODO: obviously huge room for improvement
// TODO: add multifunctions to save lines like: a+b-c*d
// FIXME: If you DONT find bugs/leaks/securityissues let me know ;)

//
// Initialize a bigint
void big_init(bigint_t **a) {
  (*a) = calloc(1, sizeof(bigint_t));
  (*a)->neg = false;
  (*a)->base = DEC;
  (*a)->alloc_t = true;
  (*a)->alloc_d = false;
}

//
// Initialize several bigint
void big_init_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_init(va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Clear a bigint
void big_end(bigint_t **a) {
  if ((*a)->alloc_d) {
    free((*a)->dig);
  }
  if ((*a)->alloc_t) {
    free((*a));
  }
}

//
// Free a string
void big_end_str(char *a) {
  if (a) {
    free(a);
  }
}

//
// Clear several bigint
void big_end_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_end(va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Set several bigint
void big_set_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_set("", va_arg(valist, bigint_t**));
  }
  va_end(valist);
}

//
// Set a bigint from string
void big_set(char *a, bigint_t **b) {
  int skip = 0;

  (*b)->neg = false;
  (*b)->base = DEC;
  if (a[0] == '-') {
    (*b)->neg = true;
    skip++;
  }
  if (a[0 + skip] == '0' && a[1 + skip] == 'x') {
    (*b)->base = HEX;
    skip = skip + 2;
  } else {
    (*b)->base = DEC;
  }
  if (strcmp("0", a) == 0) {
    (*b)->len = 1;
    (*b)->dig[0] = 0;
  } else if (strcmp("", a) == 0) {
    (*b)->len = 1;
  } else {
    while (a[skip] == '0') {
      skip++;
    }

    (*b)->len = strlen(a) - skip;
    if ((*b)->len == 0) {
      (*b)->len++;
      (*b)->dig[0] = 0;
    } else {
      for (int i = 0; i < (*b)->len; i++) {
        if (a[skip + i] - '0' < DEC) {
          (*b)->dig[i] = a[skip + i] - '0';
        } else if (a[skip + i] - '0' <= 'F' - '0') {
          (*b)->dig[i] = a[skip + i] - '0' - 7;
        } else if (a[skip + i] - '0' < 'f' - '0') {
          (*b)->dig[i] = a[skip + i] - '0' - 39;
        }
      }
    }
  }
}

//
// Allocate memory for digits
void big_alloc(bigint_t **b) {
  (*b)->dig = calloc((*b)->len, sizeof(int));
  (*b)->alloc_d = true;
}

//
// Allocate memory for digits
void big_alloc_2(bigint_t **b, int len) {
  (*b)->dig = calloc(len, sizeof(int));
  (*b)->alloc_d = true;
}

//
// Compare two bigints
bool big_cmp(bigint_t *a, bigint_t *b) {
  if ((*a).len != (*b).len) {
    return false;
  }
  for (int i = 0; i < (*a).len; i++) {
    if ((*a).dig[i] != (*b).dig[i]) {
      return false;
    }
  }
  return true;
}

//
// Compare a string and a bigint
bool big_cmp_str(char *str, bigint_t *a) {
  if ((u64)(*a).len != strlen(str)) {
    return false;
  }
  for (int i = 0; i < (*a).len; i++) {
    if ((*a).dig[i] != str[i]) {
      return false;
    }
  }
  return true;
}

//
// Copy data
void big_copy(const bigint_t *a, bigint_t **b) {
  for (int f = 0; f < (*a).len; f++) {
    (*b)->dig[f] = (*a).dig[f];
  }
  (*b)->neg = (*a).neg;
  (*b)->base = (*a).base;
  (*b)->len = (*a).len;
}

//
// Copy data refs, replaces (*a) = (*b)
void big_copy_ref(const bigint_t *a, bigint_t **b) {
  (*b)->neg = (*a).neg;
  (*b)->len = (*a).len;
  (*b)->base = (*a).base;
  big_alloc(&(*b));
  for (int l = 0; l < (*a).len; l++) {
    (*b)->dig[l] = (*a).dig[l];
  }
}

//
// Clear initial zeros
void big_clear_zeros(bigint_t **b) {
  char *bbb = (char*) malloc (MAXSTR);
  bigint_t *bb;

  big_init_m(1, &bb);
  big_alloc_2(&bb, MAXSTR);
  while ((*b)->dig[0] == 0 && (*b)->len >= 0) {
    (*b)->len--;
    (*b)->dig++;
  }
  // if the string only contains zeros atleast save one
  big_get(*b, bbb);
  if (strcmp("", bbb) == 0) {
    big_set("0", b);
  }

  big_end_m(1, bb);
  big_end_str(bbb);
}

//
// Get string from bigint
void big_get(const bigint_t *a, char *b) {
  int mod = 0;

  // Reset outparam
  memset(b, 0, strlen(b));

  // -3 is digit for '-'?
  if (a->neg && a->dig[0] != -3) {
    mod = 1;
    b[0] = '-';
  }
  if (a->base == HEX) {
    b[0+mod] = '0';
    b[1+mod] = 'x';
    mod = mod + 2;
  }
  for (int i = 0; i < a->len; i++) {
    if (a->dig[i] < DEC) {
      b[i+mod] = a->dig[i] + '0';
    } else {
      b[i+mod] = (a->dig[i] % 'a') + 'a' - 10;
    }
  }
  b[a->len+mod] = '\0';
}

//
// Get Hex value
int big_get_hex(int a, int base) {
  if (base == HEX) {
    if (a > 9) {
      if (a % 'A' < 7) {
        return 10 + (a % 'A');
      }
      if (a % 'a' < 7) {
        return 10 + (a % 'a');
      }
    }
  }
  return a;
}

//
// Bigint addition
void big_add(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, base;
  bigint_t *aa, *bb;
  char *aaa = (char*) malloc (MAXSTR);
  char *bbb = (char*) malloc (MAXSTR);

  big_init_m(2, &aa, &bb);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(c, MAXSTR);
  base = big_check_set_base(a, c);
  carry = 0;
  (*c)->neg = false;

  big_get(a, aaa);
  big_get(b, bbb);
  big_set(aaa, &aa);
  big_set(bbb, &bb);

  if ((*a).neg && (*b).neg) {
    (*c)->neg = true;
  }
  if (a == NULL || b == NULL) {
    c = NULL;
  } else if (strcmp(aaa, "0") == 0) {
    big_copy_ref(bb, c);
  } else if (strcmp(bbb, "0") == 0) {
    big_copy_ref(aa, c);
  } else {
    (*c)->len = (a->len > b->len ? a->len : b->len) + 1;
    i = a->len - 1;
    j = b->len - 1;
    k = (*c)->len - 1;

    while (i >= 0 || j >= 0 || carry > 0) {
      if (i >= 0 && j >= 0) {
        tmp = big_get_hex(aa->dig[i], aa->base) + big_get_hex(bb->dig[j],
            bb->base);
      } else if (i >= 0) {
        tmp = a->dig[i];
      } else if (j >= 0) {
        tmp = b->dig[j];
      } else {
        tmp = 0;
      }
      tmp += carry;
      carry = tmp / base;
      (*c)->dig[k] = tmp % base;
      i--;
      j--;
      k--;
    }
    big_clear_zeros(c);
  }
  big_end_str(bbb);
  big_end_str(aaa);
  big_end_m(2, &aa, &bb);
}

//
// Bigint multiplication
void big_mul(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, push_left, base;
  char *aaa = (char*) malloc (MAXSTR);
  char *bbb = (char*) malloc (MAXSTR);
  bigint_t *aa, *bb;

  big_init_m(2, &aa, &bb);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(c, MAXSTR);

  base = big_check_set_base(a, c);
  carry = 0;

  // reset output parameter
  memset((*c)->dig, 0, (*c)->len*sizeof(int));
  (*c)->neg = false;

  big_get(a, aaa);
  big_get(b, bbb);
  big_set(aaa, &aa);
  big_set(bbb, &bb);
  aa->len = a->len;
  bb->len = b->len;

  // Set result to correct sign
  if ((*aa).neg && (*bb).neg) {
    (*c)->neg = false;
  } else if ((*aa).neg || (*bb).neg) {
    (*c)->neg = true;
  }

  if (a == NULL || b==NULL) {
    c = NULL;
  } else if ((*aa).len == 1 && (*aa).dig[0] == 0) {
    (*c)->len = 1;
    big_set("0", c);
  } else if ((*bb).len == 1 && (*bb).dig[0] == 0) {
    (*c)->len = 1;
    big_set("0", c);
  } else {
    (*c)->len = aa->len + bb->len;
    i = aa->len - 1;
    j = bb->len - 1;
    k = (*c)->len - 1;
    carry = 0;
    push_left = 0;
    while (i >= 0) {
      k = (*c)->len - 1 - push_left++;
      j = bb->len - 1;
      while (j >= 0 || carry > 0) {
        if (j >= 0) {
          tmp = big_get_hex(aa->dig[i], aa->base) * big_get_hex(bb->dig[j],
              bb->base);
        } else {
          tmp = 0;
        }
        tmp += carry;
        carry = tmp / base;
        (*c)->dig[k] += tmp % base;
        carry += (*c)->dig[k] / base;
        (*c)->dig[k] = (*c)->dig[k] % base;
        j--;
        k--;
      }
      i--;
    }
    big_clear_zeros(c);
  }
  big_end_str(bbb);
  big_end_str(aaa);
  big_end_m(2, &aa, &bb);
}

//
// Bigint subtraction 
void big_sub(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, base;
  bigint_t *aa, *bb;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);

  big_init_m(2, &aa, &bb);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(c, MAXSTR);

  big_get(a, aaa);
  big_get(b, bbb);
  big_set(aaa, &aa);
  big_set(bbb, &bb);

  base = big_check_set_base(a, c);
  carry = 0;

  // reset output parameter
  memset((*c)->dig, 0, (*c)->len*sizeof(int));
  (*c)->neg = false;
  (*c)->len = (*a).len;
  if ((*a).neg && (*b).neg) {
    (*aa).neg = false;
    (*bb).neg = false;
    if (strcmp(aaa, bbb) < 0) {
      big_sub(bb, aa, c);
    } else {
      big_sub(aa, bb, c);
      (*c)->neg = false;
    }
  } else if ((*a).neg || (*b).neg) {
    (*aa).neg = false;
    (*bb).neg = false;
    big_add(aa, bb, c);
    if ((*a).len < (*b).len || (*a).len > (*b).len) {
      (*c)->neg = true;
    }
    if ((*a).len == (*b).len) {
      if (strcmp(aaa, bbb) < 0) {
        (*c)->neg = true;
      }
    }
  } else {
    if (a == NULL || b == NULL) {
      c = NULL;
    } else if (strcmp(aaa, "0") == 0 && strcmp(bbb, "0") == 0) {
      big_set("0", c);
    } else if (strcmp(aaa, "0") == 0) {
      (*bb).neg = true;
      big_copy_ref(bb, c);
      big_clear_zeros(c);
      //big_clear_zero2(c);
    } else if (strcmp(bbb, "0") == 0) {
      (*c)->len = a->len;
      big_copy_ref(aa, c);
      big_clear_zeros(c);
      //big_clear_zero2(c);
    } else {
      (*c)->len = (a->len > b->len ? a->len : b->len);
      if (a->len > b->len) {
        memset((*aa).dig, 0, (*aa).len * sizeof(int));
        memset((*bb).dig, 0, (*bb).len * sizeof(int));
        big_set(aaa, &aa);
        big_set(bbb, &bb);
        (*aa).len = a->len;
        (*bb).len = b->len;
        i = (*aa).len - 1;
        j = (*bb).len - 1;
      } else if (b->len > a->len) {
        memset((*aa).dig, 0, (*aa).len * sizeof(int));
        memset((*bb).dig, 0, (*bb).len * sizeof(int));
        (*c)->neg = true;
        big_set(bbb, &aa);
        big_set(aaa, &bb);
        (*aa).len = b->len;
        (*bb).len = a->len;
        i = (*aa).len - 1;
        j = (*bb).len - 1;
      } else {
        memset((*aa).dig, 0, (*aa).len * sizeof(int));
        memset((*bb).dig, 0, (*bb).len * sizeof(int));
        big_set(aaa, &aa);
        big_set(bbb, &bb);
        (*aa).len = a->len;
        (*bb).len = b->len;
        i = (*aa).len - 1;
        j = (*bb).len - 1;
      }
      k = (*c)->len - 1;
      carry = 0;
      while (i >= 0 || j >= 0 || carry > 0) {
        if (i >= 0 && j >= 0) {
          tmp = big_get_hex((*aa).dig[i], (*aa).base) - big_get_hex((*bb).dig[j],
              (*bb).base);
          if (tmp < 0) {
            if (i == 0 && j == 0) {
              (*c)->neg = true;
            }
            tmp += 10;
            (*aa).dig[i - 1] -= 1;
          }
        } else if (i >= 0) {
          tmp = (*aa).dig[i];
        } else if (j >= 0) {
          tmp = (*bb).dig[j];
        } else {
          tmp = 0;
        }
        tmp -= carry;
        carry = tmp / base;
        if (tmp % base < 0 && i < 2) {
          (*c)->dig[k] = (tmp % base) + base;
          if ((*c)->dig[k - 1] > 0) {
            (*c)->dig[k - 1] = (*aa).dig[k - 1] - 1;
          } else {
            (*c)->dig[k - 1] = 0;
            break;
          }
        } else {
          (*c)->dig[k] = tmp % base;
        }
        i--;
        j--;
        k--;
      }
      big_clear_zeros(c);
      if (j > i) {
        (*c)->neg = true;
      }
    }
  }
  big_end_str(bbb);
  big_end_str(aaa);
  big_end_m(2, &aa, &bb);
}

//
// Bigint division
void big_div_sub(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  char *str = (char*) malloc(MAXSTR);
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);
  char *str1 = (char*) malloc(MAXSTR);
  bigint_t *aa, *e, *f, *bb;
  u64 co;

  big_get(a, aaa);
  big_get(b, bbb);
  co = 0;
  big_init_m(4, &aa, &e, &f, &bb);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(&e, MAXSTR);
  big_alloc_2(c, MAXSTR);
  big_set(aaa, &aa);
  big_set(bbb, &bb);
  aa->len = a->len;
  bb->len = b->len;
  while ((aa->len >= bb->len) && (e->neg == false && aa->neg == false)) {
    big_sub(aa, bb, &e);
    big_get(e, str1);
    big_get(aa, aaa);
    big_set(str1, &aa);
    aa->neg = e->neg;
    aa->len = e->len;
    co++;
  }
  if (aa->neg == true) {
     co--;
  }
  sprintf(str, "%llu", co);
  big_set(str, c);
  (*c)->len = strlen(str);
  big_end_m(2, &aa, &bb);
  big_end_str(bbb);
  big_end_str(aaa);
  big_end_str(str);
}

void big_div(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  // This should work without fuckin hacks
  // fill out b with zeros to be the same lenght as a then divide
  // take that number add to c, then times b and subtract from a. repeat.
  // 1234 // 3 = 411
  // 1234 // 3000 = 0
  // 1234 // 300 = 4  -- add to result
  // 4 * 300 = 1200
  // 1234 - 1200 = 34
  // 34 // 30 = 1  -- add to result
  // 1 * 30 = 30
  // 34 - 30 = 4
  // 4 // 3 = 1   -- add to result
  // 3 * 1 = 3
  // 4 - 3 = 1
  // 1 // 3 == 0
  bigint_t *aa, *bb, *cc, *cc1, *aa1;
  int len_b, len_diff;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);

  big_init_m(5, &aa, &bb, &cc, &aa1, &cc1);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(&cc, MAXSTR);
  big_alloc_2(&aa1, MAXSTR);
  big_alloc_2(&cc1, MAXSTR);
  big_alloc_2(c, MAXSTR);

  // reset output parameter
  (*c)->neg = false;
  (*c)->len = 1;

  // Create copy of a & b
  big_get(a, aaa);
  big_get(b, bbb);
  aaa[a->len] = '\0';
  bbb[b->len] = '\0';
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  big_set(aaa, &aa);
  big_set(bbb, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;

  // Set result to correct sign
  if ((*a).neg || (*b).neg) {
    (*c)->neg = true;
  }

  // if a or b is NULL we return NULL
  // if a == b we return 1
  // if a < b we return 0
  // if b == 1 we return a
  if (a == NULL || b == NULL) {
    c = NULL;
  } else if (strcmp(aaa, bbb) == 0) {
    big_set("1", c);
  } else if (strcmp(aaa, bbb) <= 0 && strlen(aaa) == strlen(bbb)) {
    big_set("0", c);
  } else if (strcmp(bbb, "1") == 0) {
    big_copy_ref(aa, c);
  } else {
    len_diff = (*aa).len - (*bb).len;
    len_b = (*bb).len;
    for (int i = 0; i <= len_diff; i++) { // Fill divisor with zeros
      (*bb).dig[len_b + i] = 0;
      (*bb).len++;
    }
    for (int j = 0; j <= len_diff; j++) {
      if ((u64)(*bb).len > (u64)(*b).len) {
        (*bb).len--;
      }
      len_b = (*bb).len;
      big_div_sub(aa, bb, &cc);
      if ((*cc).dig[0] != 0 && (*cc).len == 1) {
        big_mul(bb, cc, &cc1);
        big_sub(aa, cc1, &aa1);
        big_clear_zeros(&aa1);
        big_get(aa1, aaa);
        big_set(aaa, &aa);
      }
      if ((*cc).len > 1) {
        for (int ii = 0; ii < (*cc).len; ii++) {
          (*c)->dig[j + ii] = (*cc).dig[ii];
          (*c)->len++;
        }
      } else {
        (*c)->dig[j] = (*cc).dig[0];
        (*c)->len++;
      }
    }
    (*c)->len--;
    big_clear_zeros(c);
  }
  big_end_str(bbb);
  big_end_str(aaa);
  big_end_m(3, &aa, &bb, &cc);
}

//
// Bigint modulo
void big_mod(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  bigint_t *aa, *bb, *cc, *cc1, *g;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);
  bool n = false;

  big_init_m(6, &aa, &bb, &cc, &cc1, &g, c);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(&cc, MAXSTR);
  big_alloc_2(&cc1, MAXSTR);
  big_alloc_2(&g, MAXSTR);
  big_alloc_2(c, MAXSTR);

  (*c)->neg = false;
  (*c)->len = 1;

  // Create copy of a & b
  big_get(a, aaa);
  big_get(b, bbb);
  big_set(aaa, &aa);
  big_set(bbb, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;

  big_set("1", &g);

  if (a == NULL || b == NULL) {
    c = NULL;
  } else {
    if ((*a).neg) {
      aa->neg = false;
      n = true;
    }
    big_div(aa, bb, &cc);
    if (n) {
      big_add(cc, g, &cc);
    }
    if (n && (*cc).neg == false) {
      (*cc).neg = true;
    }
    big_mul(cc, bb, &cc1);
    (*c)->len = (*bb).len;
    big_sub(aa, cc1, c);
    big_clear_zeros(c);
  }

  big_end_str(bbb);
  big_end_str(aaa);
  big_end_m(2, &aa, &bb);
}

//
// Bigint &1
bool big_bit_and_one(bigint_t *a) {
  return (*a).dig[(*a).len - 1] & 1;
}

//
// Check what base a has and set that to b
int big_check_set_base(const bigint_t *a, bigint_t **b) {
  int base;
  if (a->base != 0) {
    base = a->base;
    if (a->base == HEX) {
      (*b)->base = HEX;
    }
  } else {
    base = DEC;
  }
  return base;
}

//
// Print a bigint
void big_print(const bigint_t **a) {
  char *aaa = (char*) malloc (MAXSTR);
  bigint_t *aa;

  big_init_m(1, &aa);
  big_alloc_2(&aa, MAXSTR);
  big_get(*a, aaa);
  printf("%s\n", aaa);

  big_end_m(1, &aa);
  big_end_str(aaa);
}

//
// Assert two bigints are the same
void big_assert(bigint_t **b1, bigint_t **b2) {
  char *aaa = (char*) malloc (MAXSTR);
  char *bbb = (char*) malloc (MAXSTR);

  big_get(*b1, aaa);
  big_get(*b2, bbb);
  assert(strcmp(aaa, bbb) == 0);

  big_end_str(bbb);
  big_end_str(aaa);
}

//
// Assert a string and bigint is the same
void big_assert_str(char* str, bigint_t **b2) {
  char *bbb = (char*) malloc (MAXSTR);

  big_get(*b2, bbb);
  assert(strcmp(str, bbb) == 0);

  big_end_str(bbb);
}
