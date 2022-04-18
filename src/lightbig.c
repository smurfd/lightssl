//                                                                            //
#include "lightbig.h"
#include "lightdefs.h"
#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO: obviously huge room for improvement
// TODO: add multifunctions to save lines like: a+b-c*d
// FIXME: If you DONT find bugs/leaks/securityissues let me know ;)

//
// Initialize a bigint
void big_init(bigint_t **a) {
  (*a) = malloc(sizeof(bigint_t));
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
    big_init(va_arg(valist, bigint_t **));
  }
  va_end(valist);
}

//
// Free a bigint
void big_free(bigint_t **a) {
  if ((*a)->alloc_d) {
    (*a)->alloc_d = false;
    if ((*a)->dig != NULL) {
      free((*a)->dig);
    }
  }
}

//
// Free several bigint
void big_free_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_free(va_arg(valist, bigint_t **));
  }
  va_end(valist);
}

//
// Finalize bigint
void big_final(bigint_t **a) {
  if ((*a)->alloc_t) {
    (*a)->alloc_t = false;
    if ((*a) != NULL) {
      free((*a));
    }
  }
}

//
// Finalize several bigint
void big_final_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_final(va_arg(valist, bigint_t **));
  }
  va_end(valist);
}

//
// Clear a bigint
void big_end(bigint_t **a) {
  if ((*a)->alloc_d) {
    free((*a)->dig);
    (*a)->alloc_d = false;
  }
  if ((*a)->alloc_t) {
    free((*a));
    (*a)->alloc_t = false;
  }
}

//
// Free a string
void big_end_str(char *a) {
  if (a != NULL) {
    free(a);
  }
}

//
// Clear several bigint
void big_end_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_end(va_arg(valist, bigint_t **));
  }
  va_end(valist);
}

//
// resize
void big_resize(bigint_t **a, int old_len, int new_len) {
  if ((*a)->alloc_d) {
    char *aaa = malloc(MAXSTR);
    char *bbb = malloc(MAXSTR);
    bigint_t *aa = NULL;
    int tmplen;

    if ((*a)->len > 1) {
      big_init_m(1, &aa);
      (*aa).len = (*a)->len;
      big_alloc_m(1, &aa);
      big_get(*a, aaa);
      tmplen = (*aa).len;
      big_set(aaa, &aa);
      big_get(aa, bbb);

      big_free_m(1, a);
      big_final_m(1, a);
      big_init_m(1, a);
      big_alloc_len(a, new_len);
      big_set(aaa, a);
      big_get(*a, aaa);
      big_free_m(1, &aa);
      big_final_m(1, &aa);
      big_end_str(bbb);
      big_end_str(aaa);
    } else {
      (*a)->len = old_len;
    }
  }
}

//
// Set several bigint
void big_set_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_set("", va_arg(valist, bigint_t **));
  }
  va_end(valist);
}

//
// Set a bigint from string
void big_set(char *a, bigint_t **b) {
  int skip = 0;
  int len = (int)strlen(a) > (*b)->len ? strlen(a) : (*b)->len;

  // Reset outparam
  memset((*b)->dig, 0, len);

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
    while (a[skip] == '0') { // ignore 1st zeros
      skip++;
      (*b)->len--;
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
  (*b)->dig = malloc((*b)->len * LEN);
  (*b)->alloc_d = true;
}

//
// Allocate memory for digits
void big_alloc_len(bigint_t **b, int len) {
  (*b)->dig = malloc(len * LEN);
  (*b)->alloc_d = true;
}

//
// Allocate memory for digits
void big_alloc_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_alloc(va_arg(valist, bigint_t **));
  }
  va_end(valist);
}

//
// Allocate max memory for digits
void big_alloc_max_m(int len, ...) {
  va_list valist;

  va_start(valist, len);
  for (int i = 0; i < len; i++) {
    big_alloc_len(va_arg(valist, bigint_t **), MAXSTR);
  }
  va_end(valist);
}

//
// Compare two bigints
bool big_cmp(const bigint_t *a, const bigint_t *b) {
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
bool big_cmp_str(char *str, const bigint_t *a) {
  if ((u64)(*a).len != strlen(str)) {
    return false;
  }
  for (int i = 0; i < (*a).len; i++) {
    if ((*a).dig[i] != (str[i] - '0')) {
      return false;
    }
  }
  return true;
}

//
// Copy one bigint to another
void big_copy(const bigint_t *a, bigint_t **c) {
  char *aaa = malloc(MAXSTR);

  big_get(a, aaa);
  big_set(aaa, c);

  big_end_str(aaa);
}

//
// Copy data references
void big_copy_ref(const bigint_t *a, bigint_t **b) {
  char *bbb = malloc(MAXSTR);

  (*b)->len = (*a).len;
  big_alloc_m(1, b);
  big_copy(a, b);
  (*b)->neg = (*a).neg;
  (*b)->len = (*a).len;
  (*b)->base = (*a).base;
  big_end_str(bbb);
}

//
// Clear initial zeros
void big_clear_zeros(bigint_t **b) {
  char *bbb = malloc(MAXSTR);

  while ((*b)->dig[0] == 0 && (*b)->len >= 0) {
    (*b)->len--;
    (*b)->dig++;
  }

  // if the string only contains zeros atleast save one
  big_get(*b, bbb);
  if (strcmp("", bbb) == 0) {
    big_set("0", b);
  }
  big_end_str(bbb);
}

//
// Get string from bigint
void big_get(const bigint_t *a, char *b) {
  int mod = 0;
  int len = (int)strlen(b) > (*a).len ? strlen(b) : (*a).len;

  // Reset outparam
  memset(b, 0, len);

  if (a->neg && a->dig[0] != '-') {
    mod = 1;
    b[0] = '-';
  }
  if (a->base == HEX) {
    b[0 + mod] = '0';
    b[1 + mod] = 'x';
    mod = mod + 2;
  }
  for (int i = 0; i < a->len; i++) {
    if (a->dig[i] < DEC) {
      b[i + mod] = a->dig[i] + '0';
    } else {
      b[i + mod] = (a->dig[i] % 'a') + 'a' - 10;
    }
  }
  b[a->len + mod] = '\0';
}

//
// Get Hex value
i08 big_get_hex(i08 a, i08 base) {
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
  char *aaa = malloc(MAXSTR);
  char *bbb = malloc(MAXSTR);
  int i, j, k, tmp, carry, base, cmpa, cmpb;
  bigint_t *aa = NULL, *bb = NULL;

  big_init_m(2, &aa, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  (*c)->len = (*a).len;
  big_alloc_m(3, &aa, &bb, c);
  base = big_check_set_base(a, c);
  carry = 0;
  (*c)->neg = false;

  big_get(a, aaa);
  big_get(b, bbb);
  big_copy(a, &aa);
  big_copy(b, &bb);

  cmpa = strcmp(aaa, "0");
  cmpb = strcmp(bbb, "0");

  big_end_str(bbb);
  big_end_str(aaa);
  if ((*a).neg && (*b).neg) {
    (*c)->neg = true;
  }
  if (a == NULL || b == NULL) {
    c = NULL;
  } else if (cmpa == 0) {
    big_copy_ref(bb, c);
  } else if (cmpb == 0) {
    big_copy_ref(aa, c);
  } else {
    (*c)->len = (a->len > b->len ? a->len : b->len) + 1;
    i = a->len - 1;
    j = b->len - 1;
    k = (*c)->len - 1;

    while (i >= 0 || j >= 0 || carry > 0) {
      if (i >= 0 && j >= 0) {
        tmp =
          big_get_hex(aa->dig[i], aa->base) + big_get_hex(bb->dig[j], bb->base);
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
  big_free_m(2, &bb, &aa);
  big_final_m(2, &bb, &aa);
}

//
// Bigint multiplication
void big_mul(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, push_left, base;
  bigint_t *aa = NULL, *bb = NULL;

  big_init_m(2, &aa, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  (*c)->len = (*a).len + (*b).len;
  big_alloc_m(3, &aa, &bb, c);

  base = big_check_set_base(a, c);
  carry = 0;

  // reset output parameter
  memset((*c)->dig, 0, (*c)->len * LEN);
  (*c)->neg = false;

  big_copy(a, &aa);
  big_copy(b, &bb);
  aa->len = a->len;
  bb->len = b->len;

  // Set result to correct sign
  if ((*aa).neg && (*bb).neg) {
    (*c)->neg = false;
    (*aa).neg = false;
    (*bb).neg = false;
  } else if ((*aa).neg || (*bb).neg) {
    (*c)->neg = true;
  }

  if (a == NULL || b == NULL) {
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
          tmp = big_get_hex(aa->dig[i], aa->base) *
            big_get_hex(bb->dig[j], bb->base);
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
  big_free_m(2, &bb, &aa);
  big_final_m(2, &bb, &aa);
}

//
// Bigint subtraction
void big_sub(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  char *aaa = malloc(MAXSTR);
  char *bbb = malloc(MAXSTR);
  int i, j, k, tmp, carry, base, cmp, cmpa, cmpb;
  bigint_t *aa = NULL, *bb = NULL;

  big_init_m(2, &aa, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  big_alloc_m(2, &aa, &bb);

  big_get(a, aaa);
  big_get(b, bbb);
  big_copy(a, &aa);
  big_copy(b, &bb);
  cmp = strcmp(aaa, bbb);
  cmpa = strcmp(aaa, "0");
  cmpb = strcmp(bbb, "0");
  big_end_str(bbb);
  big_end_str(aaa);
  base = big_check_set_base(a, c);
  carry = 0;

  // reset output parameter
  memset((*c)->dig, 0, (*c)->len * LEN);

  (*c)->neg = false;
  (*c)->len = (*a).len;
  if (cmp == 0) { // both a and b are the same
    big_set("0", c);
  } else {
    if ((*a).neg && (*b).neg) {
      (*aa).neg = false;
      (*bb).neg = false;
      if (cmp < 0) {
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
        if (cmp < 0) {
          (*c)->neg = true;
        }
      }
    } else {
      if (a == NULL || b == NULL) {
        c = NULL;
      } else if (cmpa == 0 && cmpb == 0) {
        big_set("0", c);
      } else if (cmpa == 0) {
        (*bb).neg = true;
        big_copy_ref(bb, c);
        big_clear_zeros(c);
      } else if (cmpb == 0) {
        (*c)->len = a->len;
        big_copy_ref(aa, c);
        big_clear_zeros(c);
      } else {
        (*c)->len = (a->len > b->len ? a->len : b->len);
        if (a->len >= b->len) {
          big_copy(a, &aa);
          big_copy(b, &bb);
          (*aa).len = a->len;
          (*bb).len = b->len;
        } else {
          (*c)->neg = true;
          big_copy(a, &bb);
          big_copy(b, &aa);
          (*aa).len = b->len;
          (*bb).len = a->len;
        }
        i = (*aa).len - 1;
        j = (*bb).len - 1;
        k = (*c)->len - 1;
        carry = 0;
        while (i >= 0 || j >= 0 || carry > 0) {
          if (i >= 0 && j >= 0) {
            tmp = big_get_hex((*aa).dig[i], (*aa).base) -
              big_get_hex((*bb).dig[j], (*bb).base);
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
  }
  //  big_free_m(2, &bb, &aa);
  //  big_final_m(2, &bb, &aa);
}

//
// Subtraction for internal use, meaning inside of big loops or when you know it
// has data and not to become negative, like a counter towards zero.
void big_sub_internal(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, base;
  bigint_t *aa = NULL, *bb = NULL;

  big_init_m(2, &aa, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  big_alloc_m(2, &aa, &bb);

  big_copy(a, &aa);
  big_copy(b, &bb);
  base = big_check_set_base(a, c);
  carry = 0;

  // reset output parameter
  memset((*c)->dig, 0, (*c)->len * LEN);
  (*c)->neg = false;
  (*c)->len = (*a).len;

  (*c)->len = (a->len > b->len ? a->len : b->len);
  i = (*aa).len - 1;
  j = (*bb).len - 1;
  k = (*c)->len - 1;

  if (big_cmp(a, b)) { // both a and b are the same
    big_set("0", c);
  } else {
    while (i >= 0 || j >= 0 || carry > 0) {
      if (i >= 0 && j >= 0) {
        tmp = big_get_hex((*aa).dig[i], (*aa).base) -
          big_get_hex((*bb).dig[j], (*bb).base);
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
  big_free_m(2, &bb, &aa);
  big_final_m(2, &bb, &aa);
}

//
// Bigint division
void big_div_sub(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  bigint_t *aa = NULL, *e = NULL, *bb = NULL;
  bigint_t *co1 = NULL, *co2 = NULL, *one = NULL;

  big_init_m(6, &aa, &e, &bb, &co1, &co2, &one);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  (*e).len = (*a).len;
  (*c)->len = (*a).len;
  (*co1).len = 5;
  (*co2).len = 5;
  (*one).len = 2;

  big_alloc_m(7, &aa, &bb, &co1, &co2, &one, &e, c);
  big_copy(a, &aa);
  big_copy(b, &bb);
  aa->len = a->len;
  bb->len = b->len;
  big_set("1", &one);
  big_set("0", &co1);
  while ((aa->len >= bb->len) && (e->neg == false && aa->neg == false)) {
    big_sub(aa, bb, &e);
    big_copy(e, &aa);
    aa->neg = e->neg;
    aa->len = e->len;

    // co++
    big_add(co1, one, &co2);
    big_copy(co2, &co1);
  }
  if (aa->neg == true) {
    // co--
    big_sub(co1, one, &co2);
    big_copy(co2, &co1);
  }
  big_copy(co2, c);
  //  big_free_m(4, &one, &co1, &bb, &aa);
  //  big_final_m(4, &one, &co1, &bb, &aa);
}

void big_div(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  bigint_t *aa = NULL, *bb = NULL, *cc = NULL, *cc1 = NULL, *aa1 = NULL;
  int len_a, len_b, len_diff, cmp, cmp1;
  char *aaa = malloc(MAXSTR);
  char *bbb = malloc(MAXSTR);

  big_init_m(5, &aa, &bb, &cc, &aa1, &cc1);
  (*aa).len = (*a).len;
  (*bb).len = (*a).len;
  (*aa1).len = (*a).len;
  (*cc).len = (*a).len;
  (*cc1).len = (*a).len;
  (*c)->len = (*a).len;
  big_alloc_m(6, &aa, &bb, &cc, &aa1, &cc1, c);

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

  len_a = strlen(aaa);
  len_b = strlen(bbb);
  cmp = strcmp(aaa, bbb);
  cmp1 = strcmp(bbb, "1");

  big_end_str(bbb);
  big_end_str(aaa);

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
  } else if (cmp == 0) {
    big_set("1", c);
  } else if (cmp <= 0 && len_a == len_b) {
    big_set("0", c);
  } else if (cmp1 == 0) {
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
        big_copy(aa1, &aa);
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
  //  big_free_m(5, &cc1, &aa1, &cc, &bb, &aa);
  //  big_final_m(5, &cc1, &aa1, &cc, &bb, &aa);
}

//
// Subtraction for internal use, meaning inside of big loops or when you know it
// has data and not to become negative, like a counter towards zero.
void big_div_internal(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  bigint_t *aa = NULL, *bb = NULL, *cc = NULL, *cc1 = NULL, *aa1 = NULL;
  bigint_t *one = NULL, *co1 = NULL, *co2 = NULL, *e = NULL, *aa2 = NULL;
  int len_b, len_diff, cmp, cmp1;

  big_init_m(10, &aa, &bb, &cc, &aa1, &aa2, &cc1, &one, &co1, &co2, &e);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  (*cc).len = (*a).len;
  (*aa1).len = (*a).len;
  (*aa2).len = (*a).len;
  (*cc1).len = (*a).len;
  (*e).len = (*a).len;
  big_alloc_m(7, &aa, &bb, &cc, &aa1, &cc1, &aa2, &e);
  big_alloc_len(&one, 1);
  big_alloc_len(&co1, 1);
  big_alloc_len(&co2, 1);

  // reset output parameter
  (*c)->neg = false;
  (*c)->len = 1;

  // Create copy of a & b
  cmp = big_cmp(a, b);
  cmp1 = big_cmp_str("1", b);
  big_copy(a, &aa);
  big_copy(a, &aa2);
  big_copy(b, &bb);

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
  } else if (cmp == 1) {
    big_set("1", c);
  } else if (cmp <= 1 && (*aa).len == (*bb).len) {
    big_set("0", c);
  } else if (cmp1 == 1) {
    big_copy_ref(aa, c);
  } else {
    len_diff = (*aa).len - (*bb).len;
    len_b = (*bb).len;
    for (int i = 0; i <= len_diff; i++) { // Fill divisor with zeros
      (*bb).dig[len_b + i] = 0;
      (*bb).len++;
    }
    for (int j = 0; j <= len_diff; j++) {
      if ((u64)(*bb).len >= (u64)(*b).len) {
        (*bb).len--;
      }
      len_b = (*bb).len;
      big_set("1", &one);
      big_set("0", &co1);
      aa->neg = false;
      e->neg = false;
      while ((aa->len >= bb->len) && (e->neg == false && aa->neg == false)) {
        big_sub_internal(aa, bb, &e);
        big_copy(e, &aa);
        aa->neg = e->neg;
        aa->len = e->len;

        // co++
        big_add(co1, one, &co2);
        big_copy(co2, &co1);
      }
      if (aa->neg == true) {
        // co--
        big_sub_internal(co1, one, &co2);
        big_copy(co2, &co1);
      }
      big_copy(co1, &cc);
      big_copy(aa2, &aa);

      if ((*cc).dig[0] != 0 && (*cc).len == 1) {
        big_mul(bb, cc, &cc1);
        big_sub_internal(aa, cc1, &aa1);
        big_clear_zeros(&aa1);
        big_copy(aa1, &aa);
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
  //  big_free_m(3, &co2, &co1, &one);
  big_free_m(6, &aa2, &cc1, &aa1, &cc, &bb, &aa);
  //  big_final_m(3, &co2, &co1, &one);
  big_final_m(6, &aa2, &cc1, &aa1, &cc, &bb, &aa);
}

//
// Bigint modulo
void big_mod(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  bigint_t *aa = NULL, *bb = NULL, *cc = NULL, *cc1 = NULL, *g = NULL;
  bool n = false;

  big_init_m(6, &aa, &bb, &cc, &cc1, &g, c);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;
  (*cc).len = (*a).len;
  (*cc1).len = (*a).len;
  (*g).len = (*a).len;
  big_alloc_m(6, &aa, &bb, &cc, &cc1, &g, c);

  (*c)->neg = false;
  (*c)->len = 1;

  // Create copy of a & b
  big_copy(a, &aa);
  big_copy(b, &bb);
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
  //  big_free_m(3, &g, &cc1, &cc);
  big_free_m(2, &bb, &aa);
  //  big_final_m(3, &g, &cc1, &cc);
  big_final_m(2, &bb, &aa);
}

//
// Bigint &1
bool big_bit_and_one(bigint_t *a) {
  return (*a).dig[(*a).len - 1] & 1;
}

//
// Check what base a has and set that to b
i08 big_check_set_base(const bigint_t *a, bigint_t **b) {
  i08 base;
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
  char *aaa = malloc(MAXSTR);
  bigint_t *aa = NULL;

  big_init_m(1, &aa);
  (*aa).len = (*a)->len;
  big_alloc_m(1, &aa);
  big_get(*a, aaa);
  printf("%s\n", aaa);

  big_free_m(1, &aa);
  big_final_m(1, &aa);
  big_end_str(aaa);
}

//
// Assert two bigints are the same
void big_assert(bigint_t **b1, bigint_t **b2) {
  char *aaa = malloc(MAXSTR);
  char *bbb = malloc(MAXSTR);

  big_get(*b1, aaa);
  big_get(*b2, bbb);
  assert(strcmp(aaa, bbb) == 0);

  big_end_str(bbb);
  big_end_str(aaa);
}

//
// Assert a string and bigint is the same
void big_assert_str(char *str, bigint_t **b2) {
  char *bbb = malloc(MAXSTR);

  big_get(*b2, bbb);
  assert(strcmp(str, bbb) == 0);

  big_end_str(bbb);
}
