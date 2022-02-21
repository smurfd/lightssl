//                                                                            //
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <stdbool.h>
#include "lightbig.h"

// TODO: obviously huge room for improvement
// TODO: handle hex not just base 10
// TODO: free()
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
  int skip;

  skip = 0;
  big_init(b);
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
    big_alloc(&(*b));
    (*b)->dig[0] = 0;
  } else if (strcmp("", a) == 0) {
    (*b)->len = 1;
    big_alloc(&(*b));
  } else {
    while (a[skip] == '0') {
      skip++;
    }

    (*b)->len = strlen(a) - skip;
    if ((*b)->len == 0) {
      (*b)->len++;
      big_alloc(&(*b));
      (*b)->dig[0] = 0;
    } else {
      big_alloc(&(*b));
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
// Copy data
void big_copy(bigint_t *a, bigint_t **b) {
  for (int f = 0; f < (*a).len; f++) {
    (*b)->dig[f] = (*a).dig[f];
  }
  (*b)->neg = (*a).neg;
  (*b)->base = (*a).base;
}

// Copy data refs, replaces (*a) = (*b)
void big_copy_ref(bigint_t *a, bigint_t **b) {
  (*b)->neg = (*a).neg;
  (*b)->len = (*a).len;
  (*b)->base = (*a).base;
  big_alloc(&(*b));
  for (int l = 0; l < (*a).len; l++) {
    (*b)->dig[l] = (*a).dig[l];
  }
}

//
// Clear initial zero
void big_clear_zero(bigint_t **b) {
  if ((*b)->dig[0] == 0) {
    (*b)->len--;
    (*b)->dig++;
  }
}

//
// Clear initial zero
void big_clear_zero2(bigint_t **b) {
  if ((*b)->dig[0] == 0 && (*b)->len != 1) {
    (*b)->len--;
    (*b)->dig++;
  }
}

//
// Clear initial zeros
void big_clear_zeros(bigint_t **b) {
  while ((*b)->dig[0] == 0 && (*b)->len >= 0) {
    (*b)->len--;
    (*b)->dig++;
  }
  // if the string only contains zeros atleast save one
  if (strcmp("", big_get(*b)) == 0) {
    big_set("0", b);
  }
}

//
// Get string from bigint
char *big_get(bigint_t *a) {
  char *b = malloc(BIGLEN); //
  int mod = 0;

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
  return b;
}

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
void big_add(bigint_t *a, bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, base;
  bigint_t *aa, *bb;

  big_init_m(2, &aa, &bb);
  base = big_check_set_base(a, c);
  carry = 0;
  memset((*c), 0, sizeof(bigint_t));
  memset((*c)->dig, 0, (*c)->len*sizeof(int));
  big_set(big_get(a), &aa);
  big_set(big_get(b), &bb);

  if ((*a).neg && (*b).neg) {
    (*aa).neg = false;
    (*bb).neg = false;
    (*c)->neg = true;
    big_add(aa, bb, c);
  } else {
    if (a == NULL) {
      c = NULL;
    } else if (b == NULL) {
      c = NULL;
    } else if (strcmp(big_get(a), "0") == 0) {
      big_copy_ref(b, c);
    } else if (strcmp(big_get(b), "0") == 0) {
      big_copy_ref(a, c);
    } else {
      (*c)->len = (a->len > b->len ? a->len : b->len) + 1;
      if (!(*c)->alloc_d) {
        big_alloc(&(*c));
      }
      i = a->len - 1;
      j = b->len - 1;
      k = (*c)->len - 1;

      while (i >= 0 || j >= 0 || carry > 0) {
        if (i >= 0 && j >= 0) {
          tmp = big_get_hex(a->dig[i], a->base) + big_get_hex(b->dig[j],
              b->base);
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
      big_clear_zero(&(*c));
    }
  }
  big_end_m(2, &aa, &bb);
}

//
// Bigint multiplication
void big_mul(bigint_t *a, bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, push_left, base;

  //big_init(c);
  memset((*c), 0, sizeof(bigint_t));
  memset((*c)->dig, 0, (*c)->len*sizeof(int));

  base = big_check_set_base(a, c);
  // Set result to correct sign
  if ((*a).neg && (*b).neg) {
    (*c)->neg = false;
  } else if ((*a).neg || (*b).neg) {
    (*c)->neg = true;
  }

  if (a == NULL) {
    c = NULL;
  } else if (b==NULL) {
    c = NULL;
  } else if ((*a).len == 1 && (*a).dig[0] == 0) {
    big_end(&(*c));
    (*c)->len = 1;
    big_alloc(&(*c));
    big_set("0", c);
  } else if ((*b).len == 1 && (*b).dig[0] == 0) {
    big_end(&(*c));
    (*c)->len = 1;
    big_alloc(&(*c));
    big_set("0", c);
  } else {
    big_end(&(*c));
    (*c)->len = a->len + b->len;
    big_alloc(&(*c));
    i = a->len - 1;
    j = b->len - 1;
    k = (*c)->len - 1;
    carry = 0;
    push_left = 0;
    while (i >= 0) {
      k = (*c)->len - 1 - push_left++;
      j = b->len - 1;
      while (j >= 0 || carry > 0) {
        if (j >= 0) {
          tmp = big_get_hex(a->dig[i], a->base) * big_get_hex(b->dig[j],
              b->base);
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
    big_clear_zeros(&(*c));
  }
}

//
// Bigint subtraction
void big_sub(bigint_t *a, bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry;
  bigint_t *d, *e, *f, *aa, *bb;

  big_init_m(5, &d, &e, &f, &aa, &bb);
  big_set_m(5, &d, &e, &f, &aa, &bb);
  big_set(big_get(a), &aa);
  big_set(big_get(b), &bb);
  big_copy_ref(b, &f);
  memset((*c), 0, sizeof(bigint_t));
  memset((*c)->dig, 0, (*c)->len*sizeof(int));
  (*c)->len = f->len;
  if ((*a).neg && (*b).neg) {
    (*aa).neg = false;
    (*bb).neg = false;
    if (strcmp(big_get(a), big_get(b)) < 0) {
      big_sub(bb, aa, c);
    } else {
      big_sub(aa, bb, c);
      (*c)->neg = false;
    }
  } else if ((*a).neg) {
    big_add(a, b, c);
    if ((*a).len < (*b).len) {
      (*c)->neg = true;
    }
    if ((*a).len == (*b).len) {
      if (strcmp(big_get(a), big_get(b)) < 0) {
        (*c)->neg = true;
      }
    }
  } else if ((*b).neg) {
    big_add(a, b, c);
  } else {
    if (a == NULL) {
      c = NULL;
    } else if (b == NULL) {
      c = NULL;
    } else if (strcmp(big_get(a), "0") == 0 && strcmp(big_get(b), "0") == 0) {
      big_set("0", c);
    } else if (strcmp(big_get(a), "0") == 0) {
      (*f).neg = true;
      big_copy_ref(f, c);
      big_clear_zero2(&(*c));
    } else if (strcmp(big_get(b), "0") == 0) {
      (*c)->len = a->len;
      big_copy_ref(a, c);
      big_clear_zero2(&(*c));
    } else {
      big_end(&(*c));
      (*c)->len = (a->len > b->len ? a->len : b->len);
      big_alloc(&(*c));
      if (a->len > b->len) {
        (*d).len = a->len;
        (*e).len = b->len;
        big_alloc(&d);
        big_alloc(&e);
        big_copy(a, &d);
        big_copy(b, &e);
        i = d->len - 1;
        j = e->len - 1;
      } else if (b->len > a->len) {
        (*d).len = b->len;
        (*e).len = a->len;
        big_alloc(&d);
        big_alloc(&e);
        (*c)->neg = true;
        big_copy(b, &d);
        big_copy(a, &e);
        i = d->len - 1;
        j = e->len - 1;
      } else {
        (*d).len = a->len;
        (*e).len = b->len;
        big_alloc(&d);
        big_alloc(&e);
        big_copy(a, &d);
        big_copy(b, &e);
        i = d->len - 1;
        j = e->len - 1;
      }

      carry = 0;
      k = (*c)->len - 1;
      while (i >= 0 || j >= 0 || carry > 0) {
        if (i >= 0 && j >= 0) {
          tmp = (*d).dig[i]-(*e).dig[j];
          if (tmp < 0) {
            if (i == 0 && j == 0) {
              (*c)->neg = true;
            }
            tmp += 10;
            d->dig[i-1] -= 1;
          }
        } else if (i >= 0) {
          tmp = d->dig[i];
        } else if (j >= 0) {
          tmp = e->dig[j];
        } else {
          tmp = 0;
        }
        tmp -= carry;
        carry = tmp / 10;
        if (tmp % 10 < 0 && i < 2) {
          (*c)->dig[k] = (tmp % 10) + 10;
          if ((*c)->dig[k-1] > 0) {
            (*c)->dig[k-1] = (*d).dig[k-1] - 1;
          } else {
            (*c)->dig[k-1] = (*d).dig[k-1] - 1;
            break;
          }
        } else {
          (*c)->dig[k] = tmp % 10;
        }
        i--;
        j--;
        k--;
      }
      big_clear_zero2(&(*c));
      if (j > i) {
        (*c)->neg = true;
      }
    }
  }
}

//
// Bigint division
void big_div_x(bigint_t *a, bigint_t *b, bigint_t **d) {
  char *str = (char*) malloc(MAXSTR);
  bool nm = false;
  u_int64_t co;
  bigint_t *c, *e, *f;

  co = 0;
  big_init_m(3, &c, &e, &f);
  (*d)->len = (a->len > b->len ? a->len : b->len);
  big_set_m(3, &c, &e, &f);
  big_set(big_get(a), &c);

  memset((*d), 0, sizeof(bigint_t));
  memset((*d)->dig, 0, (*d)->len*sizeof(int));
  if (c->neg) {
    nm = true;
  }
  while (c->len >= b->len && ((c->neg == false && nm == false) ||
      (c->neg == true && nm == true))) {
    big_sub(c, b, &e);
    big_copy_ref(e, &c);
    big_clear_zero(&c);
    co++;
  }
  if (c->neg == true) {
     co--;
  }
  sprintf(str, "%llu", co);
  big_set(str, d);
  free(str);
}

void big_div(bigint_t *a, bigint_t *b, bigint_t **d) {
  int len, len123;
  bigint_t *c, *e, *w, *res, *v, *x, *y, *z, *f, *tmp, *tmp2, *ff;
  big_init_m(12, &v, &x, &y, &z, &f, &c, &e, &w, &res, &tmp, &tmp2, &ff);
  big_set_m(12, &v, &x, &y, &z, &f, &c, &e, &w, &res, &tmp, &tmp2, &ff);

  // Set result to correct sign
  if ((*a).neg || (*b).neg) {
    (*d)->neg = true;
  }

  if (a == NULL) {
    d = NULL;
  } else if (b == NULL) {
    d = NULL;
  } else if (strcmp(big_get(a), big_get(b)) == 0) {
    big_set("1", d);
  } else if (strcmp(big_get(a), big_get(b)) <= 0 && strlen(big_get(a)) ==
        strlen(big_get(b))) {
    big_set("0", d);
  } else if (strcmp(big_get(b), "1") == 0) {
    big_copy_ref(a, d);
  } else {
    len123 = 0;
    len = strlen(big_get(a)) - strlen(big_get(b));
    big_copy_ref(a, &c);
    big_copy_ref(c, &w);

    // hack to run the below loop even if the numbers have the same length
    if (len == 0) {
      len = 1;
    }
    for (int i = 0; i < len; i++) {
      big_copy_ref(b, &e);
      int len1 = strlen(big_get(c));
      int len2 = strlen(big_get(e));
      int len3 = len1-len2-1;
      if (len3 > 0) {
        int clen;
        char *ccc = malloc(MAXSTR);
        char *cc = malloc(MAXSTR);
        strcpy(cc, big_get(e));
        if (len1 >= len3 + 4) {
          len3 = len1 - 4;
        }

        // fill out with zeros, hack to save tons of iterations
        for (int j = 0; j <= len3; j++) {
          cc[len2+j] = '0';
        }
        cc[len3+1] = '\0';
        big_set(cc, &e);
        if (len < 4) {
          (*e).len=len3 + 2;
        } else {
          if (len3+1>=len2) {
            (*e).len=len3 + 1;
          } else {
            (*e).len = len2;
          }
        }

        big_copy_ref(c, &w);
        big_copy_ref(e, &x);
        big_div_x(w, x, &y);
        strcpy(ccc, big_get(y));
        clen = strlen(ccc);
        for (int k = 0; k < clen; k++) {
          if (i == 0 && clen > 1) {
            // 1st run, populate result with big-num divs ie first nums
            // in result
            for (u_int64_t l = 0; l < strlen(ccc); l++) {
              (*res).dig[l] = ccc[l] - '0';
            }
            (*res).len = strlen(ccc);
            len123 = strlen(ccc);
            break;
          } else if (clen > 1) {
            // If the number of divisions exceed 9 we do this
            char *ccc1 = malloc(MAXSTR);

            if ((*res).len < clen) {
              (*res).len = clen;
            }
            len123  = strlen(ccc) > strlen(ccc1) ? strlen(ccc):strlen(ccc1);
            strcpy(ccc1, big_get(res));
            // This hack adds a 0 to thec 1st couple of numbers so they add
            // upp correctly
            if (clen > 3 && i >= 1) {
              ccc1[clen] = '0';
              ccc1[clen + 1] = '\0';
            }
            big_set(ccc1, &tmp);
            big_set(ccc, &tmp2);
            (*res).len = strlen(ccc) > strlen(ccc1) ? strlen(ccc):strlen(ccc1);
            big_add(tmp2, tmp, &res);
            free(ccc1);
            break;
          } else {
            // Modify where to position the next character depening on the
            // above hacks to save repetitions
            if (i==1 && clen == 1 && (len123 == 3 || len123 > 4)) {
              len123--;
            }
            if (len123 > (*res).len && i > 4) {
              (*res).len = len123+1;
            }
            (*res).dig[len123] = ccc[k] - '0';
            break;
          }
        }
        (*res).len = len123;
        big_mul(x, y, &z);
        big_set(big_get(w), &f);
        big_sub(w, z, &v);
        big_copy_ref(v, &c);
        big_copy_ref(f, &w);
        len123++;
      } else {
        big_clear_zeros(&c);
        big_set(big_get(c), &ff);
        big_div_x(c, b, d);
        if (strcmp(big_get(*d), "0") != 0) {
          int mod = 1;
          if (i > 4) {
            mod = 2;
          }
          (*res).len = i + mod;
          for (u_int64_t j = 0; j < strlen(big_get(*d)); j++) {
            (*res).dig[i + j + (mod - 1)] = (*d)->dig[j];
            (*res).len = i + j + mod;
          }
        } else if (i == 2 && (*res).len == 2) {
          (*res).len++;
        }
        break;
      }
    }
    big_clear_zeros(&res);
    big_copy_ref(res, d);
  }
}

//
// Bigint modulo
void big_mod(bigint_t *a, bigint_t *b, bigint_t **e) {
  bigint_t *c, *d, *f, *g;
  bool n = false;
  int base;

  big_init_m(5, e, &c, &d, &f, &g);
  big_set_m(4, e, &c, &d, &f);
  big_set("1", &g);
  base = big_check_set_base(a, e);

  if (a == NULL) {
    e = NULL;
  } else if (b == NULL) {
    e = NULL;
  } else {
    big_copy_ref(a, &f);
    if ((*a).neg) {
      (*f).neg = false;
      n = true;
    }
    big_div(f, b, &c);
    if (n) {
      big_add(c, g, &c);
    }
    if (n && (*c).neg == false) {
      (*c).neg = true;
    }
    big_mul(c, b, &d);
    (*e)->len = (f->len > d->len ? f->len : d->len);
    if (!(*e)->alloc_d) {
      big_alloc(e);
    }
    big_sub(a, d, e);
    big_clear_zeros(&(*e));
  }
  big_end_m(2, &f, &g);
}

bool big_bit_and_one(bigint_t *a) {
  return (*a).dig[(*a).len - 1] & 1;
}

int big_check_set_base(bigint_t *a, bigint_t **b) {
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
void big_print(bigint_t **a) {
  char *c = (char*) malloc((*a)->len);

  printf("%s\n", big_get(*a));
  free(c);
}

// Assert
void big_assert(bigint_t **b1, bigint_t **b2) {
  assert(strcmp(big_get(*b1), big_get(*b2)) == 0);
}

void big_assert_str(char* str, bigint_t **b2) {
  assert(strcmp(str, big_get(*b2)) == 0);
}
