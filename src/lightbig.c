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
// Set a bigint from string
void big_set_2(char *a, bigint_t **b) {
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
void big_copy(const bigint_t *a, bigint_t **b) {
  for (int f = 0; f < (*a).len; f++) {
    (*b)->dig[f] = (*a).dig[f];
  }
  (*b)->neg = (*a).neg;
  (*b)->base = (*a).base;
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
char *big_get(const bigint_t *a) {
  char *b = (char*) malloc(BIGLEN); //
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

//
// Get string from bigint
void big_get_2(const bigint_t *a, char *b) {
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
// Bigint addition
void big_add_2(const bigint_t *a, const bigint_t *b, bigint_t **c) {
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

  big_get_2(a, aaa);
  big_get_2(b, bbb);
  big_set_2(aaa, &aa);
  big_set_2(bbb, &bb);

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
  if (bbb) {
    free(bbb);
  }
  if (aaa) {
    free(aaa);
  }
  big_end_m(2, &aa, &bb);
}

//
// Bigint multiplication
void big_mul(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, push_left, base;

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
// Bigint multiplication
void big_mul_2(const bigint_t *a, const bigint_t *b, bigint_t **c) {
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

  big_get_2(a, aaa);
  big_get_2(b, bbb);
  big_set_2(aaa, &aa);
  big_set_2(bbb, &bb);
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
  if (bbb) {
    free(bbb);
  }
  if (aaa) {
    free(aaa);
  }
  big_end_m(2, &aa, &bb);
}

//
// Bigint subtraction
void big_sub(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry;
  bigint_t *d, *e, *aa, *bb; //*f;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);
  bool bret = false;

  big_init_m(4, &d, &e, &aa, &bb);
  big_set_m(2, &d, &e);//, &f);//, &aa, &bb);
  strcpy(aaa, big_get(a));
  strcpy(bbb, big_get(b));
  big_set(aaa, &aa);
  big_set(bbb, &bb);
      big_copy(aa, &d);
      big_copy(bb, &e);

  //big_copy_ref(b, &f);
  memset((*c), 0, sizeof(bigint_t));
  memset((*c)->dig, 0, (*c)->len*sizeof(int));
  //(*c)->len = f->len;
  if ((*a).neg && (*b).neg) {
  // Handle if both a & b is negative
    (*aa).neg = false;
    (*bb).neg = false;
    if (strcmp(aaa, bbb) < 0) {
      big_copy(bb, &d);
      big_copy(aa, &e);
      //big_sub(bb, aa, c);
    } else {
      big_copy(aa, &d);
      big_copy(bb, &e);
      //big_sub(aa, bb, c);
      (*c)->neg = false;
    }
  } else if ((*a).neg || (*b).neg) {
    // Handle if only a or b is negative
    big_add(aa, bb, c);
    //big_add(a, b, c);
    bret = true;
    if ((*a).len < (*b).len || (*a).len > (*b).len) {
      (*c)->neg = true;
    }
    if ((*a).len == (*b).len) {
      if (strcmp(aaa, bbb) < 0) {
        (*c)->neg = true;
      }
    }
//  } else if ((*b).neg) {
//    big_add(a, b, c);
  }// else {
  if (bret == false) {
    if (a == NULL) {
      c = NULL;
    } else if (b == NULL) {
      c = NULL;
    } else if (strcmp(aaa, "0") == 0 && strcmp(bbb, "0") == 0) {
      big_set("0", c);
    } else if (strcmp(aaa, "0") == 0) {
      (*bb).neg = true;
      //(*f).neg = true;
      //big_copy_ref(f, c);
      big_copy_ref(bb, c);
      big_clear_zero2(&(*c));
    } else if (strcmp(bbb, "0") == 0) {
      (*c)->len = a->len;
      big_copy_ref(aa, c);
      //big_copy_ref(a, c);
      big_clear_zero2(&(*c));
    } else {
      big_end(&(*c));
      (*c)->len = (a->len > b->len ? a->len : b->len);
      big_alloc(&(*c));
      if (a->len > b->len) {
        (*d).len = a->len;
        (*e).len = b->len;
        //big_alloc(&d);
        //big_alloc(&e);
//  memset(d, 0, sizeof(bigint_t));
//  memset((*d).dig, 0, (*d).len*sizeof(int));
//  memset(e, 0, sizeof(bigint_t));
//  memset((*e).dig, 0, (*e).len*sizeof(int));

        //big_copy(a, &d);
        //big_copy_ref(a, &d);
        big_copy_ref(aa, &d);
        //big_copy(b, &e);
        //big_copy_ref(b, &e);
        big_copy_ref(bb, &e);
        i = d->len - 1;
        j = e->len - 1;
      } else if (b->len > a->len) {
        (*d).len = b->len;
        (*e).len = a->len;
        //big_alloc(&d);
        //big_alloc(&e);
//  memset(d, 0, sizeof(bigint_t));
//  memset((*d).dig, 0, (*d).len*sizeof(int));
//  memset(e, 0, sizeof(bigint_t));
//  memset((*e).dig, 0, (*e).len*sizeof(int));
        (*c)->neg = true;
        //big_copy(b, &d);
        //big_copy_ref(b, &d);
        big_copy_ref(bb, &d);
        //big_copy(a, &e);
        //big_copy_ref(a, &e);
        big_copy_ref(aa, &e);
        i = d->len - 1;
        j = e->len - 1;
      } else {
        (*d).len = a->len;
        (*e).len = b->len;
        //big_alloc(&d);
        //big_alloc(&e);
//  memset(d, 0, sizeof(bigint_t));
//  memset((*d).dig, 0, (*d).len*sizeof(int));
//  memset(e, 0, sizeof(bigint_t));
//  memset((*e).dig, 0, (*e).len*sizeof(int));
        //big_copy(a, &d);
        //big_copy_ref(a, &d);
        big_copy_ref(aa, &d);
        //big_copy(b, &e);
        //big_copy_ref(b, &e);
        big_copy_ref(bb, &e);
        i = d->len - 1;
        j = e->len - 1;
      }

      carry = 0;
      k = (*c)->len - 1;
      while (i >= 0 || j >= 0 || carry > 0) {
        if (i >= 0 && j >= 0) {
          tmp = (*d).dig[i] - (*e).dig[j];
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
  //}
  //big_end_m(3, &f, &aa, &bb);
  if (bbb) free(bbb);
  if (aaa) free(aaa);
}

//
// Bigint addition
void big_sub_2(const bigint_t *a, const bigint_t *b, bigint_t **c) {
  int i, j, k, tmp, carry, base;
  bigint_t *aa, *bb;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);

  big_init_m(2, &aa, &bb);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(c, MAXSTR);

  big_get_2(a, aaa);
  big_get_2(b, bbb);
  big_set_2(aaa, &aa);
  big_set_2(bbb, &bb);

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
      big_sub_2(bb, aa, c);
    } else {
      big_sub_2(aa, bb, c);
      (*c)->neg = false;
    }
  } else if ((*a).neg || (*b).neg) {
    (*aa).neg = false;
    (*bb).neg = false;
    big_add_2(aa, bb, c);
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
      big_clear_zero2(c);
    } else if (strcmp(bbb, "0") == 0) {
      (*c)->len = a->len;
      big_copy_ref(aa, c);
      big_clear_zero2(c);
    } else {
      (*c)->len = (a->len > b->len ? a->len : b->len);
      if (a->len > b->len) {
        memset((*aa).dig, 0, (*aa).len * sizeof(int));
        memset((*bb).dig, 0, (*bb).len * sizeof(int));
        big_set_2(aaa, &aa);
        big_set_2(bbb, &bb);
        (*aa).len = a->len;
        (*bb).len = b->len;
        i = (*aa).len - 1;
        j = (*bb).len - 1;
      } else if (b->len > a->len) {
        memset((*aa).dig, 0, (*aa).len * sizeof(int));
        memset((*bb).dig, 0, (*bb).len * sizeof(int));
        (*c)->neg = true;
        big_set_2(bbb, &aa);
        big_set_2(aaa, &bb);
        (*aa).len = b->len;
        (*bb).len = a->len;
        i = (*aa).len - 1;
        j = (*bb).len - 1;
      } else {
        memset((*aa).dig, 0, (*aa).len * sizeof(int));
        memset((*bb).dig, 0, (*bb).len * sizeof(int));
        big_set_2(aaa, &aa);
        big_set_2(bbb, &bb);
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
        printf("NEG\n");
        (*c)->neg = true;
      }
    }
  }
  if (bbb) {
    free(bbb);
  }
  if (aaa) {
    free(aaa);
  }
  big_end_m(2, &aa, &bb);
}

//
// Bigint division
void big_div_x(const bigint_t *a, const bigint_t *b, bigint_t **d) {
  char *str1 = (char*) malloc(MAXSTR);
  char *str2 = (char*) malloc(MAXSTR);
  bool nm = false;
  int coo = 0;
  bigint_t *b1, *c, *e, *f, *count, *count2, *one;

  big_init_m(7, &b1, &c, &e, &f, &count, &one, &count2);
  (*d)->len = (a->len > b->len ? a->len : b->len);
  big_set_m(6, &b1, &e, &f, &count, &one, &count2);
  big_set("1", &one);

  strcpy(str1, big_get(a));
  strcpy(str2, big_get(b));
big_set(big_get(a), &c);
//  big_set(str1, &c);
  big_set(str2, &b1);
  memset((*d), 0, sizeof(bigint_t));
  memset((*d)->dig, 0, (*d)->len * sizeof(int));
  if ((*a).neg) {
    nm = true;
  }
  while ( (c->len >= b->len) &&
       ((c->neg == false && nm == false) || (c->neg == true && nm == true) ))  {
    big_sub_2(c, b1, &e);
    printf("SUB : %s - %s = %s\n", big_get(c), big_get(b1), big_get(e));
// memset((*c).dig, 0, (*c).len * sizeof(int));
    big_copy_ref(e, &c);
// memset((*e).dig, 0, (*e).len * sizeof(int));
    big_clear_zeros(&c);
    //big_clear_zeros(&e);
    big_set(str2, &b1);
    //(*c).len = (*e).len;
    //printf("len : %d %d %d %d : %d : %d\n", c->len, b1->len, c->neg, nm, (c->neg == false && nm == false), (c->neg == true && nm == true));
    big_add(count, one, &count2);
    big_copy_ref(count2, &count);
    coo++;
    //if (c->neg) break;
  }
  if (c->neg == true) {
    big_sub_2(count, one, &count2);
    //big_init(&count);
    big_copy_ref(count2, &count);
  }
  if ((*count).len > 2) {
    if (c->neg == true) printf("NEG\n");
    printf("cooo = %d %s\n", coo, big_get(count));
    printf("%s // %s\n", big_get(a), big_get(b));
    //exit(0);
  }
  big_set(big_get(count), d);
  if (str2) {
    free(str2);
  }
  if (str1) {
    free(str1);
  }
}

//
// Bigint division
void big_div_x_2(const bigint_t *a, const bigint_t *b, bigint_t **d) {
  char *str = (char*) malloc(MAXSTR);
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);
  char *aaa1 = (char*) malloc(MAXSTR);
  char *bbb1 = (char*) malloc(MAXSTR);
  char *str1 = (char*) malloc(MAXSTR);
  bool nm = false;
  u64 co;
  bigint_t *aa, *e, *f, *bb;

  big_get_2(a, aaa);
  big_get_2(b, bbb);
  co = 0;
  big_init_m(4, &aa, &e, &f, &bb);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(&e, MAXSTR);
  big_alloc_2(d, MAXSTR);
  big_set_2(aaa, &aa);
  big_set_2(bbb, &bb);
  aa->len = a->len;
  bb->len = b->len;
  if (aa->neg) {
    nm = true;
  }
  while ((aa->len >= bb->len) && e->neg == false) {
    big_sub_2(aa, bb, &e);
    big_set_2(bbb, &bb);
    big_get_2(e, str1);
    big_set_2(str1, &aa);
    aa->neg = e->neg;
    aa->len = e->len;
    bb->len = b->len;
    co++;
    if (co > 200) {
      // This shouldnt happen
      printf("this shulndt happen\n");
      exit(0);
    }
  }
  if (aa->neg == true) {
     co--;
  }
  sprintf(str, "%llu", co);
  big_set_2(str, d);
  (*d)->len = strlen(str);
  big_end_m(2, &aa, &bb);
  if (bbb) {
    free(bbb);
  }
  if (aaa) {
    free(aaa);
  }
  if (str) {
    free(str);
  }
}

void big_div_2(const bigint_t *a, const bigint_t *b, bigint_t **c) {
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
  int len_a, len_b, len_diff, mod, base, carry;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);

  big_init_m(5, &aa, &bb, &cc, &aa1, &cc1);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(&cc, MAXSTR);
  big_alloc_2(&aa1, MAXSTR);
  big_alloc_2(&cc1, MAXSTR);
  big_alloc_2(c, MAXSTR);
  base = big_check_set_base(a, c);
  carry = 0;
  mod = 0;

  // reset output parameter
  (*c)->neg = false;
  (*c)->len = 1;

  // Create copy of a & b
  big_get_2(a, aaa);
  big_get_2(b, bbb);
  big_set_2(aaa, &aa);
  big_set_2(bbb, &bb);
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
    big_set_2("1", c);
  } else if (strcmp(aaa, bbb) <= 0 && strlen(aaa) == strlen(bbb)) {
    big_set_2("0", c);
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
      len_a = (*aa).len;
      len_b = (*bb).len;
      big_div_x_2(aa, bb, &cc);
      big_mul_2(cc, bb, &cc1);
      big_sub_2(aa, cc1, &aa1);

      big_clear_zeros(&aa1);
      big_get_2(aa1, aaa);
      big_set_2(aaa, &aa);
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
  if (bbb) {
    free(bbb);
  }
  if (aaa) {
    free(aaa);
  }
  big_end_m(3, &aa, &bb, &cc);
}

void big_div(const bigint_t *a, const bigint_t *b, bigint_t **d) {
  int len, len123;
  bigint_t *c, *e, *w, *res, *v, *x, *y, *z, *f, *tmp, *tmp2, *ff;
  big_init_m(12, &v, &x, &y, &z, &f, &c, &e, &w, &res, &tmp, &tmp2, &ff);
  big_set_m(12, &v, &x, &y, &z, &f, &c, &e, &w, &res, &tmp, &tmp2, &ff);

  // Set result to correct sign
  if ((*a).neg || (*b).neg) {
    (*d)->neg = true;
  }

  // if a or b is NULL we return NULL
  // if a == b we return 1
  // if a < b we return 0
  // if b == 1 we return a
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
    // set the len to diff between a & b
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
        if (len1 >= len3 + 4) { // this is to speed up the hackery
          len3 = len1 - 4;
        }

        // fill out the divisor with zeros,
        // hack to save tons of iterations
        for (int j = 0; j <= len3; j++) {
          cc[len2+j] = '0';
        }
        //cc[len3+1] = '\0';
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
        clen = strlen(ccc); // the number of iterations after filled out with 0s
        for (int k = 0; k < clen; k++) {
          if (i == 0 && clen > 1) {
            // 1st run, populate result with big-num divs ie first nums
            // in result
            for (u64 l = 0; l < strlen(ccc); l++) {
              (*res).dig[l] = ccc[l] - '0';
            }
            (*res).len = strlen(ccc);
            len123 = strlen(ccc);
            break;
          } else if (clen > 1) {
            // If the number of divisions exceed one digit

            // FIXME: For some reason we hit this in the middle of a long number
            //        and then the start gets "reset"
            char *ccc1 = malloc(MAXSTR);

            strcpy(ccc1, big_get(res));
            // This hack adds a 0 to the 1st couple of numbers so they add
            // upp correctly
            if (clen >= 4) {
              len123 = len123 - 2;
              if (len123 < clen)
                len123 = clen;
            }
            big_set(ccc1, &tmp);
            big_set(ccc, &tmp2);
            big_add(tmp2, tmp, &res);
            free(ccc1);
            break;
          } else {
            // Modify where to position the next character depending on the
            // above hacks to save iterations
            if (i==1 && clen == 1 && (len123 == 3 || len123 > 4)) {
              len123--;
            }
            if (len123 > (*res).len && i > 4) {
              (*res).len = len+len123+1;
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
          for (u64 j = 0; j < strlen(big_get(*d)); j++) {
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
void big_mod_2(const bigint_t *a, const bigint_t *b, bigint_t **e) {
  bigint_t *c, *d, *f, *g;
  bigint_t *aa, *bb, *cc, *cc1;
  bool n = false;
  int base;
  char *aaa = (char*) malloc(MAXSTR);
  char *bbb = (char*) malloc(MAXSTR);

  big_init_m(6, &aa, &bb, &cc, &cc1, &g, e);
  big_alloc_2(&aa, MAXSTR);
  big_alloc_2(&bb, MAXSTR);
  big_alloc_2(&cc, MAXSTR);
  big_alloc_2(&cc1, MAXSTR);
  big_alloc_2(&g, MAXSTR);
  big_alloc_2(e, MAXSTR);

  (*e)->neg = false;
  (*e)->len = 1;

  // Create copy of a & b
  big_get_2(a, aaa);
  big_get_2(b, bbb);
  big_set_2(aaa, &aa);
  big_set_2(bbb, &bb);
  (*aa).len = (*a).len;
  (*bb).len = (*b).len;

  big_set_2("1", &g);
  base = big_check_set_base(a, e);

  if (a == NULL || b == NULL) {
    e = NULL;
  } else {
    if ((*a).neg) {
      aa->neg = false;
      n = true;
    }
    big_div_2(aa, bb, &cc);
    if (n) {
      big_add_2(cc, g, &cc);
    }
    if (n && (*cc).neg == false) {
      (*cc).neg = true;
    }
    big_mul_2(cc, bb, &cc1);
    (*e)->len = (*bb).len;
    big_sub_2(aa, cc1, e);
    big_clear_zeros(&(*e));
  }

  if (bbb) {
    free(bbb);
  }
  if (aaa) {
    free(aaa);
  }
  big_end_m(2, &aa, &bb);
}

//
// Bigint modulo
void big_mod(const bigint_t *a, const bigint_t *b, bigint_t **e) {
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
    (*e)->len = (*b).len;
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
  printf("%s\n", big_get(*a));
}

// Assert
void big_assert(bigint_t **b1, bigint_t **b2) {
  assert(strcmp(big_get(*b1), big_get(*b2)) == 0);
}

void big_assert_str(char* str, bigint_t **b2) {
  assert(strcmp(str, big_get(*b2)) == 0);
}
