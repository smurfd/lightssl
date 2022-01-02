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
// TODO: handle negative numbers
// TODO: multiplication
// TODO: division
// TODO: modulo
// TODO: unlimited(...) arguments per op?
// FIXME: If you DONT find bugs/leaks/securityissues let me know ;)

//
// Return a string from int array
void big_get_str(bigint_t **b1, char **str) {
  for (int i=0; i<(*b1)->length; i++) {
    (*str)[i] = (*b1)->d[i];
  }
  (*str)[(*b1)->length] = '\0';
}

//
// Print the number
void big_print(bigint_t **b1) {
  char *c = (char*) malloc((*b1)->length);
  big_get_str(b1, &c);
  printf("%s\n", c);
  free(c);
}

//
// Initialize the struct and malloc memory for it
void big_init(bigint_t **b1) {
  *b1 = (bigint_t*) malloc(BIGLEN);
  (*b1)->d = (int*) malloc(BIGLEN);
  (*b1)->length = 0;
  (*b1)->neg = false;
}

//
// Set the number to a specific string
void big_set(bigint_t **b1, char* str) {
  int len = strlen(str);
  (*b1)->length = len;
  if (len == 0) {
    len = BIGLEN;
  }
  int *d = (int*) malloc (sizeof(int)*(len+1));
  for (int i=0; i<len; i++) {
    d[i] = str[i];
  }
  memset((*b1)->d, 0, BIGLEN);
  memcpy((*b1)->d, d, sizeof(int)*(len));
  free(d);
}

//
// Set the number to a specific string and a size
void big_set_size(bigint_t **b1, char* str, uint64_t size) {
  int len = strlen(str);
  int *d;
  size = len;
  (*b1)->length = len;
  d = (int*) malloc (sizeof(int)*len+1);
  for (int i=0; i<len; i++) {
    d[i] = (int)str[i];
  }
  memset((*b1)->d, 0, BIGLEN);
  memcpy((*b1)->d, d, sizeof(len)*len);
  free(d);
}

//
// Set the number string to negative
void big_set_negative(bigint_t **b1, bigint_t **r) {
  if ((*b1)->neg == true) {
    char *tmpr;
    tmpr = (char*) malloc((*b1)->length+1);
    tmpr[0]='-';
    for (int i=0; i<(*b1)->length; i++) {
      tmpr[i+1] = (*b1)->d[i];
    }

    big_set_size(r, tmpr, sizeof(tmpr));
    (*r)->neg = true;
    if (tmpr) {
      free(tmpr);
    }
  }
}

//
// Clear the number
void big_cls(bigint_t **b1) {
  memset((*b1)->d, 0, BIGLEN);
}

//
// Free the malloced memory
void big_end(bigint_t **b1) {
  if ((*b1)->d) {
    free((*b1)->d);
  }
  if (*b1) {
    free(*b1);
  }
}

//
// Add big numbers
void big_add(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, mix, max, carry, newd, m;
  int *ps1, *ps2;

  carry = 0;
  m = 0;

  min = (*b1)->length;
  max = (*b2)->length;
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  if (((*b1)->d[0] == '9' || (*b2)->d[0] == '9') && (max == min)) {
    (*r)->d[0] = '1';
    m = 1;
  }

  if (min > max) {
    min = (*b2)->length;
    max = (*b1)->length;
    ps1 = (*b1)->d;
    ps2 = (*b2)->d;
  }
  mix = max - min;

  for (int i=0; i<mix; i++) {
    (*r)->d[i] = ps1[i];
  }

  for (int i=0; i<min; i++) {
    newd = (ps1[max-1-i]+ps2[min-1-i])-'0'+carry;
    if (carry == 1) {
      carry = 0;
    }
    if (newd > '9') {
      carry = 1;
      newd = newd - 10;
    }
    (*r)->d[max-1-i] = newd;
  }
  (*r)->length = max + m;
}

//
// Remove leading zeros
void big_crop_zeros(bigint_t **b1, bigint_t **r) {
  int len, co;
  len = (*b1)->length;
  co = 0;
  while ((*b1)->d[co] == '0') {
    co = co + 1;
  }
  for (int i=0; i<len-co; i++) {
    (*r)->d[i] = (*b1)->d[i+co];
  }
  if (co == 0) {
    (*r) = (*b1);
    (*r)->length = (*b1)->length;
  }

  (*r)->length = len-co;
}

//
// Compare numbers. Return -1 is b1 is smaller, 0 they are alike, 1 b1 is bigger
int big_cmp(bigint_t **b1, bigint_t **b2) {
  // TODO: wayyyy better finegrained comparison
  int l1, l2,l10, l20, i, j, k; // -1=smaller, 0=alike, 1=bigger
  l1 = (*b1)->length;
  l2 = (*b2)->length;
  l10 = 0;
  l20 = 0;
  i = 0;

  l1 = l1 - l10;
  l2 = l2 - l20;
  if (l1 > l2) {
    return -1;
  } else if(l1 < l2) {
    return 1;
  }

  while (i < l1) {
    j = (*b1)->d[i];
    k = (*b2)->d[i];
    if (j < k) {
      return -1;
    } else if (j > k) {
      return 1;
    }
    i = i + 1;
  }
  return 0;
}

//
// Subtract big numbers
void big_sub(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, max, newd, k, j, co;
  int *ps1, *ps2;
  bigint_t *tmp;
  bool neg = false;

  big_init(&tmp);
  // We make a "bad" assumption
  min = (*b1)->length;
  max = (*b2)->length;
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  // Usually this is true after the bad assumption
  if (min >= max) {
    min = (*b2)->length;
    max = (*b1)->length;
    ps1 = (*b1)->d;
    ps2 = (*b2)->d;
  }

  // If strings are the same length and the 1st letter is smaller in the 1st number,
  // it will be a negative number in the end. we make it easier for ourself.
  if ((ps1[0] < ps2[0] && max == min) || (*b1)->length < (*b2)->length) {
    neg = true;
    min = (*b1)->length;
    max = (*b2)->length;
    ps1 = (*b2)->d;
    ps2 = (*b1)->d;
  }

  j = min-1;
  k = max-1;
  co = k;
  while(j>=0 && k>=0 && co >= 0) {
    newd = ps1[k] - ps2[j] + '0';
    if (newd < '0') {
      if (k-1 < 0) {
        if (co == 0) {
          newd = '0'-newd+'0';
        }
        neg = true;
      } else {
        ps1[k-1] = ps1[k-1] - 1;
        ps1[k] = ps1[k] + 10;
        if (co != 0 && ps1[k-1] < '0') {
          int x = k - 1;
          while(ps1[x] < '0') {
            if (x != k-1 && ps1[x+1] < '0') {
              ps1[x+1] = ps1[x+1] + 10;
            } else {
              ps1[x] = ps1[x] + 10;
            }
            x = x - 1;
            ps1[x] = ps1[x] - 1;
          }
        }
        newd = ps1[k] - ps2[j] + '0';
      }
    }
    (*r)->d[co] = newd;
    if (newd == '0' && k == 0) {
      int l = (*r)->length;
      big_crop_zeros(r, &tmp);
      (*r) = &(*tmp);
      (*r)->length = l;
    }
    j = j - 1;
    k = k - 1;
    co = co - 1;
  }

  if (j!=0 && j!=k) {
    for (int i=k; i>=0; i--) {
      (*r)->d[co] = ps1[i];
      if (ps1[i] < '0') {
        (*r)->d[co] = (*r)->d[co] + 10;
      }
      co = co - 1;
    }
  }

  if (neg == true) {
    (*tmp) = *(*r);
    int l = (*r)->length;
    (*tmp).length = l;
    (*tmp).neg = true;
    (*r)->neg = true;
    big_set_negative(&tmp, r);
    (*r)->length = l+1;
    (*r)->neg = true;
    if (ps1[1]!=0) {
      (*r)->length = l;
      (*r)->neg = true;
    } else {
      (*r)->length = l+1;
      (*r)->neg = true;
    }
  } else {
    (*r)->length = max;
  }
}

//
// Divide big numbers
void big_div(bigint_t **b1, bigint_t **b2, uint64_t *co) {
  bigint_t *rr1, *rr2, *zero, *tmp;
  int l;
  char *c;
  // TODO: not working 100%
  // Check if (*b2)->d < 0
  // Check if (*b1)->d < 0

  // should be positive values before this

  big_init(&rr1);
  big_init(&rr2);
  big_init(&tmp);
  big_init(&zero);
  big_set(&zero, "0");
  (*rr1) = *(*b1);
  (*rr1).length = (*b1)->length;
  *co = 0;
  while ((*rr2).neg == false) {
    l = (*rr1).length;
    big_crop_zeros(&rr1, &tmp);
    l = (*tmp).length;
    (*rr1) = (*tmp);
    (*rr1).length = (*tmp).length;
   
    big_sub(&rr1, b2, &rr2);
    if ((*rr2).neg == true || (*b2)->length > (*rr2).length) {
      break;
    }
    *co = *co+1;
    c = (char*) malloc(BIGLEN);
    big_get_str(&rr2, &c);
    big_set(&rr1, c);
    (*rr1).length = (*rr2).length;
    (*rr1).neg = (*rr2).neg;
    free(c);
  }
  *co = *co -1;
}

//
// Modulo on big numbers
void big_mod(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, max;
  int *ps1, *ps2;

  min = (*b1)->length;
  max = (*b2)->length;
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  if ((*r)->d == NULL) {

  }
}

//
// Assert that res == solution
void big_assert(bigint_t **b1, bigint_t **b2) {
  char *s1 = (char*) malloc((*b1)->length);
  char *s2 = (char*) malloc((*b2)->length);
  big_get_str(b1, &s1);
  big_get_str(b2, &s2);
  assert(strcmp(s1, s2) == 0);
  free(s2);
  free(s1);
}

//
// Multiply big numbers
// From : https://gist.github.com/anonymous/aba0a2d1194d2cd0967a
void big_mul(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int carry=0;
  int tmp;
  int push_left = 0;
  (*r)->length = (*b1)->length + (*b2)->length;
  int i = (*b1)->length - 1;
  int j = (*b2)->length - 1;
  int k = (*r)->length - 1;

  while (i >= 0) {
    k = (*r)->length - 1 - push_left;
    j = (*r)->length - 1;
    push_left = push_left + 1;
    while(j >= 0 || carry > 0) {
      if(j >= 0) {
        tmp = ((*b1)->d[i]-'0') * ((*b2)->d[j]-'0');
      } else {
        tmp = 0;
      }
      tmp = tmp + carry;
      carry = tmp / 10;
      (*r)->d[k] = (*r)->d[k] + tmp % 10;
      carry = carry + (*r)->d[k] / 10;
      (*r)->d[k] = (*r)->d[k] % 10;
      j = j - 1;
      k = k - 1;
    } 
    i = i - 1;
  }

  while((*r)->d[0] == 0) {
    (*r)->length--;
    (*r)->d++;
  }
  for (int i=0; i<(*r)->length; i++) {
    (*r)->d[i]=(*r)->d[i] + '0';
  }
}
