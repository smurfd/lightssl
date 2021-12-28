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
// Print the number
void big_print(bigint_t **b) {
  printf("%s\n", (*b)->d);
}

//
// Initialize the struct and malloc memory for it
void big_init(bigint_t **b) {
  *b = (bigint_t*)malloc(BIGLEN);
  (*b)->d = (char*) malloc(BIGLEN);
  (*b)->length = 0;
  (*b)->neg = false;
}

//
// Set the number to a specific string
void big_set(bigint_t **b, char* str) {
  memset((*b)->d, 0, strlen((*b)->d));
  memcpy((*b)->d, str, strlen(str));
}

//
// Set the number to a specific string and a size
void big_set_size(bigint_t **b, char* str, uint64_t size) {
  memset((*b)->d, 0, size);
  memcpy((*b)->d, str, strlen(str));
}

//
// Set the number string to negative
void big_set_negative(bigint_t **b1, bigint_t **r) {
  if ((*b1)->neg == true) {
    char *tmpr;
    tmpr = (char*) malloc(strlen((*b1)->d)+1);
    tmpr[0]='-';
    for (int i=0; i<(int)strlen((*b1)->d); i++) {
      tmpr[i+1] = (*b1)->d[i];
    }
    tmpr[strlen((*b1)->d)+2]='\0';
    big_set_size(r, tmpr, sizeof(tmpr));
    (*r)->neg = true;
    if (tmpr) {
      free(tmpr);
    }
  }
}

//
// Clear the number
void big_cls(bigint_t **b) {
  memset((*b)->d, 0, strlen((*b)->d));
}

//
// Free the malloced memory
void big_end(bigint_t **b) {
  if ((*b)->d) {
    free((*b)->d);
  }
  if (*b) {
    free(*b);
  }
}

//
// Add big numbers
void big_add(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, mix, max, carry, newd, m;
  char *ps1, *ps2;

  carry = 0;
  m = 0;

  min = strlen((*b1)->d);
  max = strlen((*b2)->d);
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  if (((*b1)->d[0] == '9' || (*b2)->d[0] == '9') && (max == min)) {
    (*r)->d[0] = '1';
    m = 1;
  }

  if (min > max) {
    min = strlen((*b2)->d);
    max = strlen((*b1)->d);
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

  (*r)->d[max+m] = '\0';
}

//
// Remove leading zeros
void big_crop_zeros(bigint_t **b1, bigint_t **r) {
  int len, co;
  len = strlen((*b1)->d);
  co = 0;
  while ((*b1)->d[co] == '0') {
    co = co + 1;
  }
  for (int i=0; i<len-co; i++) {
    (*r)->d[i] = (*b1)->d[i+co];
  }
  if (co == 0) {
    (*r) = (*b1);
  } else {
    (*r)->d[len-co] = '\0';
  }
}

//
// Compare numbers. Return -1 is b1 is smaller, 0 they are alike, 1 b1 is bigger
int big_cmp(bigint_t **b1, bigint_t **b2) {
  // TODO: wayyyy better finegrained comparison
  int l1, l2,l10, l20, i, j, k; // -1=smaller, 0=alike, 1=bigger
  l1 = strlen((*b1)->d);
  l2 = strlen((*b2)->d);
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
  char *ps1, *ps2;
  bigint_t *tmp;
  bool neg = false;

  big_init(&tmp);
  // We make a "bad" assumption
  min = strlen((*b1)->d);
  max = strlen((*b2)->d);
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  // Usually this is true after the bad assumption
  if (min >= max) {
    min = strlen((*b2)->d);
    max = strlen((*b1)->d);
    ps1 = (*b1)->d;
    ps2 = (*b2)->d;
  }

  // If strings are the same length and the 1st letter is smaller in the 1st number,
  // it will be a negative number in the end. we make it easier for ourself.
  if ((ps1[0] < ps2[0] && max == min) || strlen((*b1)->d)<strlen((*b2)->d)) {
    neg = true;
    min = strlen((*b1)->d);
    max = strlen((*b2)->d);
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
      big_crop_zeros(r, &tmp);
      (*r) = &(*tmp);
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
    (*tmp).neg = true;
    (*r)->neg = true;
    big_set_negative(&tmp, r);
    if (strlen(ps1)==2) {
      (*r)->d[strlen(ps1)] = '\0';
    } else {
      (*r)->d[strlen(ps1)+1] = '\0';
    }
  } else {
    (*r)->d[max] = '\0';
  }
}

//
// Multiply big numbers
void big_mul(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int carry, m, d1, d2, count, c1, c2, c3, cc, cmax, dig, newdig, newdig2;
  bigint_t *rr;

  big_init(&rr);
  big_cls(&rr);
  carry = 0;
  m = 0;
  d1 = strlen((*b1)->d);
  d2 = strlen((*b2)->d);
  count = d1 + d2 - 1;
  if (((*b1)->neg == true && (*b2)->neg == true) || ((*b1)->neg == false && (*b2)->neg == false)) {
    (*r)->neg = false;
  } else {
    (*r)->neg = true;
    (*r)->d[0] = '-';
    m = 1;
  }

  c1 = d1-1;
  c2 = d2-1;
  cmax = (d1-1)+(d2-1);
  c3 = cmax;
  cc = 0;
  dig = 0;
  newdig = 0;
  newdig2 = 0;
  carry = 0;

  for (;;) {
    // Control loop
    if (c2 < 0) {
      cc = cc + 1;
      c3 = cmax - cc;
      c2 = d2 - 1;
      c1 = c1 - 1;
      if (c1 < 0) {
        break;
      }
    }

    newdig = ((*b2)->d[c2]-'0')*((*b1)->d[c1]-'0') + '0';
    // Check if character * character exceeds 1 character as result
    if (newdig >= '0' && newdig <= '9') {
      dig = newdig;
    } else if (newdig > '9') {
      dig = newdig-('0'*(int)(newdig / '0'));
      if (dig > 9) {
        (*rr).d[c3-1] = (*rr).d[c3-1] + (dig / 10);
        carry = (int)(dig / 10);
        dig = dig - (carry*10);
        carry = 0;
      }
      dig = dig + '0';
      if (c2 == 0) {
        dig = dig + carry;
        carry = 0;
      }
    }

    newdig2 = (*rr).d[c3] + dig;
    carry = 0;
    // Check if character + possible other character + carry exceeds 1 character
    if (newdig2 >= '0' && newdig2 <= '9') {
      dig = newdig2;
    } else if (newdig2 > '9') {
      dig = newdig2-('0'*(newdig2/'0'));
      if (dig > 9) {
        if (c1 == 0 && c2 == 0) {
          char *tmpr;
          tmpr = (char*) malloc(sizeof((*rr).d+32));
          tmpr[0]='1';
          if ((*rr).d[0]>='0' && (*rr).d[0] <='9') {
            tmpr[1]=(*rr).d[0];
          } else {
            tmpr[1]='0';
          }
          for (int i=0; i<(int)strlen((*rr).d); i++) {
            tmpr[i+1] = (*rr).d[i];
          }
          tmpr[strlen((*rr).d)+2]='\0';
          big_set_size(&rr, tmpr, sizeof(tmpr));
          free(tmpr);
          c3 = c3 + 1;
        } else {
          (*rr).d[c3-1] = (*rr).d[c3-1] + (dig / 10);
        }
        carry = (int)(dig / 10);
        dig = dig - (carry*10);
        carry = 0;
      }
      dig = dig + '0';
      if (c2 == 0) {
        dig = dig + carry;
        carry = 0;
      }
    }
    (*rr).d[c3] = dig;
    c2 = c2 - 1;
    c3 = c3 - 1;
  }

  (*r) = *(&rr);
}

//
// Divide big numbers
void big_div(bigint_t **b1, bigint_t **b2, uint64_t *co) {
  bigint_t *rr1, *rr2, *zero, *tmp;
  if (strcmp((*b2)->d, "0") == 0) {
    printf("division by zero, no good!\n");
  }
  // Check if (*b2)->d < 0
  // Check if (*b1)->d < 0

  // should be positive values before this

  big_init(&rr1);
  big_init(&rr2);
  big_init(&tmp);
  big_init(&zero);
  big_set(&zero, "0");
  (*rr1) = *(*b1);
  *co = 0;

  while ((*rr2).neg == false) {
    big_crop_zeros(&rr1, &tmp);
    (*rr1) = (*tmp);
    big_sub(&rr1, b2, &rr2);
    if ((*rr2).neg == true || strlen((*b2)->d) > strlen((*rr2).d)) {
      break;
    }
    *co = *co+1;
    big_set(&rr1, (*rr2).d);
  }
  *co = *co + 1;
}

//
// Modulo on big numbers
void big_mod(bigint_t **b1, bigint_t **b2, bigint_t **r) {
  int min, max;
  char *ps1, *ps2;

  min = strlen((*b1)->d);
  max = strlen((*b2)->d);
  ps1 = (*b2)->d;
  ps2 = (*b1)->d;

  if ((*r)->d == NULL) {

  }
}
