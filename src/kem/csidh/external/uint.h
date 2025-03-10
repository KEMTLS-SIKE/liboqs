#include <stdbool.h>
#include <stdint.h>

#ifdef CSIDH_1024
    #include "p1024/params.h"
#else
    #include "p512/params.h"
#endif

extern const uint uint_0;
extern const uint uint_1;

bool uint_eq(uint const *x, uint const *y);

void uint_set(uint *x, uint64_t y);

size_t uint_len(uint const *x);
bool uint_bit(uint const *x, uint64_t k);

bool uint_add3(uint *x, uint const *y, uint const *z); /* returns carry */
bool uint_sub3(uint *x, uint const *y, uint const *z); /* returns borrow */

void uint_mul3_64(uint *x, uint const *y, uint64_t z);

void uint_random(uint *x, uint const *m);   /* uniform in the interval [0;m) */
