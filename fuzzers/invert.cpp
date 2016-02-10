#include "driver.h"
#include <botan/numthry.h>

void fuzz(const uint8_t in[], size_t len)
   {
   const BigInt x = BigInt::decode(in, len / 2);
   const BigInt mod = BigInt::decode(in + len / 2, len / 2);

   if(mod == 0)
      return;

   BigInt y = inverse_mod(x, mod);

   if(y != 0)
      {
      BigInt e = (x * y) % mod;

      FUZZER_ASSERT_EQUAL(e, 1);
      }
   }

