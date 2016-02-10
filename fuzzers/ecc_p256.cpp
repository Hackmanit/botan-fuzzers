#include "driver.h"
#include "ecc_helper.h"

void fuzz(const uint8_t in[], size_t len)
   {
   static EC_Group p256("secp256r1");
   return check_ecc_math(p256, in, len);
   }
