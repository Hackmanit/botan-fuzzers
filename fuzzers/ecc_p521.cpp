#include "driver.h"
#include "ecc_helper.h"

void fuzz(const uint8_t in[], size_t len)
   {
   static EC_Group p521("secp521r1");
   return check_ecc_math(p521, in, len);
   }
