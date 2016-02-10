#include "driver.h"
#include "ecc_helper.h"

void fuzz(const uint8_t in[], size_t len)
   {
   static EC_Group bp256("brainpool256r1");
   return check_ecc_math(bp256, in, len);
   }
