#include "driver.h"

#include <botan/eme_pkcs.h>
#include <botan/hex.h>

secure_vector<byte> simple_pkcs1_unpad(const byte in[], size_t len)
   {
   if(len < 10)
      throw Botan::Decoding_Error("bad len");

   if(in[0] != 2)
      throw Botan::Decoding_Error("bad field");

   for(size_t i = 1; i < len; ++i)
      {
      if(in[i] == 0)
         {
         if(i < 9)
            throw Botan::Decoding_Error("insufficient padding bytes");
         return secure_vector<byte>(in + i + 1, in + len);
         }
      }

   throw Botan::Decoding_Error("delim not found");
   }

void fuzz(const uint8_t in[], size_t len)
   {
   static EME_PKCS1v15 pkcs1;

   secure_vector<byte> lib_result, ref_result;
   bool lib_rejected = false, ref_rejected = false;

   try
      {
      lib_result = pkcs1.decode(in, len, len*8);
      }
   catch(Botan::Decoding_Error&) { lib_rejected = true; }

   try
      {
      ref_result = simple_pkcs1_unpad(in, len);
      }
   catch(Botan::Decoding_Error&) { ref_rejected = true; }

   FUZZER_ASSERT_EQUAL(lib_rejected, ref_rejected);

   if(lib_result != ref_result)
      {
      std::cerr << hex_encode(lib_result) << " != ref \n"
                << hex_encode(ref_result) << std::endl;
      abort();
      }

   }
