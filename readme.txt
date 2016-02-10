
This repo is for testing various message decoders and math functions
of the botan crypto library (https://github.com/randombit/botan) using
AFL and libFuzzer.

Run setup.sh to pull botan master and setup the builds.

Input corpuses are in corpus/

To add a new fuzzer, create a new file in fuzzers/, include "driver.h",
and implement the function with the signature

void fuzz(const uint8_t buf[], size_t len);

Run with

make run_{llvm,afl}_{what}

like in

make run_llvm_crl
make run_afl_tls_client

You can pass args to the fuzzer process using args=

make args=-max_len=4000 run_llvm_tls_client

The fuzzer entry point assumes no more than 4K of input. The base
libFuzzer default max len is 64 bytes, the makefile sets it to 140 as
default.

Use

make cmin_redc_p384

to run afl-cmin to minimize and merge the LLVM and AFL outputs back to
the corpus directory.

TODO:

- KLEE (https://klee.github.io)
- DFSan (http://clang.llvm.org/docs/DataFlowSanitizer.html)
- More jigs
