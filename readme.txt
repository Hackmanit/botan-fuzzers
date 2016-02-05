
This repo is for testing various message decoders and math functions
of the botan crypto library (https://github.com/randombit/botan) using
AFL and libFuzzer.

Run setup.sh to pull botan master and setup the builds.

Input corpuses are in corpus/

fuzzers.cpp is the main show

To add a new fuzzer, add a suitable function to fuzzers.cpp with this signature:

int fuzz_the_thing(const uint8_t buf[], size_t len);

then add `the_thing` to the FUZZERS variable in the Makefile

Run with

make run_{llvm,afl}_the_thing

like in

make run_llvm_redc_p384

or

make run_afl_tls_client

You can pass args to LLVM using args=

make args=-max_len=4000 run_llvm_tls_client

The fuzzer entry point assumes no more than 4K of input. The base
libFuzzer default max len is 64 bytes, the makefile sets it to 128 as
default.

Use

make cmin_redc_p384

to run afl-cmin to minimize and merge the LLVM and AFL outputs back to
the corpus

TODO:

 - Support for KLEE (https://klee.github.io)
