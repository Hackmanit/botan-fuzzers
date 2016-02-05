
FUZZERS=tls_client tls_server x509_cert x509_crl pkcs8_load \
        bn_square ressol \
        os2ecp_p256 os2ecp_p384 os2ecp_p521 os2ecp_bp512 \
        redc_p224 redc_p256 redc_p384 redc_p521 \
        ecc_mul_p256 ecc_mul_p384 ecc_mul_p521

BOTAN_DIR=botan

CLANG_COV_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters
LLVM_FLAGS=-O3 -std=c++11 -pthread -I$(BOTAN_DIR)/llvm/build/include $(BOTAN_DIR)/llvm/libbotan-1.11.a $(CLANG_COV_FLAGS)
AFL_FLAGS=-O3 -std=c++11 -pthread -I$(BOTAN_DIR)/afl/build/include $(BOTAN_DIR)/afl/libbotan-1.11.a

SOURCES=fuzzers.cpp

AFL_CXX=afl-clang-fast++
CLANG_CXX=clang++

LLVM_PROGS=$(patsubst %,bin/llvm_fuzz_%,$(FUZZERS))
AFL_PROGS=$(patsubst %,bin/afl_fuzz_%,$(FUZZERS))

all: afl_progs llvm_progs

afl_progs: $(AFL_PROGS)

llvm_progs: $(LLVM_PROGS)

bin/llvm_fuzz_%: $(SOURCES) libFuzzer.a
	$(CLANG_CXX) $(SOURCES) -DUSE_LLVM_FUZZER $(LLVM_FLAGS) libFuzzer.a -DFUZZER_POINT=$(subst bin/llvm_,,$@) -o $@

bin/afl_fuzz_%: $(SOURCES)
	$(AFL_CXX) $(SOURCES) $(AFL_FLAGS) -DFUZZER_POINT=$(subst bin/afl_,,$@) -o $@

# libFuzzer default is max_len 64 this sets 128 but allows override via args=

run_llvm_%: bin/llvm_fuzz_%
	$(eval FUZZER = $(subst bin/llvm_fuzz_,,$<))
	mkdir -p output/$(FUZZER)/llvm/queue
	mkdir -p output/$(FUZZER)/llvm/outputs
	$< -max_len=128 -artifact_prefix=output/$(FUZZER)/llvm/outputs/ output/$(FUZZER)/llvm/queue corpus/$(FUZZER) $(args)

run_afl_%: bin/afl_fuzz_%
	$(eval FUZZER = $(subst bin/afl_fuzz_,,$<))
	mkdir -p output/$(FUZZER)/afl
	afl-fuzz $(args) -o output/$(FUZZER)/afl -i corpus/$(FUZZER) $<

cmin_%: bin/afl_fuzz_%
	$(eval FUZZER = $(subst bin/afl_fuzz_,,$<))
	rm -rf cmin-dir
	mv corpus/$(FUZZER) cmin-dir
	-cp -n output/$(FUZZER)/afl/queue/* cmin-dir
	-cp -n output/$(FUZZER)/llvm/queue/* cmin-dir
	afl-cmin -i cmin-dir -o corpus/$(FUZZER) $<
	rm -rf cmin-dir

clean:
	rm -f $(LLVM_PROGS) $(AFL_PROGS)

libFuzzer.a: libFuzzer
	cd libFuzzer && clang -c -g -O2 -std=c++11 *.cpp
	ar cr libFuzzer.a libFuzzer/*.o

setup:
	svn co https://github.com/llvm-mirror/llvm/trunk/lib/Fuzzer libFuzzer

update:
	cd botan && git pull
	svn co https://github.com/llvm-mirror/llvm/trunk/lib/Fuzzer libFuzzer
