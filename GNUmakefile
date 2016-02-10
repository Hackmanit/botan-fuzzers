
FUZZERS=$(patsubst fuzzers/%.cpp,%,$(wildcard fuzzers/*.cpp))

BOTAN_DIR=botan

CLANG_COV_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=undefined -fsanitize-coverage=edge,indirect-calls,8bit-counters

SHARED_FLAGS=-O3 -g -std=c++11 -pthread
LLVM_FLAGS=-DUSE_LLVM_FUZZER -I$(BOTAN_DIR)/llvm/build/include $(SHARED_FLAGS) $(CLANG_COV_FLAGS)
AFL_FLAGS=-I$(BOTAN_DIR)/afl/build/include $(SHARED_FLAGS)

LLVM_LIBS=$(BOTAN_DIR)/llvm/libbotan-1.11.a libFuzzer.a
AFL_LIBS=$(BOTAN_DIR)/afl/libbotan-1.11.a

AFL_CXX=afl-clang-fast++
CLANG_CXX=clang++

LLVM_PROGS=$(patsubst %,bin/llvm_fuzz_%,$(FUZZERS))
AFL_PROGS=$(patsubst %,bin/afl_fuzz_%,$(FUZZERS))

all: afl_progs llvm_progs

afl_progs: $(AFL_PROGS)

llvm_progs: $(LLVM_PROGS)

#bin/llvm_fuzz_%: fuzzers.cpp $(LLVM_LIBS)
#	$(CLANG_CXX) $(LLVM_FLAGS) -DFUZZER_POINT=$(subst bin/llvm_,,$@) $< $(LLVM_LIBS) -o $@

#bin/afl_fuzz_%: fuzzers.cpp $(AFL_LIBS)
#	$(AFL_CXX) $(AFL_FLAGS) -DFUZZER_POINT=$(subst bin/afl_,,$@) $< $(AFL_LIBS) -o $@

bin/llvm_fuzz_%: fuzzers/%.cpp $(LLVM_LIBS)
	$(CLANG_CXX) $(LLVM_FLAGS) -DUSE_LLVM_FUZZER $< $(LLVM_LIBS) -o $@

bin/afl_fuzz_%: fuzzers/%.cpp $(AFL_LIBS)
	$(AFL_CXX) $(AFL_FLAGS) $< $(AFL_LIBS) -o $@

# libFuzzer default is max_len 64 this sets 128 but allows override via args=

run_llvm_%: bin/llvm_fuzz_%
	$(eval FUZZER = $(subst bin/llvm_fuzz_,,$<))
	mkdir -p output/$(FUZZER)/llvm/queue
	mkdir -p output/$(FUZZER)/llvm/outputs
	$< -max_len=140 -artifact_prefix=output/$(FUZZER)/llvm/outputs/ output/$(FUZZER)/llvm/queue corpus/$(FUZZER) $(args)

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
