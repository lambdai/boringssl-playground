.PHONY: all clean

KSRC=/home/lambdai/workspace/linux5.8
CLANG=clang
LLC=llc

all: stream.bpf.o

stream.bpf.o: stream.bpf.c
	$(CLANG) -g -I ${KSRC}/usr/include \
		 -I ${KSRC}/tools/lib/bpf \
		 -I ${KSRC}/tools/testing/selftests/bpf \
		 -target bpf -O2 -emit-llvm -c $< -o - | \
		 $(LLC) -march=bpf -mcpu=generic -filetype=obj -o $@
## Error with llc
## [29] FUNC _prog_parser type_id=28 vlen != 0
## Error w/o strip: 
## [29] FUNC _prog_parser type_id=28 vlen != 0
## Error with strip  -g --no-strip-all -R .BTF
## libbpf: Corrupted ELF file: index of strtab invalid
## Error with llvm-strip -g # strip useless DWARF info
####
# clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I 
#   ${KSRC}/tools/testing/selftests/bpf -idirafter /usr/local/include -idirafter /usr/lib/llvm-my11/lib/clang/11.0.0/include -idirafter /usr/include/x86_64-linux-gnu -idirafter /usr/include 
#   -c source/bpf/stream.bpf.c -o data/stream.bpf.o		 
# llvm-strip data/stream.bpf.o -g --no-strip-all -R .BTF
### 
clean:
	-rm -f *.o
