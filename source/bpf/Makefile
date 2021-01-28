.PHONY: all clean

KSRC=/home/lambdai/workspace/ubuntu-focal
CLANG=clang
LLC=llc

all: stream.bpf.o

stream.bpf.o: stream.bpf.c
	$(CLANG) -I ${KSRC}/usr/include \
		 -I ${KSRC}/tools/lib/bpf \
		 -I ${KSRC}/tools/testing/selftests/bpf \
		 -target bpf -O2 -emit-llvm -c $< -o - | \
		 $(LLC) -march=bpf -mcpu=generic -filetype=obj -o $@

clean:
	-rm -f *.o
