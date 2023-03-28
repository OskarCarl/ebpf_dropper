SRC=$(wildcard *.c)
OBJ=$(SRC:.c=.o)
CFLAGS=-I/usr/lib/modules/$(shell uname -r)/build/include/

all: $(SRC) $(OBJ)

$(OBJ): %.o

%.o: %.c
	clang $(CFLAGS) -O2 -g -D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign -fno-stack-protector \
		-DGEMODEL=false -DGEMODEL_P_PERCENTS=0 -DGEMODEL_R_PERCENTS=0 -DGEMODEL_K_PERCENTS=0 -DGEMODEL_H_PERCENTS=0 \
		-DPROBA_percents=1 -DSEED=42 -DIP1_TO_DROP=0x0a000001 -DIP2_TO_DROP=0x0a000002 -DPORT_TO_WATCH=6121 \
		-Wno-compare-distinct-pointer-types -emit-llvm -c $< -o - | llc -march=bpf -filetype=obj -o $@

clean:
	rm -rf *.o

.PHONY: %.o
