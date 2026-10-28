package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86 -Wno-missing-declarations" oblivion ../../../BPF/oblivion.bpf.c -- -I../../../BPF
