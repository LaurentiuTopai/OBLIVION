#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct{
	__uint(type,BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries,1<<24);
}events SEC(".maps");


//verificare cu type_array pentru a filtra procesul lui oblivion de restul:
struct{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
}self_tgid SEC(".maps");
