#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "maps.h"


char LICENSE[] SEC("license") = "GPL";
const struct event *unused_event __attribute__((unused));
const enum event_type unused_event_type __attribute__((unused));
#include "lsm_file.h"
#include "lsm_process.h"
#include "lsm_network.h"
//#include "lsm_net.h"
