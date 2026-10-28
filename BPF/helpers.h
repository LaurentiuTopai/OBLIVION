#pragma once
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"
#include "maps.h"

static __always_inline int is_self(void){
	__u32 k = 0;
	__u32 *v = bpf_map_lookup_elem(&self_tgid,&k);
	return v && *v==(bpf_get_current_pid_tgid() >> 32);
}



static __always_inline struct event *event_reserve(__u32 type)
{
	if(is_self())
		return NULL;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
   
    if (!e)
        return NULL;
    
    __builtin_memset(e, 0, sizeof(*e));
    __u64 pt = bpf_get_current_pid_tgid();
     struct task_struct *t = bpf_get_current_task_btf();
    e->ts      = bpf_ktime_get_ns();
    e->pid     = (__u32)pt;
    e->tgid    = pt >> 32;
    e->uid     = (__u32)bpf_get_current_uid_gid();
    e->type    = type;
    e->verdict = 0;
    e->path[0] = 0;

    e->ppid = BPF_CORE_READ(t,real_parent,tgid);
    e->start_time = BPF_CORE_READ(t,start_boottime);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline int is_inet(struct sockaddr *addr)
{
    __u16 fam = 0;
    bpf_probe_read_kernel(&fam, sizeof(fam), &addr->sa_family);
    return fam == AF_INET || fam == AF_INET6;
}

static __always_inline void fill_sockaddr(struct event *e, struct sockaddr *addr)
{
    __u16 fam = 0;
    bpf_probe_read_kernel(&fam, sizeof(fam), &addr->sa_family);
    e->family = fam;

    if (fam == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_kernel(&sin, sizeof(sin), addr);
        e->dport = bpf_ntohs(sin.sin_port);
        __builtin_memcpy(e->daddr, &sin.sin_addr, 4);
    } else if (fam == AF_INET6) {
        struct sockaddr_in6 sin6 = {};
        bpf_probe_read_kernel(&sin6, sizeof(sin6), addr);
        e->dport = bpf_ntohs(sin6.sin6_port);
        __builtin_memcpy(e->daddr, &sin6.sin6_addr, 16);
    }
}
//
// ino  - numar inode in interiorul unui file system
// dev - device filesystem,perechea (dev,ino) identifica un fisier unic 
// mode - i_mode tipul fisierului: S_IFREG S_IFDIR S_IFLNK
// uid - UID-ul proprietarului fisierului
// gid - GID-ul id-ul groupul cu acces la fisier
// size - dimensiunea in bytes
// nlink - numarul de hard linkuri la nivel de fisier
//
//

static __always_inline void read_dentry_name(char* dst,__u32 sz,struct dentry *d){
	const unsigned char *n = BPF_CORE_READ(d,d_name.name);
	bpf_probe_read_kernel_str(dst,sz,n);
}


static __always_inline void fill_inode_meta(struct file_meta *m,struct inode *i){
	if(!i)
		return;
    m->ino  = BPF_CORE_READ(i, i_ino);
    m->dev  = BPF_CORE_READ(i, i_sb, s_dev);
    m->mode = BPF_CORE_READ(i, i_mode);
    m->uid  = BPF_CORE_READ(i, i_uid.val);
    m->gid  = BPF_CORE_READ(i, i_gid.val);
    m->size = BPF_CORE_READ(i, i_size);
    m->nlink = BPF_CORE_READ(i, i_nlink);
}
