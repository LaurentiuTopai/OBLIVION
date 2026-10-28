#pragma once
#include <bpf/bpf_tracing.h>
#include "helpers.h"
#include "common.h"




/*
 * se declansaza la excve inainte ca noul binar sa preia binarul
 * bprm->filename	calea ceruta
 * bprm->interp		interpretorul
 * bprm->file		fisierul binar
 * bprm->cred		credentiale noi
 *
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(on_bprm_check_security,struct linux_binprm *bprm,int ret){
	if(ret)
		return ret;

	struct event *e = event_reserve(EV_EXEC);
	if(!e)
		return 0;
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), BPF_CORE_READ(bprm, filename));
	bpf_probe_read_kernel_str(e->path2, sizeof(e->path2), BPF_CORE_READ(bprm, interp));
	fill_inode_meta(&e->target, BPF_CORE_READ(bprm, file, f_inode));
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 *exec-ul a trecut de punctul de intoarcere,util pentru a verifica executia si sa vezi commul nou 
 * 
 * 
*/
SEC("lsm/bprm_committed_creds")
int BPF_PROG(on_bprm_committed_creds,const struct linux_binprm *bprm){
	struct event *e = event_reserve(EV_BPRM_COMMITED_CREDS);
	if(!e)
		return 0;
	  bpf_probe_read_kernel_str(e->path, sizeof(e->path), BPF_CORE_READ(bprm, filename));
    	fill_inode_meta(&e->target, BPF_CORE_READ(bprm, file, f_inode));

    	e->new_uid  = BPF_CORE_READ(bprm, cred, uid.val);
    	e->new_euid = BPF_CORE_READ(bprm, cred, euid.val);
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 * fork,clone,thread/task este copilul inca in constructie
 *ppid = tgid
 * clone_flags zice ce tip de clona este = CLONE_THREAD,CLONE_NEWUSER,CLONE_NEWNS,CLONE_NEWPID,CLONE_NEWNET
 *
 * */
SEC("lsm/task_alloc")
int BPF_PROG(on_task_alloc,struct task_struct *task,unsigned long clone_flags,int ret){
	if(ret)
		return ret;
	if (clone_flags & CLONE_THREAD)
        	return 0;
	struct event *e = event_reserve(EV_TASK_ALLOC);
	if(!e)
		return 0;

	e->clone_flags = clone_flags;
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 *setuid,seteuid,setresuid,setfuid
 *new/old sunt struct cred,cu campurile uid,euid,suid,fsuid
 */
SEC("lsm/task_fix_setuid")
int BPF_PROG(on_task_fix_setuid,struct cred *new_cred,const struct cred *old_cred,int flags,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_TASK_FIX_SETUID);
	if(!e)
		return 0;

	e->old_uid  = BPF_CORE_READ(old_cred, uid.val);
	e->new_uid  = BPF_CORE_READ(new_cred, uid.val);
	e->old_euid = BPF_CORE_READ(old_cred, euid.val);
	e->new_euid = BPF_CORE_READ(new_cred, euid.val);
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 * similar cu setuid dar pentru grupuri
 *
 */
SEC("lsm/task_fix_setgid")
int BPF_PROG(on_task_fix_setgid,struct cred *new_cred,const struct cred *old_cred,int flags,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_TASK_FIX_SETGID);
	if(!e)
		return 0;
	e->old_gid  = BPF_CORE_READ(old_cred, gid.val);
	e->new_gid  = BPF_CORE_READ(new_cred, gid.val);
	e->old_egid = BPF_CORE_READ(old_cred, egid.val);
	e->new_egid = BPF_CORE_READ(new_cred, egid.val);
	e->flags    = flags;
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 *cineva vrea acces ptrace la child
 *child->tgid e PID-ul victimei
 *mode e o masca PTRACE_MODE_READ(1),PTRACE_MODE_ATTACH(2),NOFOLLOW (8), FSCREDS (0x10), REALCREDS (0x20)
 *se declanseaza si la citiri /proc/<pid>/mem , /proc/<pid>/environ
 *se filtreaza dupa mode & PTRACE_MODE_ATTACH
 */
SEC("lsm/ptrace_access_check")
int BPF_PROG(on_ptrace_access_check,struct task_struct *child,unsigned int mode,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_PTRACE_ACCESS_CHECK);
	if(!e)
		return 0;
	e->ptrace_mode = mode;
	e->target_pid = BPF_CORE_READ(child,tgid);
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 *p e tinta p->tgif,sig nr semnalului,SIGKILL(9),SIGSTOP(19) pe procese critice precum EDR-ul
 *
 */
SEC("lsm/task_kill")
int BPF_PROG(on_task_kill,struct task_struct *p,struct kernel_siginfo *info,int sig,const struct cred *cred,int ret){
	if(ret)
		return ret;
	if(sig == 0)
		return 0;
	
	struct event *e = event_reserve(EV_TASK_KILL);
	if(!e)
		return 0;

	e->sig = sig;
	e->target_pid = BPF_CORE_READ(p,tgid);
	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 *se creaza un userspace nou,toate exploturile moderne incep cu un user namespace 
 *
 *
 */
SEC("lsm/userns_create")
int BPF_PROG(on_userns_create,const struct cred *cred,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_USERNS_CREATE);
	if(!e)
		return 0;
	
	 e->new_uid  = BPF_CORE_READ(cred, uid.val);
	 e->new_euid = BPF_CORE_READ(cred, euid.val);

	bpf_ringbuf_submit(e,0);
	return 0;
}
/*
 *un proces isi schimba capabilitatile 
 *effective,inheritable,permitted sunt pointeri la kernle_cap_t
 *
 *
 *
 */
SEC("lsm/capset")
int BPF_PROG(on_capset,struct cred *new,const struct cred *old,const kernel_cap_t *effective, const kernel_cap_t *inheritable,
	 const kernel_cap_t *permitted,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_CAPSET);
	if(!e)
		return 0;
	
	 e->cap_permitted     = BPF_CORE_READ(permitted, val);
    	 e->cap_old_permitted = BPF_CORE_READ(old, cap_permitted.val);
	bpf_ringbuf_submit(e,0);
	return 0;
}
