#pragma once
#include <bpf/bpf_tracing.h>
#include "helpers.h"
#include "common.h"


//MASK BITI permisiuni
#define MAY_EXEC   0x00000001
#define MAY_WRITE  0x00000002
#define MAY_READ   0x00000004
#define MAY_APPEND 0x00000008

// int ret = 0 SUCCES ret = -EPRAM FAIL
// FILE SYSCALLS
SEC("lsm/file_open")
int BPF_PROG(on_file_open, struct file *file, int ret)
{
    if (ret)
        return ret;

    if (!(file->f_flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND)))
   	 return 0;

    struct event *e = event_reserve(EV_FILE_OPEN);
    if (!e)
        return 0;

    bpf_d_path(&file->f_path, e->path, sizeof(e->path));
    e->flags = file->f_flags;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("lsm/file_permission")
int BPF_PROG(on_file_permission,struct file *file,int mask,int ret){
	if(ret)
		return ret;
	if(!(mask & MAY_WRITE))
		return 0;
	struct event *e = event_reserve(EV_FILE_PERMISSION);
	
	if(!e)
		return 0;

	read_dentry_name(e->path, sizeof(e->path), BPF_CORE_READ(file, f_path.dentry));
fill_inode_meta(&e->target, BPF_CORE_READ(file, f_inode));
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/file_truncate")
int BPF_PROG(on_file_truncate,struct file *file,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_FILE_TRUNCATE);

	if(!e)
		return 0;
	read_dentry_name(e->path, sizeof(e->path), BPF_CORE_READ(file, f_path.dentry));
fill_inode_meta(&e->target, BPF_CORE_READ(file, f_inode));
	bpf_ringbuf_submit(e,0);
	return 0;
} 


// INODE SYSCALLS

SEC("lsm/inode_unlink")
int BPF_PROG(on_inode_unlink,struct inode *dir,struct dentry *dentry,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_UNLINK);

	if(!e)
		return 0;
	read_dentry_name(e->path,sizeof(e->path),dentry);
	fill_inode_meta(&e->target,BPF_CORE_READ(dentry,d_inode));
	fill_inode_meta(&e->parent,dir);
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_rename")
int BPF_PROG(on_inode_rename,
		struct inode *old_dir,
		struct dentry *old_dentry,
		struct inode *new_dir,
		struct dentry *new_dentry,
		int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_RENAME);

	if(!e)
		return 0;
	read_dentry_name(e->path,sizeof(e->path),old_dentry);
	read_dentry_name(e->path2,sizeof(e->path2),new_dentry);


	fill_inode_meta(&e->parent,old_dir);
	fill_inode_meta(&e->target,BPF_CORE_READ(old_dentry,d_inode));

	fill_inode_meta(&e->new_parent,new_dir);
	fill_inode_meta(&e->new_target,BPF_CORE_READ(new_dentry,d_inode));

	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_mkdir")
int BPF_PROG(on_inode_mkdir,struct inode *dir,struct dentry *dentry,umode_t mode,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_MKDIR);

	if(!e)
		return 0;
	//aici banuiesc ca vine ceva de verificat ce nume are directorul creat si ce informatii trebuie sa stiu despre el
	
	read_dentry_name(e->path,sizeof(e->path),dentry);
	fill_inode_meta(&e->parent,dir);
	e->req_mode = mode;
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_rmdir")
int BPF_PROG(on_inode_rmdir,struct inode *dir,struct dentry *dentry,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_RMDIR);

	if(!e)
		return 0;
	read_dentry_name(e->path,sizeof(e->path),dentry);
	fill_inode_meta(&e->parent,dir);
	fill_inode_meta(&e->target,BPF_CORE_READ(dentry,d_inode));
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_mknod")
int BPF_PROG(on_inode_mknod,struct inode *dir,struct dentry *dentry,umode_t mode,dev_t dev,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_MKNOD);

	if(!e)
	 	return 0;
	//aici vine ceva de verificat ce nod s-a facut cand si in ce locatie
	read_dentry_name(e->path,sizeof(e->path),dentry);
	fill_inode_meta(&e->parent,dir);
	e->req_mode = mode;
	e->req_dev = dev;	
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_readlink")
int BPF_PROG(on_inode_readlink,struct dentry *dentry,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_READLINK);

	if(!e)
		return 0;
	read_dentry_name(e->path,sizeof(e->path),dentry);
	fill_inode_meta(&e->target,BPF_CORE_READ(dentry,d_inode));	
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_follow_link")
int BPF_PROG(on_inode_follow_link,struct dentry *dentry,struct inode *inode,bool rcu,int ret){
	if(ret)
		return ret;
	struct event *e = event_reserve(EV_INODE_FOLLOW_LINK);
	if(!e)
		return 0;
	

	read_dentry_name(e->path,sizeof(e->path),dentry);
	fill_inode_meta(&e->parent,inode);
	fill_inode_meta(&e->target,BPF_CORE_READ(dentry,d_inode));
	e->flags = rcu;
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/inode_permission")
int BPF_PROG(on_inode_permission,struct inode *inode,int mask,int ret){
	if(ret)
		return ret;
	if(!(mask & MAY_WRITE))
		return 0;


	struct event *e=event_reserve(EV_INODE_PERMISSION);
	if(!e)
		return 0;
	//aici banuiesc vine vazut ce nume are inodul cu permisiunile de write care a incercat sa faca prostii
	fill_inode_meta(&e->target,inode);
	bpf_ringbuf_submit(e,0);
	return 0;
}
//day 2

SEC("lsm/inode_create")
int BPF_PROG(on_inode_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_INODE_CREATE);
    if (!e)
        return 0;

    read_dentry_name(e->path, sizeof(e->path), dentry);
    fill_inode_meta(&e->parent, dir);
    e->req_mode = mode;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_symlink")
int BPF_PROG(on_inode_symlink, struct inode *dir, struct dentry *dentry,
             const char *old_name, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_INODE_SYMLINK);
    if (!e)
        return 0;

    read_dentry_name(e->path, sizeof(e->path), dentry);          
    bpf_probe_read_kernel_str(e->path2, sizeof(e->path2), old_name);
    fill_inode_meta(&e->parent, dir);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(on_inode_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_INODE_LINK);
    if (!e)
        return 0;

    read_dentry_name(e->path,  sizeof(e->path),  old_dentry); 
    read_dentry_name(e->path2, sizeof(e->path2), new_dentry);  // numele nou

    fill_inode_meta(&e->target,     BPF_CORE_READ(old_dentry, d_inode));
    fill_inode_meta(&e->new_parent, dir);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_setattr")
int BPF_PROG(on_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_INODE_SET_ATTR);
    if (!e)
        return 0;

    read_dentry_name(e->path, sizeof(e->path), dentry);
    fill_inode_meta(&e->target, BPF_CORE_READ(dentry, d_inode)); // starea de acum

    e->flags    = BPF_CORE_READ(attr, ia_valid);
    e->req_mode = BPF_CORE_READ(attr, ia_mode);
    e->req_uid  = BPF_CORE_READ(attr, ia_uid.val);
    e->req_gid  = BPF_CORE_READ(attr, ia_gid.val);
    e->req_size = BPF_CORE_READ(attr, ia_size);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(on_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret)
{
    if (ret)
        return ret;
    if (!(prot & PROT_EXEC))
        return 0;

    struct event *e = event_reserve(EV_FILE_MPROTECT);
    if (!e)
        return 0;

    e->req_prot   = reqprot;
    e->prot       = prot;
    e->addr_start = BPF_CORE_READ(vma, vm_start);
    e->addr_end   = BPF_CORE_READ(vma, vm_end);

    struct file *f = BPF_CORE_READ(vma, vm_file);
    if (f) {
        read_dentry_name(e->path, sizeof(e->path), BPF_CORE_READ(f, f_path.dentry));
        fill_inode_meta(&e->target, BPF_CORE_READ(f, f_inode));
    } else {
        e->flags = 1; 
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
SEC("lsm/mmap_file")
int BPF_PROG(on_mmap_file,struct file *file,unsigned long reqprot,unsigned long prot,unsigned long flags,int ret){
	if(ret)
		return ret;
	if(!(prot & PROT_EXEC))
		return 0;

	struct event *e = event_reserve(EV_MMAP_FILE);
	if(!e)
		return 0;

	e->req_prot = reqprot;
	e->prot = prot;
	e->map_flags = flags;
	if (file){
		read_dentry_name(e->path,sizeof(e->path),BPF_CORE_READ(file,f_path.dentry));
		fill_inode_meta(&e->target,BPF_CORE_READ(file,f_inode));
	}else{
		e->is_anon = 1;
	}
	bpf_ringbuf_submit(e,0);
	return 0;
}
SEC("lsm/path_chmod")
int BPF_PROG(on_path_chmod, const struct path *path, umode_t mode, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_PATH_CHMOD);
    if (!e)
        return 0;

    e->req_mode = mode;
    read_dentry_name(e->path, sizeof(e->path), BPF_CORE_READ(path, dentry));
    fill_inode_meta(&e->target, BPF_CORE_READ(path, dentry, d_inode));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/path_chown")
int BPF_PROG(on_path_chown, const struct path *path, __u32 uid, __u32 gid, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_PATH_CHOWN);
    if (!e)
        return 0;

    e->req_uid = uid;
    e->req_gid = gid;
    read_dentry_name(e->path, sizeof(e->path), BPF_CORE_READ(path, dentry));
    fill_inode_meta(&e->target, BPF_CORE_READ(path, dentry, d_inode));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
