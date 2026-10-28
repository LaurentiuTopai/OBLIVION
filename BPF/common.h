#pragma once
#include "vmlinux.h"

//MASK BITI permisiuni
#define MAY_EXEC   0x00000001
#define MAY_WRITE  0x00000002
#define MAY_READ   0x00000004
#define MAY_APPEND 0x00000008

#define O_ACCMODE  0003
#define O_WRONLY   0001
#define O_RDWR     0002
#define O_CREAT    0100
#define O_TRUNC    01000
#define O_APPEND   02000

#define PROT_READ 	0x1
#define PROT_WRITE 	0x2
#define PROT_EXEC 	0x4


//pentru process
#define CLONE_THREAD   0x00010000
#define CLONE_NEWNS    0x00020000
#define CLONE_NEWUSER  0x10000000
#define CLONE_NEWPID   0x20000000
#define CLONE_NEWNET   0x40000000


//pentru retea 
#define AF_UNIX    1
#define AF_INET    2
#define AF_INET6   10
#define AF_NETLINK 16
#define AF_PACKET  17
#define SOCK_RAW   3
#define SOL_SOCKET 1
#define SO_ATTACH_FILTER 26
#define SO_ATTACH_BPF    50


enum event_type{
	EV_EXEC=1,
	EV_FILE_OPEN,
	EV_FILE_PERMISSION,
	EV_FILE_TRUNCATE,

	EV_INODE_UNLINK,
	EV_INODE_RENAME,
	EV_INODE_MKDIR,
	EV_INODE_RMDIR,
	EV_INODE_MKNOD,
	EV_INODE_READLINK,
	EV_INODE_FOLLOW_LINK,
	EV_INODE_PERMISSION,
	
	EV_INODE_CREATE,
	EV_INODE_SYMLINK,
	EV_INODE_LINK,
	EV_INODE_SET_ATTR,
	EV_FILE_MPROTECT,
	EV_MMAP_FILE,
	EV_PATH_CHMOD,
	EV_PATH_CHOWN,
	
	//Apeluri procese
	EV_BPRM_COMMITED_CREDS,
	EV_TASK_ALLOC,
	EV_TASK_FIX_SETUID,
	EV_TASK_FIX_SETGID,
	EV_PTRACE_ACCESS_CHECK,
	EV_TASK_KILL,
	EV_USERNS_CREATE,
	EV_CAPSET,

	//Apeluri retea
	EV_SOCKET_CREATE,
	EV_SOCKET_CONNECT,
	EV_SOCKET_BIND,
	EV_SOCKET_LISTEN,
	EV_SOCKET_ACCEPT,
	EV_SOCKET_SENDMSG,
	EV_SOCKET_SETSOCKOPT,



	EV_URING_ALLOWED,
};
//
// ino  - numar inode in interiorul unui file system
// dev - device filesystem,perechea (dev,ino) identifica un fisier unic 
// mode - i_mode tipul fisierului: S_IFREG S_IFDIR S_IFLNK
// uid - UID-ul proprietarului fisierului
// gid - GID-ul id-ul groupul cu acces la fisier
// size - dimensiunea in bytes
// nlink - numarul de hard linkuri la nivel de fisier


struct file_meta{
	__u64 ino;
	__u64 size;
	__u32 uid; 
	__u32 gid;
	__u32 nlink; 
	__u32 dev;
	__u32 mode;
};

// req_mode - mod cerut (tip + permisiuni) la mkdir/mknode
// req_dev - dev_t cerut la mkdnod (major/minor al device-ului creat)
struct event{
	__u64 ts;
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	__u32 type;
	__s32 verdict; // 0 = allowed -EPERM = deny
	char comm[16];
	__u32 req_mode;
	__u32 req_dev;
	__u32 req_uid;
	__u32 req_gid;
	__u32 req_prot;
	__u32 prot;
	__u64 req_size;
	__u64 addr_start;
	__u64 addr_end;


	__u32 flags; // la follow-link rcu (1 = RCU WALK)
	__u32 map_flags;
	__u32 is_anon;
	//Partea de i_nodes 
	//------------------
	char path[256]; //target
	char path2[256]; // nume rau la rename -> asta pentru apelurile de sistem file de rename cum e i_node_unlink


	struct file_meta target;
	struct file_meta parent;

	struct file_meta new_target;
	struct file_meta new_parent;

	//-------------------
	//
	//Variabile syscalluri procese
	__u64 start_time;   // start_boottime al procesului curent
	__u32 ppid;

	__u64 clone_flags;  // task_alloc
	__u64 cap_old_permitted;// capset
	__u64 cap_permitted;
	__u32 target_pid;   // ptrace_access_check, task_kill (tgid-ul tineti)
	__u32 sig;          // task_kill
	__u32 ptrace_mode;  // ptrace_access_check
	__u32 old_uid, new_uid;    // task_fix_setuid
	__u32 old_euid, new_euid;
	__u32 old_gid, new_gid;    // task_fix_setgid
	__u32 old_egid,new_egid; 

	//Variabile syscalluri retea
	__u8  daddr[16];     // IPv4 în primii 4 bytes, IPv6 pe toti 16
	__u16 dport;         // host byte order (după ntohs)
	__u16 sport;
	__u32 family;        // AF_INET=2, AF_INET6=10, AF_UNIX=1, AF_PACKET=17, AF_NETLINK=16
	__u32 sock_type;     // SOCK_STREAM=1, SOCK_DGRAM=2, SOCK_RAW=3
	__u32 protocol;
	__u32 backlog;
	__u32 optname;
};
