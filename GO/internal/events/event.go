package events

import (
	"fmt"
	"net"
)

type Type uint32

const (
	EvExec Type = iota + 1
	EvFileOpen
	EvFilePermission
	EvFileTruncate

	EvInodeUnlink
	EvInodeRename
	EvInodeMkdir
	EvInodeRmdir
	EvInodeMknod
	EvInodeReadlink
	EvInodeFollowLink
	EvInodePermission

	EvInodeCreate
	EvInodeSymlink
	EvInodeLink
	EvInodeSetAttr
	EvFileMprotect
	EvMmapFile
	EvPathChmod
	EvPathChown

	//apeluri de process
	EvBprmCommitedCreds
	EvTaskAlloc
	EvTaskFixSetuid
	EvTaskFixSetgid
	EvPtraceAccessCheck
	EvTaskKill
	EvUsernsCreate
	EvCapset

	//apeluri de retea
	EvSocketCreate
	EvSocketConnect
	EvSocketBind
	EvSocketListen
	EvSocketAccept
	EvSocketSetsockopt

	EvUringAllowed
)

var evNames = map[Type]string{
	EvExec:              "exec",
	EvFileOpen:          "file_open",
	EvFilePermission:    "file_permission",
	EvFileTruncate:      "file_truncate",
	EvInodeUnlink:       "inode_unlink",
	EvInodeRename:       "inode_rename",
	EvInodeMkdir:        "inode_mkdir",
	EvInodeRmdir:        "inode_rmdir",
	EvInodeMknod:        "inode_mknod",
	EvInodeReadlink:     "inode_readlink",
	EvInodeFollowLink:   "inode_follow_link",
	EvInodePermission:   "inode_permission",
	EvInodeCreate:       "inode_create",
	EvInodeSymlink:      "inode_symlink",
	EvInodeLink:         "inode_link",
	EvInodeSetAttr:      "inode_setattr",
	EvFileMprotect:      "file_mprotect",
	EvMmapFile:          "mmap_file",
	EvPathChmod:         "path_chmod",
	EvPathChown:         "path_chown",
	EvBprmCommitedCreds: "bprm_committed_creds",
	EvTaskAlloc:         "task_alloc",
	EvTaskFixSetuid:     "task_fix_setuid",
	EvTaskFixSetgid:     "task_fix_setgid",
	EvPtraceAccessCheck: "ptrace_access_check",
	EvTaskKill:          "task_kill",
	EvUsernsCreate:      "userns_create",
	EvCapset:            "capset",
	EvSocketCreate:      "socket_create",
	EvSocketConnect:     "socket_connect",
	EvSocketBind:        "socket_bind",
	EvSocketListen:      "socket_listen",
	EvSocketAccept:      "socket_accept",
	EvSocketSetsockopt:  "socket_setsockopt",
	EvUringAllowed:      "uring_allowed",
}

type Event struct {
	Type                 Type
	Ts                   uint64
	Tgid, Pid, Ppid, Uid uint32
	StartTime            uint64
	Comm, Path, Path2    string

	// fisiere
	TargetIno  uint64
	TargetDev  uint32
	TargetMode uint32
	ParentIno  uint64
	ParentDev  uint32
	ReqMode    uint32
	Flags      uint32

	// memorie
	Prot   uint32
	IsAnon bool

	// proces
	OldEuid, NewEuid uint32
	CapAdded         uint64
	TargetPid        uint32
	Sig              uint32

	// retea
	Family  uint32
	DstIP   net.IP
	DstPort uint16
}

func (t Type) String() string {
	if n, ok := evNames[t]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", uint32(t))
}
