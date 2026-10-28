package loader

func fileHooks(o *oblivionObjects) []Hook {
	return []Hook{
		{"file_open", o.OnFileOpen},
		{"file_truncate", o.OnFileTruncate},
	}
}


func pathHooks(o *oblivionObjects) []Hook {
	return []Hook{
		{"path_chmod", o.OnPathChmod},
		{"path_chown", o.OnPathChown},
	}
}

func memHooks(o *oblivionObjects) []Hook{
	return []Hook{
		{"file_mprotect", o.OnFileMprotect},
		{"mmap_file", o.OnMmapFile},
	}
}

func inodeHooks(o *oblivionObjects) []Hook {
	return []Hook{
		{"inode_unlink", o.OnInodeUnlink},
		{"inode_rename", o.OnInodeRename},
		{"inode_mkdir", o.OnInodeMkdir},
		{"inode_rmdir", o.OnInodeRmdir},
		{"inode_create", o.OnInodeCreate},
		{"inode_symlink", o.OnInodeSymlink},
		{"inode_link", o.OnInodeLink},
		{"inode_setattr", o.OnInodeSetattr},
		{"inode_mknod", o.OnInodeMknod},
		{"inode_readlink", o.OnInodeReadlink},
	}
}
func procHooks(o *oblivionObjects) []Hook {
	return []Hook{
		{"bprm_check_security", o.OnBprmCheckSecurity},
		{"bprm_committed_creds", o.OnBprmCommittedCreds},
		{"task_alloc", o.OnTaskAlloc},
		{"task_fix_setuid", o.OnTaskFixSetuid},
		{"task_fix_setgid", o.OnTaskFixSetgid},
		{"ptrace_access_check", o.OnPtraceAccessCheck},
		{"task_kill", o.OnTaskKill},
		{"userns_create", o.OnUsernsCreate},
		{"capset", o.OnCapset},
	}
}
func netHooks(o *oblivionObjects) []Hook {
	return []Hook{
		{"socket_create", o.OnSocketCreate},
		{"socket_connect", o.OnSocketConnect},
		{"socket_bind", o.OnSocketBind},
		{"socket_listen", o.OnSocketListen},
		{"socket_accept", o.OnSocketAccept},
		{"socket_setsockopt", o.OnSocketSetsockopt},
	}
}
// Hook-uri zgomotoase, dezactivate implicit
func noisyHooks(o *oblivionObjects) []Hook {
	return []Hook{
		{"file_permission", o.OnFilePermission},
		{"inode_permission", o.OnInodePermission},
		{"inode_follow_link", o.OnInodeFollowLink},
	}
}
/*
func io_uringHooks(o *oblivionObjects) []Hook{
	return []Hook{
		{"nume","nume"},..
	}
}
*/
