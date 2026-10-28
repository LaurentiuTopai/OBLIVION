Aici am dezvoltat asa:

helpers.h
lsm_file.h apelurile : 
    -lsm/file_open
    -lsm/file_permission
    -lsm/file_truncate
    -lsm/inode_unlink
    -lsm/inode_rename
    -lsm/inode_mkdir
    -lsm/inode_rmdir
    -lsm/inode_mknod
    -lsm/inode_readlink
    -lsm/inode_follow_link
    -lsm/inode_permission
maps.h
common.h



helpers.h este un header ce contine functiile 
1.de evenimente ce vor fi transmite prin ring_buffer catre userspace in go
2.de citit inode_urile asociate fisierelor
3.de citit numele fisierelor

maps.h reprezinta structurile de ringbuffer si de structura de date ce va fi folosita dealungul dezvoltari 

common.h contine structura datelor 
    -file_meta
    -event
file_meta reprezinta structura specifica inode din sistem cat si particularitatile fisierului
event reprezinta structura evenimentului ce se petrece la nivel de sistem,proces activ,proces parinte,activitate overall

Probleme intampinate azi:
apelurile de sistem precum inode_mkdir/inode_mknod primesc in req_mode modul de crearea al fisierului,acest mode este primit din procesul ce-l executa comparativ cu 
inode_rename/inode_rmdir/inode_premission care sunt mode-uri primite in inode_ul existent.

