#pragma once
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "helpers.h"
#include "common.h"

SEC("lsm/socket_create")
int BPF_PROG(on_socket_create, int family, int type, int protocol, int kern, int ret)
{
    if (ret)
        return ret;
    if (kern)
        return 0;
    if (family != AF_PACKET && (type & 0xf) != SOCK_RAW)
        return 0;

    struct event *e = event_reserve(EV_SOCKET_CREATE);
    if (!e)
        return 0;

    e->family    = family;
    e->sock_type = type;
    e->protocol  = protocol;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(on_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret)
        return ret;
    if (!is_inet(address))
        return 0;

    struct event *e = event_reserve(EV_SOCKET_CONNECT);
    if (!e)
        return 0;

    fill_sockaddr(e, address);
    e->sock_type = BPF_CORE_READ(sock, type);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(on_socket_bind, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
    if (ret)
        return ret;
    if (!is_inet(address))
        return 0;

    struct event *e = event_reserve(EV_SOCKET_BIND);
    if (!e)
        return 0;

    fill_sockaddr(e, address);
    e->sock_type = BPF_CORE_READ(sock, type);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(on_socket_listen, struct socket *sock, int backlog, int ret)
{
    if (ret)
        return ret;

    struct event *e = event_reserve(EV_SOCKET_LISTEN);
    if (!e)
        return 0;

    e->backlog   = backlog;
    e->family    = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
    e->sport     = BPF_CORE_READ(sock, sk, __sk_common.skc_num);
    e->sock_type = BPF_CORE_READ(sock, type);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/socket_accept")
int BPF_PROG(on_socket_accept, struct socket *sock, struct socket *newsock, int ret)
{
    if (ret)
        return ret;
	
	__u16 fam = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
	if (fam != AF_INET && fam != AF_INET6)
    		return 0;

    struct event *e = event_reserve(EV_SOCKET_ACCEPT);
    if (!e)
        return 0;

    e->family = fam;
    e->sport  = BPF_CORE_READ(sock, sk, __sk_common.skc_num);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/socket_setsockopt")
int BPF_PROG(on_socket_setsockopt, struct socket *sock, int level, int optname, int ret)
{
    if (ret)
        return ret;
    if (level != SOL_SOCKET || (optname != SO_ATTACH_FILTER && optname != SO_ATTACH_BPF))
        return 0;

    struct event *e = event_reserve(EV_SOCKET_SETSOCKOPT);
    if (!e)
        return 0;

    e->protocol = level;
    e->optname  = optname;

    bpf_ringbuf_submit(e, 0);
    return 0;
}
