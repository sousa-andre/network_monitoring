#include <uapi/linux/ptrace.h>

#define __SOCKADDR_COMMON_SIZE	(sizeof (unsigned short int))
typedef unsigned short int sa_family_t;
#define	__SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

  struct sockaddr
  {
    __SOCKADDR_COMMON (sa_);	/* Common data: address family and length.  */
    char sa_data[14];		/* Address data.  */
  };

typedef uint32_t in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };

typedef uint16_t in_port_t;

struct sockaddr_in
  {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;			/* Port number.  */
    struct in_addr sin_addr;		/* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr)
			   - __SOCKADDR_COMMON_SIZE
			   - sizeof (in_port_t)
			   - sizeof (struct in_addr)];
  };



// BPF_HASH(accept_args_map, u64, struct accept_args_t);

int accept_syscall(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, u32 *addrlen) {
    //uint64_t id = bpf_get_current_pid_tgid();

    // struct accept_args_t accept_args = {};

    // accept_args_map.update(&id, &accept_args);
    // struct sockaddr_in* addr2 = addr;
    // accept_args.addr = addr;
    // struct sockaddr_in* addr2 = (struct sockaddr_in*)addr;
    bpf_trace_printk("%d", *addrlen);

    return 0;
};