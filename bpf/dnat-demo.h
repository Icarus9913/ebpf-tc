#include <stdint.h>        // uint32_t

// ebpf section
#ifndef __section
# define __section(NAME)                  \
       __attribute__((section(NAME), used))
#endif

// BPF_FUNC
#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

static int BPF_FUNC(skb_store_bytes, struct __sk_buff *skb, uint32_t off,
		    const void *from, uint32_t len, uint32_t flags);
static int BPF_FUNC(csum_diff, void *from, uint32_t from_size, void *to,
		    uint32_t to_size, uint32_t seed);
static int BPF_FUNC(l3_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static int BPF_FUNC(l4_csum_replace, struct __sk_buff *skb, uint32_t off,
		    uint32_t from, uint32_t to, uint32_t flags);
static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

// print
#ifndef printk
# define printk(fmt, ...)                                      \
    ({                                                         \
        char ____fmt[] = fmt;                                  \
        trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })
#endif

// big-endian and little-endian switch
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)

// const
#define ETH_HLEN 14
#define IP_HLEN 20
#define IPPROTO_TCP 6
