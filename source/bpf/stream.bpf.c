#include "linux/bpf.h"
// Don't use clang headers.
// #include <stdint.h> 

// bpf_helpers.h in either libbpf or in selftest
#include "bpf_helpers.h"
#include "bpf_endian.h"

char _license[] SEC("license") = "GPL";

#define NR_PAIR 100

struct conn4_key {
  __u32 local;
  __u32 remote;
  __u16 lport;
  __u16 rport;
  __u8 family;
} __attribute__((packed));

// unordered_map[tcpconn] -> sock
struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(max_entries, NR_PAIR);
  __type(key, struct conn4_key);
  __type(value, int); // TODO(lambdai): why int not long?
} peer_socks SEC(".maps");

struct bpf_map_def SEC("maps") sock_map = {
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 2,
};

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb)
{
	char debug_msg[] = "prog_parser called\n";
	bpf_trace_printk(debug_msg, sizeof(debug_msg));
	return skb->len;
}

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb)
{
	char debug_msg[] = "prog_parser verdict called\n";
	bpf_trace_printk(debug_msg, sizeof(debug_msg));
    __u32 key;
    struct conn4_key conn_key;
	//return bpf_sk_redirect_map(skb, &sock_map, key, 0);
    return bpf_sk_redirect_hash(skb, &peer_socks, &conn_key, 0);
}