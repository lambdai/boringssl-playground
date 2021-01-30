//#include "linux/bpf.h"
#include "vmlinux.h"
// Don't use clang headers.
// #include <stdint.h>

// bpf_helpers.h in either libbpf or in selftest
#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

#define NR_PAIR 100

// struct bpf_map_def SEC("maps") sock_map = {
//     .type = BPF_MAP_TYPE_SOCKMAP,
//     .key_size = sizeof(int),
//     .value_size = sizeof(int),
//     .max_entries = 2,
// };

struct conn4_key {
  __u32 local;
  __u32 remote;
  __u16 lport;
  __u16 rport;
  __u8 family;
} __attribute__((packed));

// unordered_map[tcpconn] -> sock

// Non BTF style but failed.
// struct bpf_map_def SEC(".maps") peer_socks = {
//     .type = BPF_MAP_TYPE_SOCKHASH,
//     .max_entries = 100,
//     //.key_size = sizeof(struct conn4_key),
//     .key_size = sizeof(int),
//     .value_size = sizeof(int), // TODO(lambdai): why int not long?
// };

struct {
  __uint(type, BPF_MAP_TYPE_SOCKHASH);
  __uint(max_entries, NR_PAIR);
  __type(key, struct conn4_key);
  __type(value, int); // TODO(lambdai): why int not long?
} peer_socks SEC(".maps");

SEC("prog_parser")
int _prog_parser(struct __sk_buff *skb) {
  char debug_msg[] = "prog_parser called\n";
  bpf_trace_printk(debug_msg, sizeof(debug_msg));
  return skb->len;
}

SEC("prog_verdict")
int _prog_verdict(struct __sk_buff *skb) {
  char debug_msg[] = "prog_parser verdict called\n";
  bpf_trace_printk(debug_msg, sizeof(debug_msg));
  //__u32 key = 0;
  // return bpf_sk_redirect_map(skb, &sock_map, key, 0);
  struct conn4_key conn_key = {
      .local = 0,
      .remote = 0,
      .lport = 0,
      .rport = 0,
      .family = 0,
  };
  // TODO(lambdai): fill all the fields.
  conn_key.lport = skb->local_port;
  return bpf_sk_redirect_hash(skb, &peer_socks, &conn_key, 0);
}