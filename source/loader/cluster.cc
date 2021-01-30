#include "source/loader/loader.h"

#include <arpa/inet.h>
#include <error.h>
#include <stdint.h>
#include <sys/socket.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include "glog/logging.h"

// TODO(lambdai): This should be shared among kernel bpf and user space bpf.
struct conn4_key {
  uint32_t local;
  uint32_t remote;
  uint16_t lport;
  uint16_t rport;
  uint8_t family;
} __attribute__((packed));

bool cluster_insert_conn(int map_fd, int sock_fd) {
  struct sockaddr_in sock_addr;
  socklen_t addr_len = sizeof(sock_addr);
  if (getsockname(sock_fd, reinterpret_cast<struct sockaddr *>(&sock_addr), &addr_len) != 0) {
    LOG(ERROR) << "Failed to get local socket info on fd " << sock_fd;
    return false;
  }
  conn4_key conn_key = {
      .local = 0,
      .remote = 0,
      .lport = 0,
      .rport = 0,
      .family = 0,
  };
  conn_key.lport = ntohs(sock_addr.sin_port);
  LOG(INFO) << "local port: " << conn_key.lport;
  uint32_t val = sock_fd;
  if (bpf_map_update_elem(map_fd, &conn_key, &val, BPF_ANY)) {
    LOG(ERROR) << "fail to insert sock fd " << sock_fd << " into sockhash " << map_fd;
    return false;
  }
  LOG(INFO) << "inserted sock fd " << sock_fd << " into sockhash " << map_fd;
  return true;
}