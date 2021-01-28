#include "source/loader/loader.h"
#include <error.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#include "glog/logging.h"

int map_fd;

struct bpf_object *obj;

void bpf_check_ptr(const void *obj, const char *name) {
  char err_buf[256];
  long err;

  LOG(INFO) << "bpf program name: " << name;
  if (!obj) {
    LOG(FATAL) << "bpf obj is nullptr: " << name;
  }

  err = libbpf_get_error(obj);
  if (err) {
    libbpf_strerror(err, err_buf, sizeof(err_buf));
    LOG(INFO) << "bpf: " << name << err_buf;
  }
}

struct bpf_program *do_bpf_get_prog(const char *name, enum bpf_prog_type type) {
  struct bpf_program *prog;

  prog = bpf_object__find_program_by_title(obj, name);
  bpf_check_ptr(obj, name);
  bpf_program__set_type(prog, type);

  return prog;
}

void do_bpf_attach_prog(struct bpf_program *prog, int fd,
                        enum bpf_attach_type type) {
  int prog_fd, ret;

  prog_fd = bpf_program__fd(prog);
  ret = bpf_prog_attach(prog_fd, fd, type, 0);
  if (ret) {
    LOG(FATAL) << strerror(ret) << "bpf attach prog " << type;
  }
  if (close(prog_fd)) {
    LOG(FATAL) << strerror(errno) << "bpf close prog " << type;
  }
}

void do_bpf_setup() {
  struct bpf_program *prog_parse, *prog_verdict;
  struct bpf_map *map;

  obj = bpf_object__open("data/stream.bpf.o");
  //obj = bpf_object__open("source/bpf/stream.bpf.o");
  bpf_check_ptr(obj, "obj");

  prog_parse = do_bpf_get_prog("prog_parser", BPF_PROG_TYPE_SK_SKB);
  LOG(INFO) << "get prog prog_parser";

  prog_verdict = do_bpf_get_prog("prog_verdict", BPF_PROG_TYPE_SK_SKB);
  LOG(INFO) << "get prog prog_verdict";

  if (bpf_object__load(obj)) {
    LOG(FATAL) << "bpf object load: " << libbpf_get_error(obj);
  }
  map = bpf_object__find_map_by_name(obj, "sock_map");
  bpf_check_ptr(map, "map");
  map_fd = bpf_map__fd(map);

  do_bpf_attach_prog(prog_parse, map_fd, BPF_SK_SKB_STREAM_PARSER);
  do_bpf_attach_prog(prog_verdict, map_fd, BPF_SK_SKB_STREAM_VERDICT);
}

void do_bpf_cleanup() {
  if (close(map_fd)) {
    LOG(FATAL) << strerror(errno) << "close sockmap";
  }

  bpf_object__close(obj);
}
