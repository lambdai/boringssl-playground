#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <memory>
#include <poll.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <iomanip>
#include <iostream>
#include <sstream>

#include "glog/logging.h"
#include "source/loader/cluster.h"
#include "source/loader/loader.h"

#include "external/boringssl/src/include/openssl/bio.h"
#include "external/boringssl/src/include/openssl/err.h"
#include "external/boringssl/src/include/openssl/ssl.h"

// originate from kernel/include/uapi/linux/tcp.h
#include "linux/tcp.h"

// current kernel headers
// #include "linux/socket.h"

// kernel/include/linux/socket.h"
#define SOL_TCP 6

// originate from kernel/include/uapi/linux/tls.h
#include "linux/tls.h"

static bool do_sockhash = true;
class SslOnce {
public:
  static void init() {
    // TODO(lambdai): CRYPTO_library_init is thread-safe and reentrant.
    static SslOnce once;
    LOG(INFO) << "In " << __FUNCTION__;
  }

private:
  SslOnce() {
    // no-op in boringssl.
    SSL_load_error_strings();

    // The below call is alias of the deprecated SSL_library_init(). The latter
    // calls CRYPTO_library_init(). Yet list it here for openssl guru.

    // OpenSSL_add_ssl_algorithms();

    // Needed if boring ssl is built with BORINGSSL_NO_STATIC_INITIALIZER.
    // TODO(lambdai): Seek compile-time constexpr and skip below call.
    CRYPTO_library_init();
  }
};

class ClientSocket {
public:
  ClientSocket() {}
  explicit ClientSocket(int fd) : fd_(fd) {}
  bool connect(const std::string &ipv4, int port) {
    if (!::inet_pton(AF_INET, ipv4.data(), &sock_addr_.sin_addr)) {
      return false;
    }
    sock_addr_.sin_port = htons(port);
    sock_addr_.sin_family = AF_INET;
    fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (fd_ < 0) {
      LOG(ERROR) << "fail to create socket: " << strerror(errno);
      return false;
    }
    LOG(INFO) << "connecting";
    int res =
        ::connect(fd_, reinterpret_cast<const struct sockaddr *>(&sock_addr_),
                  sizeof(struct sockaddr_in));
    if (res < 0) {
      LOG(ERROR) << "connect" << strerror(errno);
      return false;
    }
    return true;
  }
  ~ClientSocket() {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
  }
  bool valid() { return fd_ >= 0; }

  int fd_{-1};
  struct sockaddr_in sock_addr_;
};
class ServerSocket {
public:
  explicit ServerSocket(int port) : port_(port) {
    fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    int reuse = 1;
    int rc = setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int));
    if (rc < 0) {
      LOG(INFO) << "Unable to set SO_REUSEADDR";
    } else {
      LOG(INFO) << "Set SO_REUSEADDR";
    }
  }
  ~ServerSocket() {
    if (fd_ >= 0) {
      close(fd_);
      fd_ = -1;
    }
  }
  bool bind() {
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port_),
        .sin_addr =
            {
                .s_addr = htonl(INADDR_ANY),
            },
    };
    if (::bind(fd_, reinterpret_cast<const struct sockaddr *>(&addr),
               static_cast<socklen_t>(sizeof(addr))) < 0) {
      LOG(ERROR) << "bind error on " << fd_;
      return false;
    }
    return true;
  }
  bool listen() {
    if (::listen(fd_, 1) < 0) {
      LOG(ERROR) << "listen error on " << fd_;
      return false;
    }
    return true;
  }

  int getFd() { return fd_; }

  bool valid() { return fd_ >= 0; }

  std::unique_ptr<ClientSocket> accept() {
    auto socket = std::make_unique<ClientSocket>();
    socklen_t sock_len = 0;
    int fd =
        ::accept(fd_, reinterpret_cast<struct sockaddr *>(&socket->sock_addr_),
                 &sock_len);
    if (fd < 0) {
      LOG(ERROR) << "accept error on port " << port_;
      return nullptr;
    }
    socket->fd_ = fd;
    return socket;
  }

private:
  int fd_;
  int port_;
};

void dumpCurrentCipher(const SSL *ssl) {
  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  if (cipher == nullptr) {
    LOG(FATAL) << "Unknown cipher";
  }
  LOG(INFO) << "cipher: " << SSL_CIPHER_get_name(cipher);
  uint64_t read_seq = SSL_get_read_sequence(ssl);
  LOG(INFO) << "read sequence nr: " << read_seq;
  SSL_foo();
}

bool setup_ulp(int fd) {
  if (int res = setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
      res < 0) {
    LOG(INFO) << "setsockopt SOL_TCP returns " << res;
    perror("setsockopt ULP");
    return false;
  }
  return true;
}

bool setup_sock_crypto(int sock, const SSL *ssl, int direction) {

  struct tls12_crypto_info_aes_gcm_128 crypto_info;

  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  if (cipher == nullptr) {
    LOG(FATAL) << "Unknown cipher";
  }
  LOG(INFO) << "cipher: " << SSL_CIPHER_get_name(cipher);
  uint64_t seq =
      direction == 0 ? SSL_get_write_sequence(ssl) : SSL_get_read_sequence(ssl);

  // TODO(lambdai): Not sure if this TLS12 struct can be used by tls13.
  crypto_info.info.version = TLS_1_3_VERSION;
  crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_128;
  bssl::SymmetricInfo info(ssl, direction);
  {
    std::ostringstream os;
    os << "in " << __FUNCTION__ << ", key = ";
    for (const auto k : info.key_) {
      os << std::hex << std::setw(2) << static_cast<int>(k) << " ";
    }
    LOG(INFO) << os.str();
  }
  {
    std::ostringstream os;
    os << "in " << __FUNCTION__ << ", iv = ";
    for (const auto k : info.iv_) {
      os << std::hex << std::setw(2) << static_cast<int>(k) << " ";
    }
    LOG(INFO) << os.str();
  }
  memcpy(crypto_info.rec_seq, &seq, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
  memcpy(crypto_info.key, info.key_.data(), TLS_CIPHER_AES_GCM_128_KEY_SIZE);
  memcpy(crypto_info.salt, info.iv_.data(), TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  memcpy(crypto_info.iv, info.iv_.data() + 4, TLS_CIPHER_AES_GCM_128_IV_SIZE);

  if (int res = setsockopt(sock, SOL_TLS, direction == 0 ? TLS_TX : TLS_RX,
                           &crypto_info, sizeof(crypto_info));
      res < 0) {
    LOG(INFO) << "setsockopt SOL_TLS, TLS_TX returns " << res;
    perror("setsockopt SOL_TLS, TLS_TX");
    return false;
  }
  return true;
}

int main(int argc, char **argv) {
  LOG(WARNING) << "must run as sudo or set CAP_NET_ADMIN";
  // Inspired by https://wiki.openssl.org/index.php/Simple_TLS_Server

  SslOnce::init();

  LOG(INFO) << "setup bpf start";
  do_bpf_setup();
  LOG(INFO) << "setup bpf end";

  // For now we will play with TLS instead of DTLS.
  // SSLv23_server_method calls TLS_method. Other version sugar method should be
  // achieved by further SSL_CTX_set_min/max_proto_version(SSL_CTX *ctx,
  // uint16_t version);
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());

  if (!ctx) {
    LOG(FATAL) << "cannot create new ssl context";
  }
  SSL_CTX_set_keylog_callback(
      ctx, [](const SSL *ssl, const char *line) { LOG(INFO) << line; });
  // No-op in boringssl: SSL_CTX_set_ecdh_auto(ctx, onoff);

  if (SSL_CTX_use_certificate_file(ctx, "./data/server.crt",
                                   SSL_FILETYPE_PEM) <= 0) {
    LOG(FATAL) << "cannot read from cert in pem";
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "./data/server.key", SSL_FILETYPE_PEM) <=
      0) {
    LOG(FATAL) << "cannot read from key in pem";
  }

  // Call SSL_CTX_load_verify_locations() to load root CA.

  ServerSocket server_socket(4443);
  if (!(server_socket.valid() && server_socket.bind() &&
        server_socket.listen())) {
    LOG(FATAL) << "Fail to listen on port 4443 ";
  }

  LOG(INFO) << "Listening on port 4443 ";

  while (true) {
    char buf[1024];
    int n_read = 0;
    auto client = server_socket.accept();
    if (!client) {
      LOG(INFO) << "error when creating new connected socket";
      continue;
    }
    LOG(INFO) << "new client connected, fd = " << client->fd_
              << ", peer addr = "
              << "UNKNOWN";
    // SSL respresents a connection. It inherits settings from ctx. It is thread
    // migratable but it is not thread-safe.
    // SSL can reset ctx, or override settings from ctx.
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
      LOG(FATAL) << "cannot create new ssl";
    }

    // SSL_set_fd(ssl, client->fd_);
    BIO *bio = BIO_new_socket(client->fd_, 0);
    SSL_set_bio(ssl, bio, bio);

    LOG(INFO) << "ssl server handshake";
    // set as server SSL and call SSL_do_handshake.
    if (int res = SSL_accept(ssl); res <= 0) {
      int error_code = SSL_get_error(ssl, res);
      const char *error_str = SSL_error_description(error_code);
      LOG(ERROR) << "ssl server handshake error: "
                 << (error_str == nullptr ? "UNKNOWN" : error_str);
      SSL_free(ssl);
      continue;
    } else {
      LOG(INFO) << "ssl connection created.";

      dumpCurrentCipher(ssl);
      if (!setup_ulp(client->fd_)) {
        LOG(FATAL) << "Failed in setup ulp on fd " << client->fd_;
      }
      LOG(INFO) << "setsockopt ULP.";

      if (!setup_sock_crypto(client->fd_, ssl, 0 /*Write*/)) {
        LOG(FATAL) << "Failed in setup kernel crypto TX";
      }
      LOG(INFO) << "setsockopt SOL_TLS at TX";
      if (!setup_sock_crypto(client->fd_, ssl, 1 /*Read*/)) {
        LOG(FATAL) << "Failed in setup kernel crypto RX";
      }
      LOG(INFO) << "setsockopt SOL_TLS at TX";
      if (!do_sockhash) {
        int n = ::read(client->fd_, buf, sizeof(buf));
        if (n > 0) {
          LOG(INFO) << "kernel ssl read: " << std::string(buf, n);
        } else {
          LOG(ERROR) << "kernel ssl read err";
        }
        n = ::write(client->fd_, "abc", 3);
        if (n > 0) {
          LOG(INFO) << "kernel ssl write: " << std::string("abc", n);
        } else {
          LOG(ERROR) << "kernel ssl write err";
        }
        int ssl_rc = ::read(client->fd_, buf, sizeof(buf) - 1);
        if (ssl_rc > 0) {
          n_read = ssl_rc;
          // buf[ssl_rc] = '\0';
          LOG(INFO) << "Read record from kernel: " << std::string(buf, n_read);
        } else {
          LOG(INFO) << "Error read record from kernel";
        }
      } else {
        LOG(INFO) << "No pre ssl read or ssl write in sockhash";
      }
      // int rc = SSL_read(ssl, buf, sizeof(buf));
      // if (rc > 0) {
      //   LOG(INFO) << "SSL_read returns " << rc
      //             << ". Content: " << std::string(buf, rc);
      //   // Write at best effort.
      //   SSL_write(ssl, buf, rc);
      // } else if (rc == 0) {
      //   LOG(INFO) << "SSL_read returns EOF";
      // } else {
      //   LOG(INFO) << "SSL_read returns error: " << rc;
      // }

      ClientSocket origin;
      if (origin.connect("127.0.0.1", 9000)) {
        LOG(INFO) << "connected to origin";
      } else {
        LOG(ERROR) << "fail to connect origin";
      }
      if (!do_sockhash) {
        if (n_read > 0) {
          int res = 0;
          res = ::write(origin.fd_, buf, n_read);
          if (res > 0) {
            LOG(INFO) << "write to origin: " << std::string(buf, res);
          } else {
            LOG(ERROR) << "error write to origin: " << strerror(errno);
          }
          res = ::read(origin.fd_, buf, sizeof(buf));
          if (res >= 0) {
            LOG(INFO) << "read from origin: " << std::string(buf, res);
          } else {
            LOG(ERROR) << "error read from origin: " << strerror(errno);
          }
        }
      } else {
        LOG(INFO) << "kernel bpf map update";
        cluster_insert_conn(map_fd, origin.fd_);
        cluster_insert_conn(map_fd, client->fd_);

        do {
          struct pollfd pfd;
          pfd.fd = origin.fd_;
          pfd.events = POLLRDHUP;

          int ret = poll(&pfd, 1, 1000);
          if (ret == -1) {
            LOG(ERROR) << "poll eror: " << ret;
          } else if (ret == 0) {
            LOG(INFO) << "poll timeout";
          }
        } while (1);
        LOG(INFO) << "end of proxy";
      }

      SSL_shutdown(ssl);
      BIO_free(bio);
      SSL_free(ssl);
      // client socket is destroyed here.
      // origin socket is destroyed here.
    }
  }

  SSL_CTX_free(ctx);
  // cleanup_openssl();
  return 0;
}
