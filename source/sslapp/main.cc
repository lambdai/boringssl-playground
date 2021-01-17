#include <arpa/inet.h>
#include <memory>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include "glog/logging.h"

#include "external/boringssl/src/include/openssl/bio.h"
#include "external/boringssl/src/include/openssl/err.h"
#include "external/boringssl/src/include/openssl/ssl.h"

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
int main(int argc, char **argv) {
  // Inspired by https://wiki.openssl.org/index.php/Simple_TLS_Server

  SslOnce::init();

  // For now we will play with TLS instead of DTLS.
  // SSLv23_server_method calls TLS_method. Other version sugar method should be
  // achieved by further SSL_CTX_set_min/max_proto_version(SSL_CTX *ctx,
  // uint16_t version);
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());

  if (!ctx) {
    LOG(FATAL) << "cannot create new ssl context";
  }

  // No-op in boringssl: SSL_CTX_set_ecdh_auto(ctx, onoff);

  if (SSL_CTX_use_certificate_file(ctx, "./data/server.crt",
                                   SSL_FILETYPE_PEM) <= 0) {
    LOG(FATAL) << "cannot read from cert in pem";
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "./data/server.key", SSL_FILETYPE_PEM) <=
      0) {
    LOG(FATAL) << "cannot read from key in pem";
  }

  ServerSocket server_socket(4443);
  if (!(server_socket.valid() && server_socket.bind() &&
        server_socket.listen())) {
    LOG(FATAL) << "Fail to listen on port 4443 ";
  }

  LOG(INFO) << "Listening on port 4443 ";

  while (true) {
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
    SSL_set_fd(ssl, client->fd_);

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
    }
    SSL_shutdown(ssl);
    SSL_free(ssl);
    // client socket is destroyed here.
  }
  // while(1) {
  //     struct sockaddr_in addr;
  //     uint len = sizeof(addr);
  //     SSL *ssl;
  //     const char reply[] = "test\n";

  //     int client = accept(sock, (struct sockaddr*)&addr, &len);
  //     if (client < 0) {
  //         perror("Unable to accept");
  //         exit(EXIT_FAILURE);
  //     }

  //     ssl = SSL_new(ctx);
  //     SSL_set_fd(ssl, client);

  //     if (SSL_accept(ssl) <= 0) {
  //         ERR_print_errors_fp(stderr);
  //     }
  //     else {
  //         SSL_write(ssl, reply, strlen(reply));
  //     }

  //     SSL_shutdown(ssl);
  //     SSL_free(ssl);
  //     close(client);
  // }

  // close(sock);
  // SSL_free(ssl);
  SSL_CTX_free(ctx);
  // cleanup_openssl();
  return 0;
}
