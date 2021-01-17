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

  if (SSL_CTX_use_certificate_file(ctx, "./data/server.crt", SSL_FILETYPE_PEM) <= 0) {
    LOG(FATAL) << "cannot read from cert in pem";
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "./data/server.key", SSL_FILETYPE_PEM) <= 0) {
    LOG(FATAL) << "cannot read from key in pem";
  }
  // SSL respresents a connection. It inherits settings from ctx. It is thread
  // migratable but it is not thread-safe.
  // SSL can reset ctx, or override settings from ctx.
  SSL *ssl = SSL_new(ctx);
  if (!ssl) {
    LOG(FATAL) << "cannot create new ssl";
    return 1;
  }

  LOG(INFO) << "Hello, boringssl " << ssl;
  // configure_context(ctx);
  // int sock = create_socket(4433);

  // /* Handle connections */
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
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  // cleanup_openssl();
  return 0;
}
