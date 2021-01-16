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
    // Needed if boring ssl is built with BORINGSSL_NO_STATIC_INITIALIZER.
    CRYPTO_library_init();
  }
};

int main(int argc, char **argv) {
  // init_openssl();
  SslOnce::init();
  SSL_CTX *ctx = SSL_CTX_new(TLS_method());

  SSL *ssl = SSL_new(ctx);

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
}
