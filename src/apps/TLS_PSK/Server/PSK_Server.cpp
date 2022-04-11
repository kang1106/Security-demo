#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "glog/logging.h"

/********* local define *********/
struct ssl_cipher_st {
    uint32_t valid;
    const char *name;           /* text name */
    const char *stdname;        /* RFC name */
    uint32_t id;                /* id, 4 bytes, first is version */
    /*
     * changed in 1.0.0: these four used to be portions of a single value
     * 'algorithms'
     */
    uint32_t algorithm_mkey;    /* key exchange algorithm */
    uint32_t algorithm_auth;    /* server authentication */
    uint32_t algorithm_enc;     /* symmetric encryption */
    uint32_t algorithm_mac;     /* symmetric authentication */
    int min_tls;                /* minimum SSL/TLS protocol version */
    int max_tls;                /* maximum SSL/TLS protocol version */
    int min_dtls;               /* minimum DTLS protocol version */
    int max_dtls;               /* maximum DTLS protocol version */
    uint32_t algo_strength;     /* strength and export flags */
    uint32_t algorithm2;        /* Extra flags */
    int32_t strength_bits;      /* Number of bits really used */
    uint32_t alg_bits;          /* Number of bits for algorithm */
};

#define BUFF_SIZE 1024

const unsigned char tls13_aes128gcmsha256_id[] = { 0x13, 0x01 };
const char psk_ecua_key[] = "1a2b3c4d5e";   /* psk identity: psk_ecua */
const char psk_ecub_key[] = "1a2b3c4d5f";   /* psk identity: psk_ecub */

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        LOG(ERROR) << "Unable to create socket";
        exit(EXIT_FAILURE);
    }
    LOG(INFO) << "Creat socket success";

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG(ERROR) << "Unable to bind socket";
        exit(EXIT_FAILURE);
    }
    if (listen(s, 1) < 0) {
        LOG(ERROR) << "Unable to listen port";
        exit(EXIT_FAILURE);
    }
    LOG(INFO) << "Listen port......";

    return s;
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG(ERROR) << "Unable to create SSL context";
        exit(EXIT_FAILURE);
    }
    LOG(INFO) << "Creat SSL context";

    return ctx;
}

static unsigned int psk_server_cb(SSL *ssl, const char *identity,
                                  unsigned char *psk,
                                  unsigned int max_psk_len)
{
    long key_len = 0;
    unsigned char *key;

    LOG(INFO) << "psk_server_cb";

    if (!SSL_is_dtls(ssl) && SSL_version(ssl) >= TLS1_3_VERSION) {
        /*
         * This callback is designed for use in (D)TLSv1.2 (or below). It is
         * possible to use a single callback for all protocol versions - but it
         * is preferred to use a dedicated callback for TLSv1.3. For TLSv1.3 we
         * have psk_find_session_cb.
         */
        return 0;
    }

    if (identity == NULL) {
        LOG(ERROR) << "Client did not send PSK identity";
    }
    LOG(INFO) << "identity_len= " << (int)strlen(identity);
    LOG(INFO) << "identity= " << identity;

    /* here we could lookup the given identity e.g. from a database */
    if (0 == strcmp(identity, "psk_ecua")) {
        LOG(INFO) << "PSK client identity found: " << identity;
        /* convert the PSK key to binary */
        key = OPENSSL_hexstr2buf(psk_ecua_key, &key_len);
    } else if (0 == strcmp(identity, "psk_ecub")) {
        LOG(INFO) << "PSK client identity found: " << identity;
        /* convert the PSK key to binary */
        key = OPENSSL_hexstr2buf(psk_ecub_key, &key_len);
    } else {
        LOG(ERROR) << "PSK client identity not found";
        return 0;
    }

    if (key == NULL) {
        LOG(ERROR) << "Could not convert PSK key to buffer";
        return 0;
    }
    if (key_len > (int)max_psk_len) {
        LOG(ERROR) << "psk buffer of callback is too small " << max_psk_len << " for key " << key_len;
        OPENSSL_free(key);
        return 0;
    }

    memcpy(psk, key, key_len);
    OPENSSL_free(key);

    LOG(INFO) << "Fetched PSK len=" << key_len;
    return key_len;
}

static int psk_find_session_cb(SSL *ssl, const unsigned char *identity,
                               size_t identity_len, SSL_SESSION **sess)
{
    SSL_SESSION *tmpsess = NULL;
    unsigned char *key;
    long key_len;
    const SSL_CIPHER *cipher = NULL;

    if (strlen("psk_ecua") == identity_len && 0 == memcmp("psk_ecua", identity, identity_len)) {
        LOG(INFO) << "PSK client identity found: " << identity;
        key = OPENSSL_hexstr2buf(psk_ecua_key, &key_len);
    } else if (strlen("psk_ecub") == identity_len && 0 == memcmp("psk_ecub", identity, identity_len)) {
        LOG(INFO) << "PSK client identity found: " << identity;
        key = OPENSSL_hexstr2buf(psk_ecub_key, &key_len);
    } else {
        *sess = NULL;
        LOG(ERROR) << "PSK client identity not found";
        return 0;
    }

    if (key == NULL) {
        LOG(ERROR) << "Could not convert PSK key to buffer";
        return 0;
    }

    /* We default to SHA256 */
    cipher = SSL_CIPHER_find(ssl, tls13_aes128gcmsha256_id);
    if (cipher == NULL) {
        LOG(ERROR) << "Error finding suitable ciphersuite";
        OPENSSL_free(key);
        return 0;
    }

    LOG(INFO) << "Cipher name: " << cipher->name;

    tmpsess = SSL_SESSION_new();
    if (tmpsess == NULL
            || !SSL_SESSION_set1_master_key(tmpsess, key, key_len)
            || !SSL_SESSION_set_cipher(tmpsess, cipher)
            || !SSL_SESSION_set_protocol_version(tmpsess, SSL_version(ssl))) {
        OPENSSL_free(key);
        return 0;
    }
    LOG(INFO) << "psk callback end";
    OPENSSL_free(key);
    *sess = tmpsess;

    return 1;
}

void configure_context(SSL_CTX *ctx)
{
    LOG(INFO) << "Configure psk session callback";
    SSL_CTX_set_psk_server_callback(ctx, psk_server_cb);
    SSL_CTX_set_psk_find_session_callback(ctx, psk_find_session_cb);

    LOG(INFO) << "Set TLS cipher";
    SSL_CTX_set_cipher_list(ctx, "PSK-AES128-GCM-SHA256");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
}

int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    OpenSSL_add_ssl_algorithms();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while(1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;
        char message[BUFF_SIZE];
        int str_len;
        const char reply[] = "Message received ACK\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            LOG(ERROR) << "Unable to accept";
            exit(EXIT_FAILURE);
        }
        LOG(INFO) << "Accecpt client request, socket id: " << client;

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) == -1) {
            LOG(ERROR) << "SSL connection failed";
        } else {
            LOG(INFO) << "SSL connection using: " << SSL_get_cipher(ssl);
            while(1) {
                str_len = SSL_read(ssl, message, BUFF_SIZE - 1);
                message[str_len] = '\0';
                LOG(INFO) << "Message from client: " << message;
                SSL_write(ssl, reply, strlen(reply));
            }
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
}
