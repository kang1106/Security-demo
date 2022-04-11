#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
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
const char psk_identity[] = "psk_ecua";
const char psk_key[] = "1a2b3c4d5e";

SSL_CTX *create_context()
{
    LOG(INFO) << "Create SSL context";
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        LOG(ERROR) << "Create SSL context failed";
        return nullptr;
    }

    return ctx;
}

static int psk_use_session_cb(SSL *s, const EVP_MD *md,
                              const unsigned char **id, size_t *idlen,
                              SSL_SESSION **sess)
{
    SSL_SESSION *usesess = NULL;
    const SSL_CIPHER *cipher = NULL;

    long key_len;
    unsigned char *key = OPENSSL_hexstr2buf(psk_key, &key_len);
    // unsigned char key[] = {0x1a, 0x2b, 0x3c, 0x4d, 0x5e};

    if (key == NULL) {
        LOG(ERROR) << "Could not convert PSK key" << psk_key << " to buffer";
        return 0;
    }

    /* We default to SHA-256 */
    cipher = SSL_CIPHER_find(s, tls13_aes128gcmsha256_id);
    if (cipher == NULL) {
        LOG(ERROR) << "Cannot find suitable ciphersuite";
        OPENSSL_free(key);
        return 0;
    }

    LOG(INFO) << "Find session cipher name: " << cipher->name;

    usesess = SSL_SESSION_new();
    if (usesess == NULL
            || !SSL_SESSION_set1_master_key(usesess, key, key_len)
            || !SSL_SESSION_set_cipher(usesess, cipher)
            || !SSL_SESSION_set_protocol_version(usesess, TLS1_3_VERSION)) {
        OPENSSL_free(key);
        LOG(ERROR) << "Creating ssl session failed";
    }
    OPENSSL_free(key);

    cipher = SSL_SESSION_get0_cipher(usesess);
    if (cipher == NULL)
        LOG(ERROR) << "Error creating ssl session";

    if (md != NULL && SSL_CIPHER_get_handshake_digest(cipher) != md) {
        /* PSK not usable, ignore it */
        LOG(ERROR) << "PSK not usable, ignore it";
        *id = NULL;
        *idlen = 0;
        *sess = NULL;
        SSL_SESSION_free(usesess);
    } else {
        LOG(INFO) << "PSK usable, psk length: " <<  key_len;
        *sess = usesess;
        *id = (unsigned char *)psk_identity;
        *idlen = strlen(psk_identity);
    }

    return 1;
}

void configure_context(SSL_CTX *ctx)
{
    LOG(INFO) << "Configure psk session callback";
    SSL_CTX_set_psk_use_session_callback(ctx, psk_use_session_cb);

    LOG(INFO) << "Set TLS cipher";
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
}

int main(int argc, char *argv[]) {
    int client;
    struct sockaddr_in serv_addr;
    char message[BUFF_SIZE];
    int str_len = 0, read_len = 0;

    SSL_CTX *ctx;

    if(argc != 3) {
        LOG(ERROR) << "Usage: " << argv[0] << "<IP> <port>";
        exit(0);
    }

    OpenSSL_add_ssl_algorithms();
    ctx = create_context();
    configure_context(ctx);

    client = socket(PF_INET, SOCK_STREAM, 0);
    if(client == -1) {
        LOG(ERROR) << "Creat socket failed";
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));

    if(connect(client, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1) {
        LOG(ERROR) << "Connect socket port failed";
    } else {
        LOG(INFO) << "Connecting........";
    }

    while (1)
    {
        SSL *ssl;

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        if(SSL_connect(ssl) == -1) {
            LOG(ERROR) << "SSL connection failed";
            return 0;
        } else {
            LOG(INFO) << "SSL connection using cipher: " <<  SSL_get_cipher(ssl);

            while(1) {
                LOG(INFO) << "Input Q/q to exit";
                fgets(message, BUFF_SIZE, stdin);
                if(!strcmp(message, "q\n") || !strcmp(message, "Q\n"))
                    break;
                SSL_write(ssl, message, strlen(message));
                str_len = SSL_read(ssl, message, BUFF_SIZE - 1);
                message[str_len] = '\0';
                LOG(INFO) << "Message from server: " << message;
            }
        }
        SSL_free(ssl);
    }

    close(client);
    SSL_CTX_free(ctx);
    return 0;
}
