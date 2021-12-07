#include "../include/openssl/pem.h"
#include "../include/openssl/bio.h"
#include "../include/openssl/x509.h"
#include "../include/openssl/sm2.h"

int main(){
    BIO *bp = NULL;
    bp = BIO_new_file("userkey.pem", "r");

        // X509 *cert;
        EC_KEY *private_key;
        private_key = PEM_read_bio_ECPrivateKey(bp, NULL, 0, NULL);
        if (private_key == NULL) {
            printf("read key failed");
            return 0;
        }

        EC_KEY_print_fp(stdout, private_key, 0);
        auto privateKey = EC_KEY_get0_private_key(private_key);
        auto ss = BN_bn2hex(privateKey);
        printf("%s", ss);
        // printf("%d\n",X509_get_signature_type(cert));
        // printf("%d\n",(int)X509_get_version(cert));
        EC_KEY_free(private_key);
    BIO_free(bp);
    return 0;
}