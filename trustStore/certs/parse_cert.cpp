#include "../include/openssl/pem.h"
#include "../include/openssl/bio.h"
#include "../include/openssl/x509.h"

int main(){
    BIO *bp = NULL;
    bp = BIO_new_file("usercert.pem", "r");

    while (1) {
        X509 *cert;
        cert = PEM_read_bio_X509(bp, NULL, 0, NULL);
        if (cert == NULL) {
            printf("read certificate failed");
            break;
        }

        X509_print_fp(stdout, cert);
        printf("%d\n",X509_get_signature_type(cert));
        printf("%d\n",(int)X509_get_version(cert));
        X509_free(cert);
    }
    BIO_free(bp);
    return 0;
}