#include "security_app.hpp"

int main (void)
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 128 bit key */
    // unsigned char *key = (unsigned char *)"0123456789012345";
    unsigned char key[16] = {0x0, 0x1, 0x2, 0x3,
                           0x4, 0x5, 0x6, 0x7,
                           0x8, 0x9, 0x0, 0x1,
                           0x2, 0x3, 0x4, 0x5};

    /* A 128 bit IV */
    // unsigned char *iv = (unsigned char *)"012345678901";
    unsigned char iv[12] = {0x0, 0x1, 0x2, 0x3,
                            0x4, 0x5, 0x6, 0x7,
                            0x8, 0x9, 0x0, 0x1};
    size_t iv_len = 12;

    /* Message to be encrypted */
    unsigned char *plaintext =
         (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Additional data */
    unsigned char *additional =
        (unsigned char *)"The five boxing wizards jump quickly.";

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    /* Buffer for the tag */
    unsigned char tag[16];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = gcm_encrypt(plaintext, strlen ((char *)plaintext),
                                 additional, strlen ((char *)additional),
                                 key,
                                 iv, iv_len,
                                 ciphertext, tag);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    printf("Tag is:\n");
    BIO_dump_fp (stdout, (const char *)tag, 16);

    /* Decrypt the ciphertext */
    decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len,
                                    additional, strlen ((char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    } else {
        printf("Decryption failed\n");
    }

    tag[sizeof(tag)-1]+=0xAA;
    printf("\nModified tag is:\n");
    BIO_dump_fp (stdout, (const char *)tag, 16);


    /* Decrypt the ciphertext with modified tag */
    decryptedtext_len = gcm_decrypt(ciphertext, ciphertext_len,
                                    additional, strlen ((char *)additional),
                                    tag,
                                    key, iv, iv_len,
                                    decryptedtext);

    if (decryptedtext_len >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        decryptedtext[decryptedtext_len] = '\0';

        /* Show the decrypted text */
        printf("Decrypted text is:\n");
        printf("%s\n", decryptedtext);
    } else {
        printf("Decryption failed\n");
    }

    return 0;
}
