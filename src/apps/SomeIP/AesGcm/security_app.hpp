#include <openssl/evp.h>
#include <glog/logging.h>

#define E_OK       0
#define E_NOT_OK   1

const int keyLength = 16;
static const unsigned char gcm_key[keyLength] =
    {0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11};

const int ivLength = 12;
static const unsigned char gcm_iv[ivLength] =
    {0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11};

const int aadLength = 16;
static const unsigned char gcm_aad[aadLength] =
    {0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11,
     0x11, 0x11, 0x11, 0x11};

int encypt_aes_gcm(const unsigned char* plain, int plainLength, unsigned char* encrypt, int* encryptLength, unsigned char* tag) {
    EVP_CIPHER_CTX *ctx;
    int len;

    LOG(INFO) << "AES GCM encryption start";
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        LOG(ERROR) << "Cipher context init failed";

    LOG(INFO) << "Creat cipher context success";

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOG(ERROR) << "Cipher operation init failed";

    LOG(INFO) << "AES GCM encryption operation init";

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL))
        LOG(ERROR) << "Cipher operation init failed";

    LOG(INFO) << "AES GCM set iv length";

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv))
        LOG(ERROR) << "Cipher key and iv init failed";

    LOG(INFO) << "AES GCM set iv and key";

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, gcm_aad, aadLength))
        LOG(ERROR) << "Add init failed";

    LOG(INFO) << "AES GCM set aad and aad length";

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, encrypt, encryptLength, plain, plainLength))
        LOG(ERROR) << "Update plain text failed";

    LOG(INFO) << "AES GCM cipher length: " << *encryptLength;
    LOG(INFO) << "AES GCM cipher: ";
    for(int i = 0; i < *encryptLength; i++) {
        printf("%x", encrypt[i]);
    }

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, encrypt + *encryptLength, &len))
        LOG(ERROR) << "Finalize gcm encryption";
    *encryptLength += len;
    LOG(INFO) << "AES GCM cipher length: " << *encryptLength;
    LOG(INFO) << "AES GCM cipher: " << encrypt;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
        LOG(ERROR) << "Get gcm authenticate tag";

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return E_OK;
}

int decypt_aes_gcm(const unsigned char* encrypt, int encryptLength, unsigned char* plain, int* plainLength, unsigned char* tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        LOG(ERROR) << "Cipher context init failed";

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        LOG(ERROR) << "Cipher decrypt init failed";

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, ivLength, NULL))
        LOG(ERROR) << "IV Length set failed";

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv))
        LOG(ERROR) << "Key and IV set failed";

    /*
     * Provide any AAD data. This can be called zero or more times as
     * required
     */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, gcm_aad, aadLength))
        LOG(ERROR) << "AAD and key set failed";

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plain, plainLength, encrypt, encryptLength))
        LOG(ERROR) << "AES GCM decrypt failed";

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
        LOG(ERROR) << "AES GCM set expected tag failed";

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plain + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        *plainLength += len;
        return E_OK;
    } else {
        /* Verify failed */
        return E_NOT_OK;
    }
}