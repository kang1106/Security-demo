#include "security_app.hpp"

int main() {
    const unsigned char plainPre[4] = {0x12, 0x34, 0x56, 0x78};
    int plainLength = 4;
    unsigned char* encrypt;
    int encryptLength;
    unsigned char* tag;
    int retVal = E_NOT_OK;

    LOG(INFO) << "Openssl aes gcm test";
    OpenSSL_add_all_algorithms();

    retVal = encypt_aes_gcm(plainPre, plainLength, encrypt, &encryptLength, tag);
    LOG(INFO) << "Cipher text length: " << encryptLength;
    LOG(INFO) << "Encrypt text: " << encrypt;

    return 0;
}