#ifndef GMSSL_HPP_
#define GMSSL_HPP_

#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <string.h>
#include "context.hpp"

class context;

class gmssl {
  public:
    explicit gmssl(std::shared_ptr<context> ctx) :
        ctx_(ctx), PKEY_TYPE(0), pCtx(nullptr), pKeyParams(nullptr), pKey(nullptr),
        mdCtx(nullptr), signature(nullptr), signLen(nullptr) {}
    ~gmssl() {};
    void set_pkey_type(int type);
    void generate_pkey();
    unsigned char* sign_message(char* msg);
    void clean();
    int verify_message(char* msg);
    void init();
    void shutdown();

  private:
    std::shared_ptr<context> ctx_;

    /** @brief Public Key Type, support:
     *     EVP_PKEY_EC (SM2、ECDSA、ECIES、ECDH)
     *     EVP_PKEY_DSA (DSA)
     *     EVP_PKEY_DH (DH) 
     */
    int PKEY_TYPE;

    /** context for parameter generation */
    EVP_PKEY_CTX* pCtx;

    /** parameter for public key generation */ 
    EVP_PKEY* pKeyParams;

    /** public key */
    EVP_PKEY* pKey;

    /** message digst context */
    EVP_MD_CTX* mdCtx;

    /** message signature */
    unsigned char* signature;

    /** signature length */
    size_t* signLen;
};

#endif /* GMSSL_HPP_ */