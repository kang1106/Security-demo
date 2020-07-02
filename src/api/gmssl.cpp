#include "gmssl.hpp"

void gmssl::init() {
    ctx_->log_->info("gmssl init ...");
    /* Load the human readable error strings for libcrypto */
    ERR_load_crypto_strings();
    /* Load all digest and cipher algorithms */
    OpenSSL_add_all_algorithms();
    /* Load config file, and other important initialisation */
    OPENSSL_config(nullptr);
}

void gmssl::shutdown() {
    ctx_->log_->info("gmssl shutdown ...");
    /* Removes all digests and ciphers */
    EVP_cleanup();
    /* if you omit the next, a small leak may be left when you make use of 
     * the BIO (low level API) for e.g. base64 transformations.
     */
    CRYPTO_cleanup_all_ex_data();
    /* Remove error strings */
    ERR_free_strings();
}

void gmssl::set_pkey_type(int type) {
    ctx_->log_->info("setting public key type ...");
    if (type == EVP_PKEY_EC) {
        PKEY_TYPE = EVP_PKEY_EC;
    } else if (type == EVP_PKEY_DSA) {
        PKEY_TYPE = EVP_PKEY_DSA;
    } else if (type == EVP_PKEY_DH) {
        PKEY_TYPE = EVP_PKEY_DH;
    } else {
        ctx_->log_->warning("invalid public key type ...");
        return;
    }
    ctx_->log_->info("setting public key successfully ...");
}

void gmssl::generate_pkey() {
    ctx_->log_->info("public key generation starting ...");
    /* creat context for parameter generation*/
    pCtx = EVP_PKEY_CTX_new_id(PKEY_TYPE, nullptr);
    if(!pCtx) {
        ctx_->log_->debug("creat parameter context failed ...");
        return;
    }

    if(!EVP_PKEY_paramgen_init(pCtx)) {
        ctx_->log_->debug("init parameter failed ...");
        return;
    }

    /* generate parameter base on public key type */
    switch(PKEY_TYPE) {
        case EVP_PKEY_EC:
	        /* NID_sm2p256v1 curve */
	        if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pCtx, NID_sm2p256v1)) {
                ctx_->log_->debug("setting pctx NID failed ...");
                return;
            }
	        break;

        case EVP_PKEY_DSA:
	        /* setting pctx length 2048 */
	        if(!EVP_PKEY_CTX_set_dsa_paramgen_bits(pCtx, 2048)) {
                ctx_->log_->debug("setting pctx length failed ...");
                return;
            }
	        break;

        case EVP_PKEY_DH:
	        /* setting pctx 2048 bit prime */
	       if(!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pCtx, 2048)) {
                ctx_->log_->debug("setting pctx prime failed ...");
                return;
           }
    }

    if (!EVP_PKEY_paramgen(pCtx, &pKeyParams)) {
        ctx_->log_->debug("generate public key parameter failed ...");
        return;
    }
    /* generate public key */
    if(pKeyParams != nullptr) {
	    if(!(pCtx = EVP_PKEY_CTX_new(pKeyParams, nullptr))) {
            ctx_->log_->debug("creat public key context failed ...");
            return;
        }
    } else {
        return;
    }

    if(!EVP_PKEY_keygen_init(pCtx)) {
        ctx_->log_->debug("init key generation failed ...");
        return;
    }

    /* RSA key setting length not support currently */
    // if(PKEY_TYPE == EVP_PKEY_RSA) {
	//     if(!EVP_PKEY_CTX_set_rsa_keygen_bits(pCtx, 2048)) {
    //         ctx_->log_->debug("setting key length failed ...");
    //         return;
    //     }
    // }

    /* generate key */
    if (!EVP_PKEY_keygen(pCtx, &pKey)) {
        ctx_->log_->debug("generate public key failed ...");
        return;
    }
}

unsigned char* gmssl::sign_message(char* msg) {
    ctx_->log_->info("start sign message ...");
    
    /* creat message digest context */
    if(!(mdCtx = EVP_MD_CTX_create())) {
        ctx_->log_->debug("creat message context failed ...");
        return nullptr;
    }
    
    if(1 != EVP_DigestSignInit(mdCtx, NULL, EVP_sm3(), NULL, pKey)) {
        ctx_->log_->debug("init digest failed ...");
        return nullptr;
    }
    if(1 != EVP_DigestSignUpdate(mdCtx, msg, strlen(msg))) {
        ctx_->log_->debug("message update failed ...");
        return nullptr;
    }

    /* get signature length */
    signLen = new size_t;
    if(1 != EVP_DigestSignFinal(mdCtx, nullptr, signLen)) {
        ctx_->log_->debug("get signature length failed ...");
        return nullptr;
    }
    ctx_->log_->info("signature length is: ", (int)(*signLen));
    /* allocate memory */
    if(!(signature = static_cast<unsigned char*>(OPENSSL_malloc(sizeof(unsigned char) * (*signLen))))) {
        ctx_->log_->debug("allcate memory failed ...");
        return nullptr;
    }

    /* generate signature */
    if(1 != EVP_DigestSignFinal(mdCtx, signature, signLen)) {
        ctx_->log_->debug("generate signature failed ...");
        return nullptr;
    }
    ctx_->log_->signprint("The signature is:", signature, int(*signLen));
    ctx_->log_->info("generate signature successfully");

    // OPENSSL_free(*signature);
    // delete signLen;
    return signature;
}

void gmssl::clean()
{
    if(signature) OPENSSL_free(signature);
    if(mdCtx) EVP_MD_CTX_destroy(mdCtx);
    delete signLen;
}

int gmssl::verify_message(char* msg) {
    if(1 != EVP_DigestVerifyInit(mdCtx, nullptr, EVP_sm3(), nullptr, pKey)) {
        ctx_->log_->debug("digest verify init failed ...");
        return 0;
    }

    if(1 != EVP_DigestVerifyUpdate(mdCtx, msg, strlen(msg))) {
       ctx_->log_->debug("digest verify update failed ...");
       return 0;
    }

    if(1 == EVP_DigestVerifyFinal(mdCtx, signature, *signLen)) {
	    ctx_->log_->info("verify message successfully ...");
        return 1;
    } else {
	    ctx_->log_->info("verify message failed ...");
        return 0;
    }
}
