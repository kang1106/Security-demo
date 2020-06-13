#include <memory>
#include <cstring>
#include "SecuredMessage.h"
#include "context.hpp"
#include "api/sec_codec.hpp"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/crypto.h>

int main() {
    auto ctx_ = std::make_shared<context>();
    ctx_->log_->info("text log and context class ...");

    char str[] ={0x11, 0x22};

    char* msg = sec_encode(str);
    if(nullptr == msg) {
        ctx_->log_->debug("error encode");
    } else {
        ctx_->log_->debug("success encode");
    }
    ctx_->log_->info("encode data's size is: ", std::strlen(msg));

    ctx_->log_->info("******** Test GmSSL lib starting *********");

    // init 
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);

    ctx_->log_->info("run hear 111");
    /* creat context for parameter */
    auto type = EVP_PKEY_EC;
    auto pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if(!pctx) {
        ctx_->log_->debug("failed 111");
    }

    if(!EVP_PKEY_paramgen_init(pctx)) {
        ctx_->log_->debug("failed 222");
    }

    ctx_->log_->info("run hear 222");
    /* 根据类型设置paramgen参数 */
    switch(type)
    {
        case EVP_PKEY_EC:
	        /* 使用在obj_mac.h中定义的NID_sm2p256v1命名曲线 */
	        if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_sm2p256v1)) {
                ctx_->log_->debug("failed 333");
            }
            ctx_->log_->info("run hear 333");
	        break;

        case EVP_PKEY_DSA:
	        /* 设置位长度为2048*/
	        if(!EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, 2048)) {
                ctx_->log_->debug("failed 444");
            }
	            break;

        case EVP_PKEY_DH:
	        /* 设置一个2048位的素数 */
	       if(!EVP_PKEY_CTX_set_dh_paramgen_prime_len(pctx, 2048)) {
               ctx_->log_->debug("failed 555");
           }
    }

    /* 生成参数 */
    EVP_PKEY* params = NULL;
    if (!EVP_PKEY_paramgen(pctx, &params)) {
        ctx_->log_->debug("failed 666");
    }
    ctx_->log_->info("run hear 444");
    // EVP_PKEY_CTX kctx;
    if(params != NULL) {
	    if(!(pctx = EVP_PKEY_CTX_new(params, NULL))) {
            ctx_->log_->debug("failed 777");
        }
        ctx_->log_->info("run hear 555");
    } else {
	/* 创建用于生成密钥的上下文 */
	    if(!(pctx = EVP_PKEY_CTX_new_id(type, NULL))) {
            ctx_->log_->debug("failed 888");
        }
    }

    if(!EVP_PKEY_keygen_init(pctx)) {
        ctx_->log_->debug("failed 999");
    }
    ctx_->log_->info("run hear 666");

    /* RSA密钥是在生成密钥期间设置密钥长度，而不是在生成参数的时候! */
    if(type == EVP_PKEY_RSA) {
	    if(!EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048)) {
            ctx_->log_->debug("failed 000");
        }
    }
    ctx_->log_->info("run hear 777");
    /* 生成密钥 */
    EVP_PKEY* key = NULL;
    if (!EVP_PKEY_keygen(pctx, &key)) {
        ctx_->log_->debug("failed 111");
    }
    ctx_->log_->info("run hear 888");
    EVP_MD_CTX *mdctx = NULL;
    int ret = 0;
    
    unsigned char* sig = NULL;
    
    /* 创建消息摘要上下文 */
    if(!(mdctx = EVP_MD_CTX_create())) {
        ctx_->log_->debug("failed 222");
    }
    
    ctx_->log_->info("run hear 999");
    /* 初始化DigestSign操作 - 在这个例子中，选择SHA-256作为消息摘要函数 */
    if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) {
        ctx_->log_->debug("failed 333");
    }
    ctx_->log_->info("run hear 111");
    /* 调用更新消息 */
    if(1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) {
        ctx_->log_->debug("failed 444");
    }
    ctx_->log_->info("run hear 222");
    /* 完成DigestSign操作 */
    /* 首先调用EVP_DigestSignFinal，采用一个为NULL的sig参数来获得签名的长度。返回的长度保存在slen变量中 */
    size_t* slen = new size_t;
    if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) {
        ctx_->log_->debug("failed 555");
    }
    ctx_->log_->info("run hear 333");
    /* 根据slen的大小为签名分配内存 */
    if(!(sig = static_cast<unsigned char*>(OPENSSL_malloc(sizeof(unsigned char) * (*slen))))) {
        ctx_->log_->debug("failed 666");
    }
    ctx_->log_->info("run hear 444");
    /* 获得签名 */
    if(1 != EVP_DigestSignFinal(mdctx, sig, slen)) {
        ctx_->log_->debug("failed 777");
    }
    printf("signature length is: %d\n", *slen);
    printf("signature is: %s\n", sig);
    printf("size is: %d\n", sizeof(sig));
    // char* pData = "hello world";
    // char buf[3];
    // std::string result = "";
    // for (int i = 0; i < int(*slen); i++)
    // {
    //     sprintf(buf, "%02x", sig[i]);
    //     result += buf;
    // }
    // printf("%s\n", result);
    ctx_->log_->info("run hear 555");
    /* 成功 */
    ret = 1;
    

    /* 用公钥初始化`密钥` */
    if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, key)) {
        ctx_->log_->debug("failed 888");
    }


   /* 用公钥初始化`密钥` */
   if(1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg))) {
       ctx_->log_->debug("failed 999");
   }

   if(1 == EVP_DigestVerifyFinal(mdctx, sig, *slen))
   {
	ctx_->log_->info("verify successfully");
   }
   else
   {
	ctx_->log_->info("verify failed");
   }

    
    /* 清理 */
    if(sig && !ret) OPENSSL_free(sig);
    if(mdctx) EVP_MD_CTX_destroy(mdctx);

    delete slen;
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    ctx_->log_->info("******** Test GmSSL lib end ***********");

    size_t re_length = sizeof(SecuredMessage_t);
    spud_t* spdu = static_cast<spud_t*>((calloc(1,sizeof(spud_t))));
    int su = sec_decode(spdu, msg, re_length);
    delete msg;
    ctx_->log_->info("su is: ", su);
    ctx_->log_->info("spdu version is: ", spdu->version);
    ctx_->log_->info("spdu payload[0] is: ", spdu->payload[0]);
    ctx_->log_->info("spdu payload[1] is: ", spdu->payload[1]);
    return 0;
}
