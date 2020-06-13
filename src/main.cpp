#include <memory>
#include <cstring>
#include "SecuredMessage.h"
#include "context.hpp"
#include "api/sec_codec.hpp"
#include "api/gmssl.hpp"

int main() {
    auto ctx_ = std::make_shared<context>();
    ctx_->log_->info("text log and context class ...");

    char str[] ="hello world, I'm yu kang";

    char* msg = sec_encode(str);
    if(nullptr == msg) {
        ctx_->log_->debug("error encode");
    } else {
        ctx_->log_->debug("success encode");
    }
    ctx_->log_->info("encode data's size is: ", std::strlen(msg));

    ctx_->log_->info("******** Test GmSSL lib starting *********");
    gmssl crypto(ctx_);
    crypto.init();
    crypto.set_pkey_type(EVP_PKEY_EC);
    crypto.generate_pkey();
    crypto.sign_message(msg);
    crypto.verify_message(msg);
    crypto.clean();
    crypto.shutdown();

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
