#include <memory>
#include <cstring>
#include "SecuredMessage.h"
#include "context.hpp"
#include "api/sec_codec.hpp"

int main() {
    auto ctx_ = std::make_shared<context>();
    ctx_->log_->info("text log and context class ...");

    char str[] ={0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

    char* re = sec_encode(str);
    if(nullptr == re) {
        ctx_->log_->debug("error encode");
    } else {
        ctx_->log_->debug("success encode");
    }
    ctx_->log_->info("encode data's size is: ", std::strlen(re));
    size_t re_length = sizeof(SecuredMessage_t);
    spud_t* spdu = static_cast<spud_t*>((calloc(1,sizeof(spud_t))));
    int su = sec_decode(spdu, re, re_length);
    delete re;
    ctx_->log_->info("su is: ", su);
    ctx_->log_->info("spdu version is: ", spdu->version);
    ctx_->log_->info("spdu payload[0] is: ", spdu->payload[0]);
    ctx_->log_->info("spdu payload[1] is: ", spdu->payload[1]);
    return 0;
}
