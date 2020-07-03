#include "api/cert_param.hpp"

// void certParam::set_version(long ver) {
//     version = ver;
// };
// long certParam::get_version() {
//     return version;
// }

// void certParam::set_serial_number(const char* sn, 256) {
//     strcpy((char*)serialNumber.c_str(),sn);
// };
// std::string certParam::get_serial_number() {
//     return serialNumber->;
// };

// void certParam::pubKey::set_pubKey_type(int type) {
//     pubKey::type = type;
// }

// int certParam::pubKey::get_pubKey_type() {
//     return pubKey::type;
// }

void certParam::pubKey::set_key(const unsigned char* key, size_t keyLen) {
    keyLen_ = keyLen;
    key_ = new unsigned char[keyLen_];
    // strcpy(key_, key);
    memcpy(key_, key, keyLen);
}

void certParam::pubKey::get_key(unsigned char* key) {
    // strcpy(key, key_);
    memcpy(key_, key, keyLen_);
}

certParam::pubKey::~pubKey() {
    if(keyLen_ > 0) {
        delete [] key_;
        key_ = nullptr;
    }
}

void certParam::pubKey::set_pointType(int t) {
    auto type = pointType(t);
    switch (type) {
        case point_compress:
            pointType_ = point_compress;
            break;
        case point_uncompress:
            pointType_ = point_uncompress;
            std::cout << "The point type is uncompress type z||x||y ..." << std::endl;
            break;
        case point_hybrid:
            pointType_ = point_hybrid;
        default:
            pointType_ = unknow;
            std::cout << "The point type is unkonw type ..." << std::endl;
            break;
    }
}