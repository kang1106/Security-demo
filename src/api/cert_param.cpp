#include "api/cert_param.hpp"

void certParam::set_version(long ver) {
    version = ver;
};
long certParam::get_version() {
    return version;
}

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

// void certParam::pubKey::set_pubKey_key(char* key) {
    
// }