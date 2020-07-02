#ifndef CERT_PARAM_HPP_
#define CERT_PARAM_HPP_

#include "openssl/evp.h"
#include "context.hpp"
#include <cstring>

class context;

template <class type>  // char and unsigned char
class char_st {
  public:
    type* str_;
    size_t len_;

    explicit char_st() :
        str_(nullptr),
        len_(0) {}
    void set_string(type* str, size_t len) {
        str_ = new type[len];
        strcpy(str_, str);
    }
    ~char_st() {
        delete [] str_;
        str_ = nullptr;
    }
};

struct certObject
{
    long version;
    std::string serialNumber;
    int pKeyType;
    int signType;
    char* pkey;
    char sigAlg[128];
    unsigned long issuerHash;
    unsigned long subjectHash;
    unsigned char certHash[25];
    unsigned int certHashLen;
};

class certParam {
  private:
    long version;

  public:
    char_st<char> serialNumber;
    explicit certParam() :
        version(0),
        serialNumber() {}
        // pubKey_() {}

    void set_version(long ver);
    long get_version();

    // void set_serial_number(const char* sn, size_t len);
    // std::string get_serial_number();

    // class pubKey {
    //   private:
    //     int type;
    //     char key_x[32];
    //     char key_y[32];
    //     char key_z[1];
    //     int eccCurve;
    //   public:
    //     explicit pubKey() :
    //       type(0),
    //       key_x(),
    //       key_y(),
    //       key_z(),
    //       eccCurve(0) {}

    //     void set_pubKey_type(int type);
    //     int get_pubKey_type();
    //     void set_pubKey_key(char* key);
    //     char* get_pubKey_key();
    //     void set_pubKey_curve(int curve);
    //     int get_pubKey_curve();
    // };
    // pubKey pubKey_;
};

#endif // CERT_PARAM_HPP_
