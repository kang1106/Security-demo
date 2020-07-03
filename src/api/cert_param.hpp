#ifndef CERT_PARAM_HPP_
#define CERT_PARAM_HPP_

#include "openssl/evp.h"
#include "context.hpp"
#include <cstring>
#include <iostream>

class context;

template <class type>  // char and unsigned char
// class char_st {
//   public:
//     type* str_;
//     size_t len_;

//     explicit char_st() :
//         str_(nullptr),
//         len_(0) {}
//     void set_string(type* str, size_t len) {
//         str_ = new type[len];
//         strcpy(str_, str);
//     }
//     ~char_st() {
//         delete [] str_;
//         str_ = nullptr;
//     }
// };

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
    long version_;

  public:
    // char_st<char> serialNumber;
    explicit certParam() :
        version_(0) {}
        // pubKey_() {}

    void set_version(long version) {
        version_ = version;
    }
    long get_version() {
        return version_;
    }

    // void set_serial_number(const char* sn, size_t len);
    // std::string get_serial_number();

    class pubKey {
      private:
        int type_;
        // char key_x[32];
        // char key_y[32];
        // char key_z[1];
        unsigned char* key_;
        size_t keyLen_;
        int eccCurve_;
        enum pointType {
          point_compress   = 2,
          point_uncompress = 4,
          point_hybrid     = 6,
          unknow           = 8,
        };
        pointType pointType_;

      public:
        explicit pubKey() :
          type_(0),
          key_(nullptr),
          keyLen_(0),
          eccCurve_(0) {}
        
        ~pubKey();

        // void set_pubKey_type(int type);
        int get_type() {
            return type_;
        }
        void set_type(int type) {
          type_ = type;
        }
        void set_key(const unsigned char* key, size_t keyLen);
        size_t get_length() {
            return keyLen_;
        }
        void get_key(unsigned char* key);
        unsigned char* get_key() {
          return key_;
        }
        void set_curve(int curve) {
            eccCurve_ = curve;
        }
        int get_curve() {
            return eccCurve_;
        }
        void set_pointType(int type);
        int get_pointType() {
            return int(pointType_);
        }
    };
    pubKey pubKey_;
};

#endif // CERT_PARAM_HPP_
