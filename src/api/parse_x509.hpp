#ifndef PARSE_X509_HPP_
#define PARSE_X509_HPP_

#include "context.hpp"
#include "openssl/pem.h"
#include "openssl/bio.h"
#include  "openssl/x509.h"
#include "openssl/ossl_typ.h"
#include "api/cert_param.hpp"
#include "openssl/evp.h"

#define  SM2SIGNWITHSM3   "1.2.156.10197.1.501"
#define  sm2p256v1        1121

class contex;
// class certParam;

namespace GmSSL {

class certificate {
  public:
    explicit certificate(std::shared_ptr<context> ctx) :
        ctx_(ctx),
        certParam_() {}

    ~certificate();

    void parse_x509(const char* filename);

    void get_certificate_version();

    void get_certificate_sn();

    void get_certificate_pubKey();

  private:
    std::shared_ptr<context> ctx_;

    X509* cert;

    // struct certObject certObject;

    certParam certParam_;

};

} // GmSSL

#endif // PARSE_X509_HPP_
