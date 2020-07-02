#include "parse_x509.hpp"
#include <cstring>

void GmSSL::certificate::parse_x509(const char* filename) {
    BIO *bp = nullptr;
    bp = BIO_new_file(filename, "r");
    cert = PEM_read_bio_X509(bp, NULL, 0, NULL);
    if (cert == nullptr) {
        printf("read certificate failed\n");
    }

    X509_print_fp(stdout, cert);

    get_certificate_version();
    // get_certificate_sn();

    // // signature algorithm through getting public key type
    // auto pKey = X509_get_pubkey(cert);
    // certObject.pKeyType = EVP_PKEY_id(pKey);
    // switch (certObject.pKeyType) {
    //     case EVP_PKEY_EC:
    //         ctx_->log_->info("public key type is: EVP_PKEY_EC");
    //         break;
    //     default:
    //         ctx_->log_->info("other public key type");
    //         break;
    // }

    // // get public key
    // auto ec_key = EVP_PKEY_get0_EC_KEY(pKey);
    // auto ec_pkey = EC_KEY_get0_public_key(ec_key);
    // auto ec_group = EC_KEY_get0_group(ec_key); 
    // auto ec_form = EC_KEY_get_conv_form(ec_key); // the point is encoded as z||x||y, where z is the octet 0x04
    // unsigned char buf[65];
    // size_t len;
    // certObject.pkey = EC_POINT_point2hex(ec_group, ec_pkey, ec_form, nullptr);
    // len = EC_POINT_point2oct(ec_group, ec_pkey, ec_form, nullptr, 0, NULL);
    // EC_POINT_point2oct(ec_group, ec_pkey, ec_form, buf, len, NULL);
    // ctx_->log_->signprint("The public key is: ", buf, len);
    // ctx_->log_->info("The public key is: ", len);
    // ctx_->log_->info("The public key is: ", certObject.pkey);
    // ctx_->log_->info("The public key is: ", strlen(certObject.pkey));
    
    // // get ECC curve
    // auto curve = EC_GROUP_get_curve_name(ec_group);
    // if (sm2p256v1 == curve) {
    //     ctx_->log_->info("The curve is: sm2p256v1");
    // }

    // // get ceritificate signature and signature algorithm
    // const ASN1_BIT_STRING* signature;
    // const X509_ALGOR* algorithm;
    // X509_get0_signature(&signature, &algorithm, cert);
    // ctx_->log_->signprint("The signature is:", signature->data, signature->length);
    // ctx_->log_->info("The signature type is: ", signature->type);
    // ctx_->log_->info("The signature length is: ", signature->length);
    // // ctx_->log_->info("The signature flags is: ", signature->flags);

    // const ASN1_OBJECT* obj;
    // int type;
    // const void* val;
    // X509_ALGOR_get0(&obj, &type, &val, algorithm);
    // ctx_->log_->info("The algorithm type is: ", type);
    // OBJ_obj2txt(certObject.sigAlg, 128, obj, 1);
    // if(!(strcmp(certObject.sigAlg, SM2SIGNWITHSM3))) {
    //     ctx_->log_->info("The signature algorithm is: sm2sign-with-sm3");
    // }

    // // get issuer name and hash
    // auto issuerName = X509_get_issuer_name(cert);
    // certObject.issuerHash = X509_issuer_name_hash(cert);
    // ctx_->log_->info("The issure hash is: ", certObject.issuerHash);

    // // get hash algorithm

    // // get subject type

    // // get subject name
    // auto subjectName = X509_get_subject_name(cert);
    // char common_Name[256];
    // X509_NAME_get_text_by_NID(subjectName, NID_commonName, common_Name, 256);
    // ctx_->log_->info("subject common name: ", common_Name);
    // certObject.subjectHash =  X509_subject_name_hash(cert);
    // ctx_->log_->info("The subject hash is: ", certObject.subjectHash);

    // // get certificate hash
    // auto temp = X509_digest(cert, EVP_sha1(), certObject.certHash, &(certObject.certHashLen));
    // if(temp){
    //     printf("success\n");
    // }
    // printf("success\n");
    // ctx_->log_->signprint("The certificate hash is:", certObject.certHash, certObject.certHashLen);

    // certObject.signType =  X509_get_signature_type(cert);
    // ctx_->log_->info("signature type is: ", certObject.signType);

    // EVP_PKEY_free(pKey);
    // EC_KEY_free(ec_key);
    X509_free(cert);
    BIO_free(bp);
}

GmSSL::certificate::~certificate () {

}

void GmSSL::certificate::get_certificate_version() {
    // certificate version
    auto version = X509_get_version(cert);
    switch(version) {
        case 0:
            ctx_->log_->info("certificate version is: V1 ...");
            break;
        case 1:
            ctx_->log_->info("certificate version is: V2 ...");
            break;
        case 2:
            ctx_->log_->info("certificate version is: V3 ...");
            break;
        default:
            ctx_->log_->info("invalid version ...");
            break;
    }
    certParam_.set_version(version);
    ctx_->log_->info("certParam version is: ", certParam_.get_version());
}

void GmSSL::certificate::get_certificate_sn() {
    // ceritificate serial number
    auto sn = X509_get_serialNumber(cert);
    auto bn = ASN1_INTEGER_to_BN(sn, nullptr);
    auto serialNumber = BN_bn2hex(bn);
    auto serialNumberLen = strlen(serialNumber);
    // auto len = BN_num_bytes(bn);
    // BN_bn2bin();
    // certParam_.set_serial_number(BN_bn2hex(bn));
    certParam_.serialNumber.set_string(serialNumber, serialNumberLen);

    OPENSSL_free(serialNumber);
    serialNumber = nullptr;
    ASN1_INTEGER_free(sn);
    BN_free(bn);
    ctx_->log_->info("ceritificate serial number is: ", certParam_.serialNumber.str_);
}
