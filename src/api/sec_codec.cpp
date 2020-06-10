#include <iostream>
#include "sec_codec.hpp"

char* sec_encode(char* raw) {
    SecuredMessage_t* spdu = new SecuredMessage_t;
    if (NULL == spdu) {
        std::cout << "error allocate spdu" << std::endl;
    } else {
        std::cout << "success allocate spdu" << std::endl;
    }
    int rawSize = strlen(raw);
    std::cout << "raw data size is: " << rawSize << std::endl;

    spdu->version = 2;
    spdu->payload.present = Payload_PR_unSecuredData;
    
    OCTET_STRING_t* temp = NULL;
    temp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, raw, rawSize);
    spdu->payload.choice.unSecuredData = *temp;

    asn_enc_rval_t ec;

    // ASN.1 encoding of the SPDU message
    size_t size = sizeof(SecuredMessage_t);
    char* result = new char[size];
    memset(result, 0, size);
    std::cout << "size: " << size << std::endl;

    ec = uper_encode_to_buffer(&asn_DEF_SecuredMessage, spdu, result, size);
    std::cout << "Run hear 999" << std::endl;
    // free(spdu);
    delete spdu;
    if (ec.encoded == -1) {
        return nullptr;
    }
    return result;
}

int sec_decode(spud_t* spdu, char* raw, size_t raw_length) {
    SecuredMessage_t* spdu_s = new SecuredMessage_t;
    asn_dec_rval_t de;
    de = uper_decode(0, &asn_DEF_SecuredMessage, (void **)(&spdu_s), raw, raw_length, 0, 0);
    if (de.code != RC_OK) {
        std::cout << "Run hear 10" << std::endl;
        return -1;
    }
    else {
        spdu->version = spdu_s->version;
        memcpy(spdu->payload, spdu_s->payload.choice.unSecuredData.buf, spdu_s->payload.choice.unSecuredData.size);
    }
    delete spdu_s;

    return 1;
}