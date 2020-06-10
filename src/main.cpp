#include "SecuredMessage.h"

#include <asn_application.h>
#include <asn_internal.h>

typedef struct {
    uint8_t     version;
    char       payload[100];
    // uint8_t*       ver;
} spud_t;

int spduEncode(char* raw, char* str) {
    SecuredMessage_t* spdu = NULL;

    spdu = static_cast<SecuredMessage_t*>(calloc(1, sizeof(SecuredMessage_t)));
    if (NULL == spdu) {
        printf("error allocate spdu\n");
    } else {
        printf("success allocate spdu\n");
    }
    int size_str = strlen(str);
    printf("length: %d\n", size_str);

//    Uint8_t SS = 3;
//     spdu->ver = &SS; 
    spdu->version = 2;
    spdu->payload.present = Payload_PR_unSecuredData;
    
    OCTET_STRING_t* temp = NULL;
    temp = OCTET_STRING_new_fromBuf(&asn_DEF_OCTET_STRING, str, strlen(str));
    spdu->payload.choice.unSecuredData = *temp;

    asn_enc_rval_t ec;

    // ASN.1 encoding of the SPDU message
    size_t size = sizeof(SecuredMessage_t);
    printf("size: %d\n", (int)size);
    //*buffer_size = size;

    ec = uper_encode_to_buffer(&asn_DEF_SecuredMessage, spdu, raw, size);
    printf("Run hear 999\n");
    // ASN_STRUCT_FREE(asn_DEF_OCTET_STRING, temp);
    free(spdu);
    if (ec.encoded == -1) {
        return -1;
    }
    return 1;
}

// asn_dec_rval_t
// uper_decode(asn_codec_ctx_t *opt_codec_ctx, asn_TYPE_descriptor_t *td, void **sptr, const void *buffer, size_t size, int skip_bits, int unused_bits) {

int spdudecode(spud_t* spdu, char* raw, size_t raw_length) {
    SecuredMessage_t* spdu_s = static_cast<SecuredMessage_t*>(calloc(1,sizeof(SecuredMessage_t)));
    asn_dec_rval_t de;
    de = uper_decode(0, &asn_DEF_SecuredMessage, (void **)(&spdu_s), raw, raw_length, 0, 0);
    if (de.code != RC_OK) {
        printf("Run hear 10\n");
        return -1;
    }
    else {
        spdu->version = spdu_s->version;
        // spdu->ver = (uint8_t*)spdu_s ->ver;
        memcpy(spdu->payload, spdu_s->payload.choice.unSecuredData.buf, spdu_s->payload.choice.unSecuredData.size);
    }
    free(spdu_s);

    return 1;
}

int main() {
    char* re = NULL;
    // re = static_cast<SecuredMessage_t*>(calloc(1,sizeof(SecuredMessage_t)));
    re = new char[sizeof(SecuredMessage_t)];
    if (NULL == re) {
        printf("error allocate re\n");
    } else {
        printf("success allocate re\n");
    }
    char str[2];
    str[0] = 0x11;
    str[1] = 0x02;
    int tt = spduEncode(re, str);
    if(-1 == tt) {
        printf("error encode \n");
    } else {
        printf("success encode \n");
    }
    //printf("%d", *re);
    size_t re_length = sizeof(SecuredMessage_t);
    spud_t* spdu = static_cast<spud_t*>((calloc(1,sizeof(spud_t))));
    int su = spdudecode(spdu, re, re_length);

    printf("%d\n", su);
    printf("%d\n", spdu->version);
    // printf("%d\n", *(spdu->ver));
    printf("%d\n", spdu->payload[0]);
    printf("%d\n", spdu->payload[1]);
    return 0;
}