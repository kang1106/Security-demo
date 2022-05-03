#include "aes128_gcm.hpp"
#include <vsomeip/vsomeip.hpp>
#include <glog/logging.h>

// key configuration
uint8_t key[16] = {0x0, 0x1, 0x2, 0x3,
                   0x4, 0x5, 0x6, 0x7,
                   0x8, 0x9, 0x0, 0x1,
                   0x2, 0x3, 0x4, 0x5};

// iv configration
uint8_t iv[12] = {0x0, 0x1, 0x2, 0x3,
                  0x4, 0x5, 0x6, 0x7,
                  0x8, 0x9, 0x0, 0x1};

uint32_t iv_len = 12;
uint32_t add_len = 4;
uint32_t tag_len = 16;

int sompeip_set_encrypt_payload(std::shared_ptr<vsomeip::message> someip_message,
                                std::shared_ptr<vsomeip::payload> pl,
                                const uint8_t* payload, uint32_t payload_length) {
    // aaditional data
    uint8_t additional[4];
    uint8_t ciphertext[128];
    uint8_t tag[16];

    /* Request id currently is different between server and client */
    // additional[0] = ((someip_message->get_request() >> 24) & 0xff);
    // additional[1] = ((someip_message->get_request() >> 16) & 0xff);
    // additional[2] = ((someip_message->get_request() >> 8) & 0xff);
    // additional[3] = ((someip_message->get_request() >> 0) & 0xff);
    additional[0] = someip_message->get_protocol_version();
    additional[1] = someip_message->get_interface_version();
    additional[2] = static_cast<uint8_t>(someip_message->get_message_type());
    additional[3] = static_cast<uint8_t>(someip_message->get_return_code());

    uint8_t plaintext[payload_length];
    memcpy(plaintext, payload, payload_length);

    uint32_t ciphertext_len = gcm_encrypt(plaintext,
                                          payload_length,
                                          additional,
                                          add_len,
                                          key,
                                          iv,
                                          iv_len,
                                          ciphertext,
                                          tag);

    /* Do something useful with the ciphertext here */
    LOG(INFO) << "Ciphertext is: ";
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    LOG(INFO) << "Tag is: ";
    BIO_dump_fp (stdout, (const char *)tag, 16);

    std::vector<vsomeip::byte_t> pl_data;
    for(int i = 0; i < ciphertext_len; ++i)
        pl_data.push_back(ciphertext[i]);

    for(int i = 0; i < tag_len; ++i)
        pl_data.push_back(tag[i]);

    pl->set_data(pl_data);
    someip_message->set_payload(pl);

    return 0;
}


int someip_get_decrypt_payload(const std::shared_ptr<vsomeip::message> someip_message,
                               uint8_t* payload, uint32_t& payload_length) {
    uint8_t additional[4];

    /* Request id currently is different between server and client */
    // additional[0] = ((someip_message->get_request() >> 24) & 0xff);
    // additional[1] = ((someip_message->get_request() >> 16) & 0xff);
    // additional[2] = ((someip_message->get_request() >> 8) & 0xff);
    // additional[3] = ((someip_message->get_request() >> 0) & 0xff);

    additional[0] = someip_message->get_protocol_version();
    additional[1] = someip_message->get_interface_version();
    additional[2] = static_cast<uint8_t>(someip_message->get_message_type());
    additional[3] = static_cast<uint8_t>(someip_message->get_return_code());

    int32_t cipher_len = someip_message->get_payload()->get_length();
    uint8_t* ciphertext = someip_message->get_payload()->get_data();
    uint8_t* tag = ciphertext + (cipher_len - tag_len);

    /* Decrypt the ciphertext */
    payload_length = gcm_decrypt(ciphertext,
                                 cipher_len - tag_len,
                                 additional,
                                 add_len,
                                 tag,
                                 key,
                                 iv,
                                 iv_len,
                                 payload);

    if (payload_length >= 0) {
        /* Add a NULL terminator. We are expecting printable text */
        payload[payload_length] = '\0';
        /* Show the decrypted text */
        LOG(INFO) << "Decrypted text is: " << payload;
    } else {
        LOG(INFO) << "Decryption failed";
    }
}
