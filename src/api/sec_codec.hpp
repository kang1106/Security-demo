#ifndef SEC_CODEC_HPP_
#define SEC_CODEC_HPP_

#include "sec_type.hpp"
#include "SecuredMessage.h"

char* sec_encode(char* raw);
int sec_decode(spud_t* spdu, char* raw, size_t raw_length);

#endif