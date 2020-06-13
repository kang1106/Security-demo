#ifndef SEC_TYPE_HPP_
#define SEC_TYPR_HPP_

#include <stdint.h>

typedef struct {
    uint8_t     version;
    char       payload[100];
} spud_t;

#endif /* SEC_TYPR_HPP_ */