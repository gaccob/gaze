#ifndef CHECKSUM_H_
#define CHECKSUM_H_

#include <stdint.h>

struct cksum_vec {
    const uint8_t* ptr;
    int len;
};

uint16_t checksum(const struct cksum_vec*, int);
uint16_t checksum_shouldbe(uint16_t, uint16_t);

uint16_t checksum2(const struct cksum_vec*, int);

#endif
