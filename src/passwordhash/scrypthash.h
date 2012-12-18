#ifndef _SCRYPTHASH_H_
#define _SCRYPTHASH_H_

#include <stdint.h>
#include <stdio.h>

int HashPassword(const char* passwd, uint64_t N, uint32_t r, uint32_t p, uint8_t header[96]);

#endif /* !_SCRYPTHASH_H_ */
