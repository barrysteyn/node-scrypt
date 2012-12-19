#ifndef _SCRYPTHASH_H_
#define _SCRYPTHASH_H_

#include <stdint.h>
#include <stdio.h>

int HashPassword(const uint8_t*, uint8_t header[96], size_t, double, double);
int VerifyHash(const uint8_t header[96], const uint8_t*);

#endif /* !_SCRYPTHASH_H_ */
