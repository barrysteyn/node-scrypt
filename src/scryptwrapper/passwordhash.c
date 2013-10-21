/* 
   passwordhash.c and passwordhash.h

   Copyright (C) 2012 Barry Steyn (http://doctrina.org/Scrypt-Authentication-For-Node.html)

   This source code is provided 'as-is', without any express or implied
   warranty. In no event will the author be held liable for any damages
   arising from the use of this software.

   Permission is granted to anyone to use this software for any purpose,
   including commercial applications, and to alter it and redistribute it
   freely, subject to the following restrictions:

   1. The origin of this source code must not be misrepresented; you must not
      claim that you wrote the original source code. If you use this source code
      in a product, an acknowledgment in the product documentation would be
      appreciated but is not required.

   2. Altered source versions must be plainly marked as such, and must not be
      misrepresented as being the original source code.

   3. This notice may not be removed or altered from any source distribution.

   Barry Steyn barry.steyn@gmail.com 

*/

#include "sha256.h"
#include "keyderivation.h"
#include "sysendian.h"

#include <string.h>

/*
 * Creates a password hash. This is the actual key derivation function
 */
int
HashPassword(const uint8_t* passwd, uint8_t header[96], size_t maxmem, double maxmemfrac, double maxtime) {
    int logN=0;
    uint64_t N=0;
    uint32_t r=0, p=0;
    uint8_t dk[64],
            salt[32],
            hbuf[32];
    uint8_t * key_hmac = &dk[32];
    SHA256_CTX ctx;
    HMAC_SHA256_CTX hctx;
    int rc;

    /* Calculate logN, r, p */
    if ((rc = pickparams(maxmem, maxmemfrac, maxtime, &logN, &r, &p) != 0))
        return (rc);

    
    /* Get Some Salt */
    if ((rc = getsalt(salt, 32)) != 0)
        return (rc); 

    /* Generate the derived keys. */
    N = (uint64_t) 1 << logN;
    if (KeyDerivationFunction(passwd, (size_t)strlen((char *)passwd), salt, 32, N, r, p, dk, 64))
        return (3);

    /* Construct the file header. */
    memcpy(header, "scrypt", 6); //Sticking with Colin Percival's format of putting scrypt at the beginning
    header[6] = 0;
    header[7] = logN;
    be32enc(&header[8], r);
    be32enc(&header[12], p);
    memcpy(&header[16], salt, 32);

    /* Add header checksum. */
    SHA256_Init(&ctx);
    scrypt_SHA256_Update(&ctx, header, 48);
    scrypt_SHA256_Final(hbuf, &ctx);
    memcpy(&header[48], hbuf, 16);

    /* Add header signature (used for verifying password). */
    HMAC_SHA256_Init(&hctx, key_hmac, 32);
    HMAC_SHA256_Update(&hctx, header, 64);
    HMAC_SHA256_Final(hbuf, &hctx);
    memcpy(&header[64], hbuf, 32);

    return 0; //success
}

/*
 * Verifies password hash (also ensures hash integrity at same time)
 */
int
VerifyHash(const uint8_t header[96], const uint8_t* passwd) {
    int N=0;
    uint32_t r=0, p=0; 
    uint8_t dk[64],
            salt[32],
            hbuf[32];
    uint8_t * key_hmac = &dk[32];
    HMAC_SHA256_CTX hctx;
    SHA256_CTX ctx;

    /* Parse N, r, p, salt. */
    N = (uint64_t)1 << header[7]; //Remember, header[7] is actually LogN
    r = be32dec(&header[8]);
    p = be32dec(&header[12]);
    memcpy(salt, &header[16], 32);

    /* Verify header checksum. */
    SHA256_Init(&ctx);
    scrypt_SHA256_Update(&ctx, header, 48);
    scrypt_SHA256_Final(hbuf, &ctx);
    if (memcmp(&header[48], hbuf, 16))
            return (7);

    /* Compute Derived Key */
    if (KeyDerivationFunction(passwd, (size_t)strlen((char *)passwd), salt, 32, N, r, p, dk, 64))
        return (3);

    /* Check header signature (i.e., verify password). */
    HMAC_SHA256_Init(&hctx, key_hmac, 32);
    HMAC_SHA256_Update(&hctx, header, 64);
    HMAC_SHA256_Final(hbuf, &hctx);
    if (memcmp(hbuf, &header[64], 32))
        return (11);        

    return (0); //Success
}
