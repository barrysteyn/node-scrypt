/*
	hash.c

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
#include "pickparams.h"
#include "sysendian.h"
#include "salt.h"

#include <stdlib.h>
#include <string.h>

//
// Creates a password hash. This is the actual key derivation function
//
int
Hash(const uint8_t* passwd, size_t passwdSize, uint8_t* hash, uint32_t logN, uint32_t r, uint32_t p) {
	uint64_t N=1;
	uint8_t dk[64],
		salt[32],
		hbuf[32];
	uint8_t * key_hmac = &dk[32];
	SHA256_CTX ctx;
	HMAC_SHA256_CTX hctx;
	int rc;

	/* Get Some Salt */
	if ((rc = getsalt(salt, 32)) != 0)
		return (rc);

	/* Generate the derived keys. */
	N <<= logN;
	if (ScryptKeyDerivationFunction(passwd, passwdSize, salt, 32, N, r, p, dk, 64))
		return (3);

	/* Construct the hash. */
	memcpy(hash, "scrypt", 6); //Sticking with Colin Percival's format of putting scrypt at the beginning
	hash[6] = 0;
	hash[7] = logN;
	be32enc(&hash[8], r);
	be32enc(&hash[12], p);
	memcpy(&hash[16], salt, 32);

	/* Add hash checksum. */
	SHA256_Init(&ctx);
	scrypt_SHA256_Update(&ctx, hash, 48);
	scrypt_SHA256_Final(hbuf, &ctx);
	memcpy(&hash[48], hbuf, 16);

	/* Add hash signature (used for verifying password). */
	HMAC_SHA256_Init(&hctx, key_hmac, 32);
	HMAC_SHA256_Update(&hctx, hash, 64);
	HMAC_SHA256_Final(hbuf, &hctx);
	memcpy(&hash[64], hbuf, 32);

	return 0; //success
}

//
//  Verifies password hash (also ensures hash integrity at same time)
//
int
Verify(const uint8_t* hash, const uint8_t* passwd, size_t passwdSize) {
	uint64_t N=0;
	uint32_t r=0, p=0;
	uint8_t dk[64],
		salt[32],
		hbuf[32];
	uint8_t * key_hmac = &dk[32];
	HMAC_SHA256_CTX hctx;
	SHA256_CTX ctx;

	/* Parse N, r, p, salt. */
	N = (uint64_t)1 << hash[7]; //Remember, hash[7] is actually LogN
	r = be32dec(&hash[8]);
	p = be32dec(&hash[12]);
	memcpy(salt, &hash[16], 32);

	/* Verify hash checksum. */
	SHA256_Init(&ctx);
	scrypt_SHA256_Update(&ctx, hash, 48);
	scrypt_SHA256_Final(hbuf, &ctx);
	if (memcmp(&hash[48], hbuf, 16))
		return (7);

	/* Compute Derived Key */
	if (ScryptKeyDerivationFunction(passwd, passwdSize, salt, 32, N, r, p, dk, 64))
		return (3);

	/* Check hash signature (i.e., verify password). */
	HMAC_SHA256_Init(&hctx, key_hmac, 32);
	HMAC_SHA256_Update(&hctx, hash, 64);
	HMAC_SHA256_Final(hbuf, &hctx);
	if (memcmp(hbuf, &hash[64], 32))
		return (11);

	return (0); //Success
}
