#include "sha256.h"
#include "sysendian.h"
#include "crypto_scrypt.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

#define ENCBLOCK 65536

static int
Log(uint64_t N) {
    static const uint64_t b[] = {0xAAAAAAAA, 0xCCCCCCCC, 0xF0F0F0F0, 0xFF00FF00, 0xFFFF0000, 0xFFFFFFFF00000000};
    register unsigned int r = (N & b[0]) != 0;
    int i;
    for (i = 5; i > 0; i--) {
      r |= ((N & b[i]) != 0) << i;
    }

    return r;
}

static int
getsalt(uint8_t salt[32])
{
	int fd;
	ssize_t lenread;
	uint8_t * buf = salt;
	size_t buflen = 32;

	/* Open /dev/urandom. */
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		goto err0;

	/* Read bytes until we have filled the buffer. */
	while (buflen > 0) {
		if ((lenread = read(fd, buf, buflen)) == -1)
			goto err1;

		/* The random device should never EOF. */
		if (lenread == 0)
			goto err1;

		/* We're partly done. */
		buf += lenread;
		buflen -= lenread;
	}

	/* Close the device. */
	while (close(fd) == -1) {
		if (errno != EINTR)
			goto err0;
	}

	/* Success! */
	return (0);

err1:
	close(fd);
err0:
	/* Failure! */
	return (4);
}

int HashPassword(const uint8_t* passwd, int N, uint32_t r, uint32_t p, uint8_t header[96]) {
    uint8_t salt[32];
    uint8_t dk[64];
    uint8_t hbuf[32];
    SHA256_CTX ctx;
    HMAC_SHA256_CTX hctx;
    uint8_t * key_hmac = &dk[32];
    int rc;

    /* Get Some Salt */
    if ((rc = getsalt(salt)) != 0)
        return (rc); 

    /* Generate the derived keys. */
    if (crypto_scrypt(passwd, (size_t)strlen((char *)passwd), salt, 32, N, r, p, dk, 64))
        return (3);

    /* Construct the file header. */
    memcpy(header, "scrypt", 6); //Sticking with Colin Percival's format of putting scrypt at the beginning
    header[6] = 0;
    header[7] = Log(N);
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

int VerifyHash(const uint8_t header[96], const uint8_t* passwd) {
    uint8_t dk[64];
    uint8_t salt[32];
    uint8_t hbuf[32];
    int N;
    uint32_t r;
    uint32_t p; 
    uint8_t * key_hmac = &dk[32];
    HMAC_SHA256_CTX hctx;
    SHA256_CTX ctx;

    /* Parse N, r, p, salt. */
    N = (uint64_t)1 << header[7];

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
    if (crypto_scrypt(passwd, (size_t)strlen((char *)passwd), salt, 32, N, r, p, dk, 64))
        return (3);

    /* Check header signature (i.e., verify password). */
    HMAC_SHA256_Init(&hctx, key_hmac, 32);
    HMAC_SHA256_Update(&hctx, header, 64);
    HMAC_SHA256_Final(hbuf, &hctx);
    if (memcmp(hbuf, &header[64], 32))
        return (11);        

    return (0); //Success
}
