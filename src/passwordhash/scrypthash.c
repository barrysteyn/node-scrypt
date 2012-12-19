#include "sha256.h"
#include "sysendian.h"
#include "crypto_scrypt.h"
#include "memlimit.h"
#include "scryptenc_cpuperf.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <openssl/aes.h>

/*
 * Given maxmem, maxmemfrac and maxtime, this functions calculates the N,r,p variables. 
 * Values for N,r,p are machine dependent. This is copied directly from Colin Percival's srypt reference code
 */
static int
pickparams(size_t maxmem, double maxmemfrac, double maxtime, int * logN, uint32_t * r, uint32_t * p) {
    size_t memlimit;
    double opps;
    double opslimit;
    double maxN, maxrp;
    int rc;

    /* Figure out how much memory to use. */
    if (memtouse(maxmem, maxmemfrac, &memlimit))
        return (1);

    /* Figure out how fast the CPU is. */
    if ((rc = scryptenc_cpuperf(&opps)) != 0)
        return (rc);
    opslimit = opps * maxtime;

    /* Allow a minimum of 2^15 salsa20/8 cores. */
    if (opslimit < 32768)
        opslimit = 32768;

    /* Fix r = 8 for now. */
    *r = 8;

    /*
    * The memory limit requires that 128Nr <= memlimit, while the CPU
    * limit requires that 4Nrp <= opslimit. If opslimit < memlimit/32,
    * opslimit imposes the stronger limit on N.
    */
#ifdef DEBUG
    fprintf(stderr, "Requiring 128Nr <= %zu, 4Nrp <= %f\n",
    memlimit, opslimit);
#endif
    if (opslimit < memlimit/32) {
        /* Set p = 1 and choose N based on the CPU limit. */
        *p = 1;
        maxN = opslimit / (*r * 4);
        for (*logN = 1; *logN < 63; *logN += 1) {
            if ((uint64_t)(1) << *logN > maxN / 2)
                break;
        }
    } else {
        /* Set N based on the memory limit. */
        maxN = memlimit / (*r * 128);
        for (*logN = 1; *logN < 63; *logN += 1) {
            if ((uint64_t)(1) << *logN > maxN / 2)
            break;
        }

        /* Choose p based on the CPU limit. */
        maxrp = (opslimit / 4) / ((uint64_t)(1) << *logN);
        if (maxrp > 0x3fffffff)
            maxrp = 0x3fffffff;
        *p = (uint32_t)(maxrp) / *r;
    }

#ifdef DEBUG
    fprintf(stderr, "N = %zu r = %d p = %d\n",
    (size_t)(1) << *logN, (int)(*r), (int)(*p));
#endif

    /* Success! */
    return (0);
}

/*
 * Obtains salt for password hash. This function is copied from Colin Percival's scrypt reference code
 */
static int
getsalt(uint8_t salt[32]) {
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

/*
 * Creates a password hash. This is the actual key derivation function
 */
int
HashPassword(const uint8_t* passwd, uint8_t header[96], size_t maxmem, double maxmemfrac, double maxtime) {
    int logN;
    uint64_t N;
    uint32_t r, p;
    uint8_t salt[32];
    uint8_t dk[64];
    uint8_t hbuf[32];
    SHA256_CTX ctx;
    HMAC_SHA256_CTX hctx;
    uint8_t * key_hmac = &dk[32];
    int rc;

    /* Calculate logN, r, p */
    if ((rc = pickparams(maxmem, maxmemfrac, maxtime, &logN, &r, &p) != 0))
        return (rc);

    
    /* Get Some Salt */
    if ((rc = getsalt(salt)) != 0)
        return (rc); 

    /* Generate the derived keys. */
    N = (uint64_t) 1 << logN;
    if (crypto_scrypt(passwd, (size_t)strlen((char *)passwd), salt, 32, N, r, p, dk, 64))
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
 * Verifies password hash
 */
int
VerifyHash(const uint8_t header[96], const uint8_t* passwd) {
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
