/* 
   keyderivation.c

   Copyright (C) 2013 Barry Steyn (http://doctrina.org/Scrypt-Authentication-For-Node.html)

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

#include <sys/types.h>

#include "crypto_scrypt.h"
#include "scryptenc_cpuperf.h"
#include "memlimit.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

/*
 * Given maxmem, maxmemfrac and maxtime, this functions calculates the N,r,p variables. 
 * Values for N,r,p are machine dependent. This is copied directly from Colin Percival's srypt reference code
 */
int
pickparams(size_t maxmem, double maxmemfrac, double maxtime, int * logN, uint32_t * r, uint32_t * p) {
    //Note: logN (as opposed to N) is calculated here. This is because it is compact (it can be represented by an int)
    //      and it is easy (and quick) to convert to N by right shifting bits
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

    /* Success! */
    return (0);
}

/*
 * Obtains salt for password hash. This function is copied from Colin Percival's scrypt reference code
 */
int
getsalt(uint8_t salt[], size_t saltlen) {
	int fd;
	ssize_t lenread;
	uint8_t * buf = salt;

	/* Open /dev/urandom. */
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		goto err0;

	/* Read bytes until we have filled the buffer. */
	while (saltlen > 0) {
		if ((lenread = read(fd, buf, saltlen)) == -1)
			goto err1;

		/* The random device should never EOF. */
		if (lenread == 0)
			goto err1;

		/* We're partly done. */
		buf += lenread;
		saltlen -= lenread;
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
 * This is the actual key derivation function. 
 * It is binary safe and is exposed to this module for those that need
 * access to the underlying key derivation function of Scrypt
 */
int
KeyDerivationFunction(const uint8_t* key, size_t keylen, const uint8_t *salt, size_t saltlen, uint64_t N, uint32_t r, uint32_t p,uint8_t * buf, size_t buflen) {
    if (crypto_scrypt(key, keylen, salt, saltlen, N, r, p, buf, buflen))
        return (3);
    
    return 0; //success
}
