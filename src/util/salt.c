/*
	salt.c

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

//Documentation about OpenSSL's random number generator can be found at http://wiki.openssl.org/index.php/Random_Numbers

#include "salt.h"

#include <openssl/rand.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

//
// Obtains a source of randomness from /dev/urandom (This function is copied from Colin Percival's scrypt reference code)
//
int
getsalt(uint8_t salt[], size_t saltlen) {
#ifndef _MSC_VER
	int fd;
	ssize_t lenread;

	/* Open /dev/urandom. */
	if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
		goto err0;

	/* Read bytes until we have filled the buffer. */
	while (saltlen > 0) {
		if ((lenread = read(fd, salt, saltlen)) == -1)
			goto err1;

		/* The random device should never EOF. */
		if (lenread == 0)
			goto err1;

		/* We're partly done. */
		salt += lenread;
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
#endif
	/* Try openssl */
	if (RAND_bytes(salt, (int)saltlen) != 1) {
		/* Failure */
		return (4);
	} else {
		/* Success! */
		return (0);
	}
}
