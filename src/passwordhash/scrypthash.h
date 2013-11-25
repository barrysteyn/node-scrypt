/* 
   scrypthash.c and scrypthash.h

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
/*
 * This source code is a derivate from the original source code
 * from the source as detailed above.
 * Modifications: Copyright (C) 2013 Tobias Hintze
 * MIT license shall apply for the modifications.
 */

#ifndef _SCRYPTHASH_H_
#define _SCRYPTHASH_H_

#include <stdint.h>
#include <stdio.h>

int HashPassword(const uint8_t*, uint8_t header[96], size_t, double, double, uint8_t dkout[64]);
int VerifyHash(const uint8_t header[96], const uint8_t*, uint8_t dkout[64]);

#endif /* !_SCRYPTHASH_H_ */
