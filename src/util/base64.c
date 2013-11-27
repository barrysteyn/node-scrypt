/* 
   base64.c and base64.h

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

   René Nyffenegger rene.nyffenegger@adp-gmbh.ch

*/

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <stdint.h>
#include <string.h> //needed for strlen function

#include "base64.h"

//Forward declaration

static size_t
calcDecodedLength(const char* b64input) { //Calculates the length of a decoded base64 string
    size_t len = strlen(b64input),
            padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
            padding = 2;
    else if (b64input[len-1] == '=') //last char is =
            padding = 1;

    return (size_t)len*0.75 - padding;
}

size_t
base64_encode(const uint8_t* input, size_t length, char **b64text) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
    BIO_write(bio, input, length);
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE); // Do not destroy bufferPtr when freeing bio memory in next line
    BIO_free_all(bio);
    //BIO_free_all(b64);

    *b64text=(*bufferPtr).data;

    return (*bufferPtr).length;
}

size_t
base64_decode(const char* b64text, uint8_t **output) {
    BIO *bio, *b64;
    size_t outputLength = 0,
           decodeLen = calcDecodedLength(b64text);

    *output = (uint8_t*)malloc(decodeLen);

    bio = BIO_new_mem_buf((void *)b64text, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
    outputLength = BIO_read(bio, *output, strlen(b64text));
    BIO_free_all(bio);
    //BIO_free_all(b64);

    return outputLength;
}
