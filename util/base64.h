#ifndef base64_h
#define base64_h

//forward declarations
char *base64_encode(const unsigned char*, int);
unsigned char *base64_decode(const char *input, int length, int *outlen);

#endif
