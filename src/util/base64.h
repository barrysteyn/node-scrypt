//forward declarations

#include <stdint.h>

size_t
base64_decode(const char* b64text, uint8_t **output);

size_t
base64_encode(const uint8_t* input, size_t length, char **b64text);
