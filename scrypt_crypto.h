#ifndef scrypt_crypto_h
#define scrypt_crypto_h

//Forward declarations
using namespace v8;

Handle<Value> EncryptAsyncBefore(const Arguments& args);
void EncryptWork(uv_work_t* req);
void EncryptAsyncAfter(uv_work_t* req);

#endif
