#ifndef scrypt_crypto_h
#define scrypt_crypto_h

//Forward declarations
using namespace v8;

Handle<Value> EncryptAsyncBefore(const Arguments& args);
void EncryptWork(uv_work_t* req);
void EncryptAsyncAfter(uv_work_t* req);

Handle<Value> DecryptAsyncBefore(const Arguments& args);
void DecryptWork(uv_work_t* req);
void DecryptAsyncAfter(uv_work_t* req);
#endif
