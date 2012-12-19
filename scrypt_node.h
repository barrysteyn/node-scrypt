#ifndef scrypt_crypto_h
#define scrypt_crypto_h

//Forward declarations
using namespace v8;

Handle<Value> HashAsyncBefore(const Arguments& args);
void HashWork(uv_work_t* req);
void HashAsyncAfter(uv_work_t* req);

Handle<Value> VerifyAsyncBefore(const Arguments& args);
void VerifyWork(uv_work_t* req);
void VerifyAsyncAfter(uv_work_t* req);

Handle<Value> EncryptAsyncBefore(const Arguments& args);
void EncryptWork(uv_work_t* req);
void EncryptAsyncAfter(uv_work_t* req);

Handle<Value> DecryptAsyncBefore(const Arguments& args);
void DecryptWork(uv_work_t* req);
void DecryptAsyncAfter(uv_work_t* req);
#endif
