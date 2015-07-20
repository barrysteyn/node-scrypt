#include "scrypt_async.h"

// Async class
class ScryptKDFVerifyAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptKDFVerifyAsyncWorker(NanCallback* callback, _NAN_METHOD_ARGS) :
      ScryptAsyncWorker(callback),
      kdf_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]))),
      key_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[1]))),
      key_size(node::Buffer::Length(args[1]))
    {
      ScryptPeristentObject = NanNew<v8::Object>();
      ScryptPeristentObject->Set(NanNew<v8::String>("KDFBuffer"), args[0]);
      ScryptPeristentObject->Set(NanNew<v8::String>("KeyBuffer"), args[1]);
      SaveToPersistent("ScryptPeristentObject", ScryptPeristentObject);
    };

    void Execute();
    void HandleOKCallback();

  private:
    const uint8_t* kdf_ptr;
    const uint8_t* key_ptr;
    const size_t key_size;
    bool match;
};
