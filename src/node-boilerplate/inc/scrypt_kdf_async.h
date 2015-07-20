#include "scrypt_async.h"

// Async class
class ScryptKDFAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptKDFAsyncWorker(NanCallback* callback, _NAN_METHOD_ARGS) :
      ScryptAsyncWorker(callback),
      key_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]))),
      key_size(node::Buffer::Length(args[0])),
      params(args[1]->ToObject())
    {
      ScryptPeristentObject = NanNew<v8::Object>();
      ScryptPeristentObject->Set(NanNew<v8::String>("keyBuffer"), args[0]);
      ScryptPeristentObject->Set(NanNew<v8::String>("KDFResult"), NanNewBufferHandle(96));
      SaveToPersistent("ScryptPeristentObject", ScryptPeristentObject);
      KDFResult_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(ScryptPeristentObject->Get(NanNew<v8::String>("KDFResult"))));
    };

    void Execute();
    void HandleOKCallback();

  private:
    uint8_t* KDFResult_ptr;
    const uint8_t* key_ptr;
    const size_t key_size;
    const Scrypt::Params params;
};
