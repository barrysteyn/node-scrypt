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
      KDFObject = NanNew<v8::Object>();
      KDFObject->Set(NanNew<v8::String>("keyBuffer"), args[0]);
      KDFObject->Set(NanNew<v8::String>("KDFResult"), NanNewBufferHandle(96));
      NanAssignPersistent(PersistentHandle, KDFObject);
      KDFResult_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(KDFObject->Get(NanNew<v8::String>("KDFResult"))));
    };

    ~ScryptKDFAsyncWorker() {
      NanDisposePersistent(PersistentHandle);
    }

    void Execute();
    void HandleOKCallback();

  private:
    v8::Persistent<v8::Object> PersistentHandle;
    v8::Local<v8::Object> KDFObject;

    uint8_t* KDFResult_ptr;
    const uint8_t* key_ptr;
    const size_t key_size;
    const Scrypt::Params params;
};
