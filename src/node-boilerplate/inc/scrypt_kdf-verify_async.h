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
      KDFObject = NanNew<v8::Object>();
      KDFObject->Set(NanNew<v8::String>("KDFBuffer"), args[0]);
      KDFObject->Set(NanNew<v8::String>("KeyBuffer"), args[1]);
      NanAssignPersistent(PersistentHandle, KDFObject);
    };

    ~ScryptKDFVerifyAsyncWorker() {
      NanDisposePersistent(PersistentHandle);
    }

    void Execute();
    void HandleOKCallback();

  private:
    v8::Persistent<v8::Object> PersistentHandle;
    v8::Local<v8::Object> KDFObject;

    const uint8_t* kdf_ptr;
    const uint8_t* key_ptr;
    const size_t key_size;
    bool match;
};
