#include "scrypt_async.h"

// Async class
class ScryptHashAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptHashAsyncWorker(NanCallback* callback, _NAN_METHOD_ARGS) :
      ScryptAsyncWorker(callback),
      key_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]))),
      key_size(node::Buffer::Length(args[0])),
      params(args[1]->ToObject()),
    	hash_size(args[2]->Uint32Value()),
    	salt_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[3]))),
    	salt_size(node::Buffer::Length(args[3]))
    {
      ScryptPeristentObject = NanNew<v8::Object>();
      ScryptPeristentObject->Set(NanNew<v8::String>("KeyBuffer"), args[0]);
      ScryptPeristentObject->Set(NanNew<v8::String>("HashBuffer"), NanNewBufferHandle(hash_size));
      ScryptPeristentObject->Set(NanNew<v8::String>("SaltBuffer"), args[3]);
      SaveToPersistent("ScryptPeristentObject", ScryptPeristentObject);

      hash_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(ScryptPeristentObject->Get(NanNew<v8::String>("HashBuffer"))));
    };

    void Execute();
    void HandleOKCallback();

  private:
    const uint8_t* key_ptr;
    const size_t key_size;
  	const Scrypt::Params params;
  	const size_t hash_size;
  	const uint8_t* salt_ptr;
  	const size_t salt_size;
    uint8_t* hash_ptr;
};
