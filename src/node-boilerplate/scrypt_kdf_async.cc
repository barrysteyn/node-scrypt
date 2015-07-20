#include <nan.h>
#include <node.h>

#include "scrypt_kdf_async.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "keyderivation.h"
}

using namespace v8;

void ScryptKDFAsyncWorker::Execute() {
  //
  // Scrypt key derivation function
	//
  result = KDF(key_ptr, key_size, KDFResult_ptr, params.N, params.r, params.p);
}

void ScryptKDFAsyncWorker::HandleOKCallback() {
  NanScope();

  Local<Value> argv[] = {
    NanNull(),
		GetFromPersistent("ScryptPeristentObject")->Get(NanNew<String>("KDFResult"))
  };

  callback->Call(2, argv);
}

// Asynchronous access to scrypt params
NAN_METHOD(kdf) {
  NanScope();

  //
  // Create Scrypt Async Worker
  //
  NanCallback *callback = new NanCallback(args[2].As<Function>());
  NanAsyncQueueWorker(new ScryptKDFAsyncWorker(callback, args));

  NanReturnUndefined();
}
