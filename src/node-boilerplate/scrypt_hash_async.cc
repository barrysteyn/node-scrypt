#include <nan.h>
#include <node.h>

#include "scrypt_hash_async.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "hash.h"
}

using namespace v8;

void ScryptHashAsyncWorker::Execute() {
  //
  // Scrypt KDF Verification function
	//
  result = ScryptHashFunction(key_ptr, key_size, salt_ptr, salt_size, params.N, params.r, params.p, hash_ptr, hash_size);
}

void ScryptHashAsyncWorker::HandleOKCallback() {
  NanScope();

	Local<Value> argv[] = {
    NanNull(),
		PersistentHandle->Get(NanNew<v8::String>("HashBuffer"))
  };

  callback->Call(2, argv);
}

// Asynchronous access to scrypt params
NAN_METHOD(Hash) {
  NanScope();

  //
  // Create Scrypt Async Worker
  //
  NanCallback *callback = new NanCallback(args[4].As<Function>());
  NanAsyncQueueWorker(new ScryptHashAsyncWorker(callback, args));

  NanReturnUndefined();
}
