#include <nan.h>
#include <node.h>

#include "scrypt_kdf-verify_async.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "keyderivation.h"
}

using namespace v8;

void ScryptKDFVerifyAsyncWorker::Execute() {
  //
  // Scrypt KDF Verification function
	//
  result = Verify(kdf_ptr, key_ptr, key_size);
  match = (result == 0);
  result = (result == 11) ? 0 : result; // Set result to 0 if 11 so error not thrown
}

void ScryptKDFVerifyAsyncWorker::HandleOKCallback() {
  NanScope();

	Local<Value> argv[] = {
    NanNull(),
		(match) ? NanTrue() : NanFalse()
  };

  callback->Call(2, argv);
}

// Asynchronous access to scrypt params
NAN_METHOD(KDFVerify) {
  NanScope();

  //
  // Create Scrypt Async Worker
  //
  NanCallback *callback = new NanCallback(args[2].As<Function>());
  NanAsyncQueueWorker(new ScryptKDFVerifyAsyncWorker(callback, args));

  NanReturnUndefined();
}
