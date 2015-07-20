#include <nan.h>
#include <node.h>

#include "scrypt_params_async.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "pickparams.h"
}

using namespace v8;

void ScryptParamsAsyncWorker::Execute() {
  // Scrypt: calculate input parameters
  result = pickparams(&logN, &r, &p, maxtime, maxmem, maxmemfrac);
}

void ScryptParamsAsyncWorker::HandleOKCallback() {
  NanScope();

  // Returned params in JSON object
  Local <Object> obj = NanNew<Object>();
  obj->Set(NanNew<String>("N"), NanNew<Integer>(logN));
	obj->Set(NanNew<String>("r"), NanNew<Integer>(r));
	obj->Set(NanNew<String>("p"), NanNew<Integer>(p));

  Local<Value> argv[] = {
    NanNull(),
    obj
  };

  callback->Call(2, argv);
}

// Asynchronous access to scrypt params
NAN_METHOD(params) {
  NanScope();

	//
  // Create Scrypt Async Worker
  //
  NanCallback *callback = new NanCallback(args[3].As<Function>());
  NanAsyncQueueWorker(new ScryptParamsAsyncWorker(callback, args));

  NanReturnUndefined();
}
