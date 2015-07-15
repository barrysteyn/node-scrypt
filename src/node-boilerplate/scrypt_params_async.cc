#include "scrypt_params_async.h"
#include "scrypt_error.h"

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
NAN_METHOD(Params) {
  NanScope();

  //
  // Arguments From JavaScript
  //
  double maxtime = args[0]->NumberValue();
  double maxmemfrac = args[1]->NumberValue();
  size_t maxmem = args[2]->Uint32Value();
  NanCallback *callback = new NanCallback(args[3].As<Function>());

  // Call Async Worker
  NanAsyncQueueWorker(new ScryptParamsAsyncWorker(callback, maxtime, maxmemfrac, maxmem));
  NanReturnUndefined();
}
