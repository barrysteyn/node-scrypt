#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "pickparams.h"
}

using namespace v8;

//Synchronous access to scrypt params
NAN_METHOD(paramsSync) {
  NanScope();

	//
  // Variable Declaration
	//
  int logN = 0;
  uint32_t r = 0;
  uint32_t p = 0;

	//
  // Arguments from JavaScript
  //
	const double maxtime = args[0]->NumberValue();
  const size_t maxmem = args[2]->Uint32Value();
  const double maxmemfrac = args[1]->NumberValue();

	//
  // Scrypt: calculate input parameters
  //
	const int result = pickparams(&logN, &r, &p, maxtime, maxmem, maxmemfrac);

	//
  // Error handling
  //
	if (result) {
		NanThrowError(NodeScrypt::ScryptError(result));
  }

	//
  // Return values in JSON object
  //
	Local <Object> obj = NanNew<Object>();
  obj->Set(NanNew<String>("N"), NanNew<Integer>(logN));
	obj->Set(NanNew<String>("r"), NanNew<Integer>(r));
	obj->Set(NanNew<String>("p"), NanNew<Integer>(p));

  NanReturnValue(obj);
}
