#include <nan.h>
#include <node.h>

#include "common.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "keyderivation.h"
}

using namespace v8;

//Synchronous access to scrypt params
NAN_METHOD(KDFSync) {
  NanScope();

  /* Variable Declaration */
  int result;
  uint8_t* kdf = NULL;

  // Arguments from JavaScript
  const uint8_t* key_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]));
  const size_t keySize = node::Buffer::Length(args[0]);
  const uint32_t N = args[1]->ToObject()->Get(NanNew<String>("N"))->ToInteger()->Value();
  const uint32_t r = args[1]->ToObject()->Get(NanNew<String>("r"))->ToInteger()->Value();
  const uint32_t p = args[1]->ToObject()->Get(NanNew<String>("p"))->ToInteger()->Value();

  // Scrypt: calculate input parameters
  result = KDF(key_ptr, keySize, kdf, N, r, p);

  // There is an error
  if (result) {
		NanThrowError(Scrypt::ScryptError(result));
  }

  // Return values in JSON object
  //Handle<Value> kdfResult = BUFFER_ENCODED(kdf, Nan::BUFFER);
  Handle<Value> kdfResult = NanNew(kdf);

  NanReturnValue(kdfResult);
}
