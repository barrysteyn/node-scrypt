#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

//
// Scrypt is a C library and there needs c linkings
//
extern "C" {
	#include "keyderivation.h"
}

using namespace v8;

//
// Synchronous Scrypt params
//
NAN_METHOD(KDFSync) {
  NanScope();

  //
	// Variable Declaration
	//
	Local<Value> kdfResult = NanNewBufferHandle(96);

	//
  // Arguments from JavaScript
  //
	const uint8_t* key_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0])); //assume args[0] is a buffer
  const size_t keySize = node::Buffer::Length(args[0]);
	const Scrypt::Params params = args[1]->ToObject();

	//
  // Scrypt key derivation function
	//
  const int result = KDF(key_ptr, keySize, reinterpret_cast<uint8_t*>(node::Buffer::Data(kdfResult)), params.N, params.r, params.p);

	//
  // Error handling
  //
	if (result) {
		NanThrowError(Scrypt::ScryptError(result));
  }

	NanReturnValue(kdfResult);
}
