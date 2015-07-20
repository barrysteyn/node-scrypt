#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

//
// Scrypt is a C library and there needs c linkings
//
extern "C" {
	#include "hash.h"
}

using namespace v8;

//
// Synchronous Scrypt params
//
NAN_METHOD(hashSync) {
  NanScope();

	//
  // Arguments from JavaScript
  //
	const uint8_t* key_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]));
  const size_t key_size = node::Buffer::Length(args[0]);
	const Scrypt::Params params = args[1]->ToObject();
	const size_t hash_size = args[2]->Uint32Value();
	const uint8_t* salt_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(args[3]));
	const size_t salt_size = node::Buffer::Length(args[3]);

  //
	// Variable Declaration
	//
	Local<Value> hash_result = NanNewBufferHandle(hash_size);
	uint8_t* hash_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(hash_result));

	//
  // Scrypt key derivation function
	//
	const int result = ScryptHashFunction(key_ptr, key_size, salt_ptr, salt_size, params.N, params.r, params.p, hash_ptr, hash_size);

	//
  // Error handling
  //
	if (result) {
		NanThrowError(Scrypt::ScryptError(result));
  }

	NanReturnValue(hash_result);
}
