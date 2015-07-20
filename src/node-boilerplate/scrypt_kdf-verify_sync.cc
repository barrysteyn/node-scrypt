#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
	#include "keyderivation.h"
}

using namespace v8;

//Synchronous access to scrypt params
NAN_METHOD(kdfVerifySync) {
  NanScope();

  //
	// Variable Declaration
	//
  const uint8_t* kdf_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]));
  const uint8_t* key_ptr = reinterpret_cast<uint8_t*>(node::Buffer::Data(args[1]));
  const size_t key_size = node::Buffer::Length(args[1]);

	//
  // Scrypt KDF Verification
	//
  const int result = Verify(kdf_ptr, key_ptr, key_size);

	//
  // Return result (or error)
  //
	if (result && result != 11) { // 11 is the "error" code for an incorrect match
		NanThrowError(Scrypt::ScryptError(result));
  }

	NanReturnValue((!result) ? NanTrue() : NanFalse());
}
