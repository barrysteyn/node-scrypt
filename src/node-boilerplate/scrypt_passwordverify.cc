/*
	scrypt_passwordverify.cc 

	Copyright (C) 2013 Barry Steyn (http://doctrina.org/Scrypt-Authentication-For-Node.html)

	This source code is provided 'as-is', without any express or implied
	warranty. In no event will the author be held liable for any damages
	arising from the use of this software.

	Permission is granted to anyone to use this software for any purpose,
	including commercial applications, and to alter it and redistribute it
	freely, subject to the following restrictions:

	1. The origin of this source code must not be misrepresented; you must not
	claim that you wrote the original source code. If you use this source code
	in a product, an acknowledgment in the product documentation would be
	appreciated but is not required.

	2. Altered source versions must be plainly marked as such, and must not be
	misrepresented as being the original source code.

	3. This notice may not be removed or altered from any source distribution.

	Barry Steyn barry.steyn@gmail.com

*/

#include <v8.h>
#include <node.h>
#include <node_buffer.h>
#include <string>

//Scrypt is a C library
extern "C" {
	#include "passwordhash.h"
}

using namespace v8;
#include "scrypt_common.h"
#include "scrypt_passwordverify.h"

namespace {

struct PasswordHash {
	//Async callback function
	Persistent<Function> callback;
	Handle<Value> hash, password;

	//Custom data
	int result;
	char *hash_ptr, *password_ptr;
	size_t passwordSize;

	PasswordHash() : hash_ptr(NULL), password_ptr(NULL), passwordSize(0) { callback.Clear(); hash.Clear(); password.Clear(); }
	~PasswordHash() { 
		if (!callback.IsEmpty()) {
			Persistent<Value>(hash).Dispose();
			Persistent<Value>(password).Dispose();
		}
		callback.Dispose(); 
	}
};

int
AssignArguments(const Arguments& args, std::string& errorMessage, PasswordHash& passwordHash) {
	if (args.Length() < 2) {
		errorMessage = "both hash and password are needed";
		return ADDONARG;
	}

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errorMessage = "both hash and password are needed before the callback function";
		return ADDONARG;
	}

	for (int i=0; i < args.Length(); i++) {
		Handle<Value> currentVal = args[i];

		if (i > 1 && currentVal->IsFunction()) {
			passwordHash.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			passwordHash.hash = Persistent<Value>::New(passwordHash.hash);
			passwordHash.password = Persistent<Value>::New(passwordHash.password);
			return 0;
		}

		switch(i) {
			case 0: //Hash
				if (Internal::ProduceBuffer(currentVal, "hash", errorMessage, node::BASE64)) {
					return ADDONARG;
				}

				passwordHash.hash = currentVal;
				passwordHash.hash_ptr = node::Buffer::Data(currentVal);

				break;

			case 1: //Password
				if (Internal::ProduceBuffer(currentVal, "password", errorMessage, node::ASCII)) {
					return ADDONARG;
				}

				passwordHash.password = currentVal;
				passwordHash.password_ptr = node::Buffer::Data(currentVal);
				passwordHash.passwordSize = node::Buffer::Length(currentVal);

				break;
		}
	}

	return 0;
}

//
// Work Function: Actual password hash done here
//
void
VerifyHashWork(PasswordHash* passwordHash) {
	passwordHash->result = VerifyHash(
		(const uint8_t*)passwordHash->hash_ptr,
		(const uint8_t*)passwordHash->password_ptr, 
		passwordHash->passwordSize
	);
}

//
// Asynchronous: Wrapper to actual work function
//
void
VerifyHashAsyncWork(uv_work_t* req) {
    VerifyHashWork(static_cast<PasswordHash*>(req->data));
}

//
// Synchronous: After work function
//
void
VerifyHashSyncAfterWork(Local<Value>& result, const PasswordHash* passwordHash) {
	if (passwordHash->result && passwordHash->result != 11) {
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,passwordHash->result)
		);
	} else {
		result = Local<Value>::New(Boolean::New(passwordHash->result == 0));
	}
}

//
// Asynchonous: After work function
//
void
VerifyHashAsyncAfterWork(uv_work_t* req) {
	HandleScope scope;
	PasswordHash* passwordHash = static_cast<PasswordHash*>(req->data);

	Local<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,passwordHash->result),
		Local<Value>::New(Boolean::New(passwordHash->result == 0))
	};

	TryCatch try_catch;
	passwordHash->callback->Call(Context::GetCurrent()->Global(), 2, argv);

	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	//Clean up
	delete passwordHash;
	delete req;
}

} //end of anon namespace

//
// VerifyPasswordHash: Parses arguments and determines what type (sync or async) this function is
// This function is the "entry" point from JavaScript land
//
Handle<Value> 
VerifyPasswordHash(const Arguments& args) {
	uint8_t parseResult = 0;
	HandleScope scope;
	std::string validateMessage;
	PasswordHash* passwordHash = new PasswordHash();
	Local<Value> result;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *passwordHash))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		if (passwordHash->callback.IsEmpty()) {
			//Synchronous
			VerifyHashWork(passwordHash);
			VerifyHashSyncAfterWork(result, passwordHash);
		} else {
			//Asynchronous work request
			uv_work_t *req = new uv_work_t();
			req->data = passwordHash;
			
			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, VerifyHashAsyncWork, (uv_after_work_cb)VerifyHashAsyncAfterWork);
			assert(status == 0); 
		}
	}

	if (passwordHash->callback.IsEmpty()) {
		delete passwordHash;
	}

	return scope.Close(result);
}
