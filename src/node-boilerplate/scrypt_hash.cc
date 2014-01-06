/*
	scrypt_hash.cc 

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

//C Linkings
extern "C" {
	#include "passwordhash.h"
}

using namespace v8;
#include "common.h"

namespace 
{

//
// Structure to hold information
//
struct HashInfo {
	//Encodings
	node::encoding keyEncoding, outputEncoding;

	//Async callback function
	Persistent<Function> callback;
	Handle<Value> password, passwordHash;

	//Custom data for scrypt
	int result;
	
	char *password_ptr, *passwordHash_ptr;
	size_t passwordSize, passwordHashSize;
	Internal::ScryptParams params;

	//Construtor / destructor   
	HashInfo(Handle<Object> config) : password_ptr(NULL), passwordHash_ptr(NULL), passwordSize(0),passwordHashSize(96) {
		keyEncoding = static_cast<node::encoding>(config->Get(v8::String::New("_keyEncoding"))->ToUint32()->Value());
		outputEncoding = static_cast<node::encoding>(config->Get(v8::String::New("_outputEncoding"))->ToUint32()->Value());		 
		callback.Clear(); 
		password.Clear();
		passwordHash.Clear();
	}
	~HashInfo() {
		if (!callback.IsEmpty()) {
			Persistent<Value>(password).Dispose();
			Persistent<Value>(passwordHash).Dispose();
		}
		callback.Dispose();
	}
};

//
// Validates and assigns arguments from JS land. Also determines if function is async or sync
//
int 
AssignArguments(const Arguments& args, std::string& errorMessage, HashInfo &hashInfo) {
	uint8_t scryptParameterParseResult = 0;	
	if (args.Length() < 2) {
		errorMessage = "wrong number of arguments - at least two arguments are needed - password and scrypt parameters JSON object";
		return ADDONARG;

	}

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errorMessage = "wrong number of arguments at least two arguments are needed before the callback function - password and scrypt parameters JSON object";
		return ADDONARG;
	}

	for (int i=0; i < args.Length(); i++) {
		Handle<Value> currentVal = args[i];
		if (i > 1 && currentVal->IsFunction()) {
			hashInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			hashInfo.password = Persistent<Value>::New(hashInfo.password);
			hashInfo.passwordHash = Persistent<Value>::New(hashInfo.passwordHash);
			return 0;
		}

		switch(i) {
			case 0: //Password
				if (Internal::ProduceBuffer(currentVal, "password", errorMessage, hashInfo.keyEncoding)) {
					return ADDONARG;
				}
				hashInfo.password = currentVal;
				hashInfo.password_ptr = node::Buffer::Data(currentVal);
				hashInfo.passwordSize = node::Buffer::Length(currentVal);

				//Create hash buffer - note that it is the same size as the password buffer
				Internal::CreateBuffer(hashInfo.passwordHash, hashInfo.passwordHashSize);
				hashInfo.passwordHash_ptr = node::Buffer::Data(hashInfo.passwordHash);
				break;

			case 1: //Scrypt parameters
				if (!currentVal->IsObject()) {
					errorMessage = "expecting scrypt parameters JSON object";
					return ADDONARG;
				}

				scryptParameterParseResult = Internal::CheckScryptParameters(currentVal->ToObject(), errorMessage);
				if (scryptParameterParseResult) {
					return scryptParameterParseResult;
				}

				hashInfo.params = currentVal->ToObject();

				break;   
		}
	}

	return 0;
}

//
// Synchronous: After work function
//
void
PasswordHashSyncAfterWork(Handle<Value> &passwordHash, const HashInfo* hashInfo) {
	if (hashInfo->result) { //There has been an error
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,hashInfo->result)
		);
	} else {
		passwordHash = BUFFER_ENCODED(hashInfo->passwordHash, hashInfo->outputEncoding);
	}
}

//
// Asynchronous: After work function
//
void 
PasswordHashAsyncAfterWork(uv_work_t *req) {
	HandleScope scope;
	HashInfo* hashInfo = static_cast<HashInfo*>(req->data);
	uint8_t argc = (hashInfo->result) ? 1 : 2;
	Handle<Value> passwordHash = BUFFER_ENCODED(hashInfo->passwordHash, hashInfo->outputEncoding);

	Handle<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,hashInfo->result),
		passwordHash
	};

	TryCatch try_catch;
	hashInfo->callback->Call(Context::GetCurrent()->Global(), argc, argv);

	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	//Cleanup
	delete hashInfo; 
	delete req;
}


//
// Work Function: Actual password hash performed here
//
void 
PasswordHashWork(HashInfo* hashInfo) {
	//perform scrypt password hash
	hashInfo->result = HashPassword(
		(const uint8_t*)hashInfo->password_ptr, hashInfo->passwordSize,
		(uint8_t*)hashInfo->passwordHash_ptr,
		hashInfo->params.N, hashInfo->params.r, hashInfo->params.p
	);
}

//
// Asynchronous: Wrapper to actual work function
//
void 
PasswordHashAsyncWork(uv_work_t* req) {
	PasswordHashWork(static_cast<HashInfo*>(req->data));	
}

} //end of unnamed namespace

//
// Hash: Parses arguments and determines what type (sync or async) this function is
// This function is the "entry" point from JavaScript land
//
Handle<Value> 
Hash(const Arguments& args) {
	uint8_t parseResult = 0;
	HandleScope scope;
	std::string validateMessage;
	HashInfo* hashInfo = new HashInfo(Local<Object>::Cast(args.Callee()->Get(String::New("config")))); 
	Handle<Value> passwordHash;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *hashInfo))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		if (hashInfo->callback.IsEmpty()) {
			//Synchronous 
			PasswordHashWork(hashInfo);
			PasswordHashSyncAfterWork(passwordHash, hashInfo);
		} else {
			//Work request 
			uv_work_t *req = new uv_work_t();
			req->data = hashInfo;

			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, PasswordHashAsyncWork, (uv_after_work_cb)PasswordHashAsyncAfterWork);
			assert(status == 0);
		}
	}

	//Clean up heap only if call is synchronous
	if (hashInfo->callback.IsEmpty()) {
		delete hashInfo;
	}

	return scope.Close(passwordHash);
}
