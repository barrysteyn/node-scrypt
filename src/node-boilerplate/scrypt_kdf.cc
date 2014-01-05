/*
	scrypt_kdf.cc 

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

#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <string>

//C Linkings
extern "C" {
	#include "keyderivation.h"
	#include "salt.h"
}

using namespace v8;
#include "common.h"

namespace 
{

//
// Structure to hold information
//
struct ScryptInfo {
	//Async Persistent Values
	Persistent<Function> callback;
	Handle<Value> key, salt, hashBuffer;

	//Custom data for scrypt
	int result;
	char *key_ptr, *salt_ptr, *hashBuffer_ptr;
	size_t keySize, saltSize, hashBufferSize;
	bool saltPersist;
	Internal::ScryptParams params;

	//Construtor / destructor   
	ScryptInfo() : key_ptr(NULL), salt_ptr(NULL), hashBuffer_ptr(NULL), keySize(0), saltSize(32), hashBufferSize(64), saltPersist(false) { 
		callback.Clear(); key.Clear(); salt.Clear(); hashBuffer.Clear(); 
	}

	~ScryptInfo() {
		if (!callback.IsEmpty()) {
			Persistent<Value>(key).Dispose();
			if (this->saltPersist) Persistent<Value>(salt).Dispose();
			Persistent<Value>(hashBuffer).Dispose();
		}
		callback.Dispose();
	}
};

//
// Validates and assigns arguments from JS land. Also determines if function is async or sync
//
int 
AssignArguments(const Arguments& args, std::string& errorMessage, ScryptInfo &scryptInfo) {
	uint8_t scryptParameterParseResult = 0;
	if (args.Length() < 2) {
		errorMessage = "at least two arguments are needed - key and a json object representing the scrypt parameters";
		return ADDONARG;
	}

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errorMessage = "at least two arguments are needed before the callback function - key and a json object representing the scrypt parameters";
		return ADDONARG;
	}

	for (int i=0; i < args.Length(); i++) {
		Handle<Value> currentVal = args[i];

		if (i > 1 && currentVal->IsFunction()) {
			scryptInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			scryptInfo.key = Persistent<Value>::New(scryptInfo.key);
			if (!scryptInfo.salt.IsEmpty()) {
				scryptInfo.saltPersist = true;
				scryptInfo.salt = Persistent<Value>::New(scryptInfo.salt);
			}

			return 0;
		}

		switch(i) {
			case 0: //key
				if (Internal::ProduceBuffer(currentVal, "key", errorMessage, node::ASCII, false)) {
					return ADDONARG;
				}
				
				scryptInfo.key = currentVal;
				scryptInfo.key_ptr = node::Buffer::Data(currentVal);
				scryptInfo.keySize = node::Buffer::Length(currentVal);

				break;

			case 1: //Scrypt parameters
				if (!currentVal->IsObject()) {
					errorMessage = "expecting JSON object representing scrypt parameters";
					return ADDONARG;
				}

				scryptParameterParseResult = Internal::CheckScryptParameters(currentVal->ToObject(), errorMessage);
				if (scryptParameterParseResult) {
					return scryptParameterParseResult;
				}

				scryptInfo.params = currentVal->ToObject();

				break;

			case 2: //length
				if (!currentVal->IsNumber()) {
					errorMessage = "length must be a number";
					return ADDONARG;
				}
			
				if (currentVal->ToNumber()->Value() > 64) {
					scryptInfo.hashBufferSize = currentVal->ToNumber()->Value();
				}
			
				break;

			case 3: //salt
				if (Internal::ProduceBuffer(currentVal, "salt", errorMessage, node::ASCII, false)) {
					return ADDONARG;
				}
				
				scryptInfo.salt = currentVal;
				scryptInfo.salt_ptr = node::Buffer::Data(currentVal);
				scryptInfo.saltSize = node::Buffer::Length(scryptInfo.salt);
		}
	}

	return 0;
}

//
// Creates the JSON object returned to JS land
//
void
CreateJSONResult(Handle<Value> &result, ScryptInfo* scryptInfo) {
	Local<Object> resultObject = Object::New();
	resultObject->Set(String::NewSymbol("hash"), scryptInfo->hashBuffer);

	if (scryptInfo->salt.IsEmpty()) {
		Internal::CreateBuffer(scryptInfo->salt, scryptInfo->salt_ptr, scryptInfo->saltSize);
	}
	resultObject->Set(String::NewSymbol("salt"), scryptInfo->salt);

	result = resultObject;
}

//
// Synchronous: After work function
//
void
KDFSyncAfterWork(Handle<Value>& kdf, ScryptInfo* scryptInfo) {
	if (scryptInfo->result) { //There has been an error
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,scryptInfo->result)
		);
	} else {
		CreateJSONResult(kdf, scryptInfo);
	}
}

//
// Asynchronous: After work function
//
void 
KDFAsyncAfterWork(uv_work_t *req) {
	HandleScope scope;
	ScryptInfo* scryptInfo = static_cast<ScryptInfo*>(req->data);
	Local<Value> kdfResult;
	uint8_t argc = (scryptInfo->result) ? 1 : 2;
	if (!scryptInfo->result) {
		CreateJSONResult(kdfResult, scryptInfo);
	}
	
	Handle<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,scryptInfo->result),
		kdfResult
	};

	TryCatch try_catch;
	scryptInfo->callback->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	//Cleanup
	delete scryptInfo; 
	delete req;
}

//
// Work Function: Actual scrypt key derivation performed here
//
void 
KDFWork(ScryptInfo* scryptInfo) {
	if (!scryptInfo->salt_ptr) {
		scryptInfo->salt_ptr = new char[scryptInfo->saltSize];
		getsalt((uint8_t*)scryptInfo->salt_ptr, scryptInfo->saltSize);
	}

	scryptInfo->result = ScryptKeyDerivationFunction(
		(uint8_t*)scryptInfo->key_ptr, scryptInfo->keySize,
		(uint8_t*)scryptInfo->salt_ptr, scryptInfo->saltSize,
		scryptInfo->params.N, scryptInfo->params.r, scryptInfo->params.p,
		(uint8_t*)scryptInfo->hashBuffer_ptr, scryptInfo->hashBufferSize
	);
}

//
// Asynchronous: Wrapper to actual work function
//
void 
KDFAsyncWork(uv_work_t* req) {
	KDFWork(static_cast<ScryptInfo*>(req->data));	
}

} //end of unnamed namespace

//
// PasswordHash: Parses arguments and determines what type (sync or async) this function is
// This function is the "entry" point from JavaScript land
//
Handle<Value> 
KDF(const Arguments& args) {
	uint8_t parseResult = 0;
	HandleScope scope;
	std::string validateMessage;
	ScryptInfo* scryptInfo = new ScryptInfo(); 
	Local<Value> kdf;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *scryptInfo))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		Internal::CreateBuffer(scryptInfo->hashBuffer, scryptInfo->hashBufferSize);
		scryptInfo->hashBuffer_ptr = node::Buffer::Data(scryptInfo->hashBuffer);

		if (scryptInfo->callback.IsEmpty()) {
			//Synchronous 
			KDFWork(scryptInfo);
			KDFSyncAfterWork(kdf, scryptInfo);
		} else {
			//Asynchronous
			scryptInfo->hashBuffer = Persistent<Value>::New(scryptInfo->hashBuffer);

			//Work request 
			uv_work_t *req = new uv_work_t();
			req->data = scryptInfo;

			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, KDFAsyncWork, (uv_after_work_cb)KDFAsyncAfterWork);
			assert(status == 0);
		}
	}

	//Clean up heap only if call is synchronous
	if (scryptInfo->callback.IsEmpty()) {
		delete scryptInfo;
	}

	return scope.Close(kdf);
}
