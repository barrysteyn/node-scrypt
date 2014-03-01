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

#include <node.h>
//#include <v8.h>
#include <node_buffer.h>
#include <string>

//C Linkings
extern "C" {
	#include "hash.h"
}

using namespace v8;
#include "common.h"
#include "scrypt_config_object.h"

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
	Handle<Value> key, keyHash;

	//Custom data for scrypt
	int result;
	
	char *key_ptr, *keyHash_ptr;
	size_t keySize, keyHashSize;
	Internal::ScryptParams params;

	//Construtor / destructor   
	HashInfo(Handle<Object> config) : key_ptr(NULL), keyHash_ptr(NULL), keySize(0),keyHashSize(96) {
		keyEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_keyEncoding"))->ToUint32()->Value());
		outputEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_outputEncoding"))->ToUint32()->Value());
		callback.Clear(); 
		key.Clear();
		keyHash.Clear();
	}
	~HashInfo() {
		if (!callback.IsEmpty()) {
			Persistent<Value>(key).Dispose();
			Persistent<Value>(keyHash).Dispose();
		}
		callback.Dispose();
	}
};

//
// Validates and assigns arguments from JS land. Also determines if function is async or sync
//
int 
AssignArguments(const Arguments& arguments, std::string& errorMessage, HashInfo &hashInfo) {
	uint8_t scryptParameterParseResult = 0;
	if (arguments.Length() < 2) {
		errorMessage = "wrong number of arguments - at least two arguments are needed - key and scrypt parameters JSON object";
		return ADDONARG;

	}

	if (arguments.Length() >= 2 && (arguments[0]->IsFunction() || arguments[1]->IsFunction())) {
		errorMessage = "wrong number of arguments at least two arguments are needed before the callback function - key and scrypt parameters JSON object";
		return ADDONARG;
	}

	for (int i=0; i < arguments.Length(); i++) {
		Handle<Value> currentVal = arguments[i];

		if (currentVal->IsUndefined() || currentVal->IsNull()) {
			errorMessage = "argument is undefined or null";
			return ADDONARG;
		}

		if (i > 1 && currentVal->IsFunction()) {
			hashInfo.callback = Persistent<Function>::New(Local<Function>::Cast(arguments[i]));
			hashInfo.key = Persistent<Value>::New(hashInfo.key);
			hashInfo.keyHash = Persistent<Value>::New(hashInfo.keyHash);
			return 0;
		}

		switch(i) {
			case 0: //key
				if (Internal::ProduceBuffer(currentVal, "key", errorMessage, hashInfo.keyEncoding)) {
					return ADDONARG;
				}
				hashInfo.key = currentVal;
				hashInfo.key_ptr = node::Buffer::Data(currentVal);
				hashInfo.keySize = node::Buffer::Length(currentVal);

				//Create hash buffer - note that it is the same size as the key buffer
				Internal::CreateBuffer(hashInfo.keyHash, hashInfo.keyHashSize);
				hashInfo.keyHash_ptr = node::Buffer::Data(hashInfo.keyHash);
				break;

			case 1: //Scrypt parameters
				if (!currentVal->IsObject()) {
					errorMessage = "expecting scrypt parameter JSON object";
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
PasswordHashSyncAfterWork(Handle<Value> &keyHash, const HashInfo* hashInfo) {
	if (hashInfo->result) { //There has been an error
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,hashInfo->result)
		);
	} else {
		keyHash = BUFFER_ENCODED(hashInfo->keyHash, hashInfo->outputEncoding);
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
	Handle<Value> keyHash = BUFFER_ENCODED(hashInfo->keyHash, hashInfo->outputEncoding);

	Handle<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,hashInfo->result),
		keyHash
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
// Work Function: Actual key hash performed here
//
void 
PasswordHashWork(HashInfo* hashInfo) {
	//perform scrypt hash
	hashInfo->result = Hash(
		(const uint8_t*)hashInfo->key_ptr, hashInfo->keySize,
		(uint8_t*)hashInfo->keyHash_ptr,
		hashInfo->params.N, hashInfo->params.r, hashInfo->params.p
	);
}

//
// Asynchronous: Wrapper to work function
//
void 
PasswordHashAsyncWork(uv_work_t* req) {
	PasswordHashWork(static_cast<HashInfo*>(req->data));	
}

//
// Hash: Parses arguments and determines what type (sync or async) this function is
//
Handle<Value> 
Hash(const Arguments& arguments) {
	uint8_t parseResult = 0;
	HandleScope scope;
	std::string validateMessage;
	HashInfo* hashInfo = new HashInfo(Local<Object>::Cast(arguments.Holder()->Get(String::New("config")))); 
	Handle<Value> keyHash;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(arguments, validateMessage, *hashInfo))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		if (hashInfo->callback.IsEmpty()) {
			//Synchronous 
			PasswordHashWork(hashInfo);
			PasswordHashSyncAfterWork(keyHash, hashInfo);
		} else {
			//Work request 
			uv_work_t *req = new uv_work_t();
			req->data = hashInfo;

			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, PasswordHashAsyncWork, (uv_after_work_cb)PasswordHashAsyncAfterWork);
			if (status != 0)
				assert(status == 0);
		}
	}

	//Clean up heap only if call is synchronous
	if (hashInfo->callback.IsEmpty()) {
		delete hashInfo;
	}

	return scope.Close(keyHash);
}

} //end of unnamed namespace

//
// Constructor For Object Exposed To JavaScript
//
Handle<Value>
CreateHashFunction(const Arguments& arguments) {
	HandleScope scope;

	Local<ObjectTemplate> hash = ObjectTemplate::New();
	hash->SetCallAsFunctionHandler(Hash);
	hash->Set(String::New("config"), CreateScryptConfigObject("hash"), v8::ReadOnly);

	return scope.Close(hash->NewInstance());
}
