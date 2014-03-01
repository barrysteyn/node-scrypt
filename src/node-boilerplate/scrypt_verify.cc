/*
	scrypt_verifyhash.cc 

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
#include <v8.h>
#include <node_buffer.h>
#include <string>

//Scrypt is a C library
extern "C" {
	#include "hash.h"
}

using namespace v8;
#include "common.h"
#include "scrypt_config_object.h"

namespace {

struct HashInfo {
	//Encodings
	node::encoding hashEncoding, keyEncoding;

	//Async callback function
	Persistent<Function> callback;
	Handle<Value> hash, key;

	//Custom data
	int result;
	char *hash_ptr, *key_ptr;
	size_t keySize;

	HashInfo(Handle<Object> config) : hash_ptr(NULL), key_ptr(NULL), keySize(0) { 
		hashEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_hashEncoding"))->ToUint32()->Value());
		keyEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_keyEncoding"))->ToUint32()->Value());
		callback.Clear(); 
		hash.Clear(); 
		key.Clear(); 
	}

	~HashInfo() { 
		if (!callback.IsEmpty()) {
			Persistent<Value>(hash).Dispose();
			Persistent<Value>(key).Dispose();
		}
		callback.Dispose(); 
	}
};

int
AssignArguments(const Arguments& args, std::string& errorMessage, HashInfo& hashInfo) {
	if (args.Length() < 2) {
		errorMessage = "both hash and key are needed";
		return ADDONARG;
	}

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errorMessage = "both hash and key are needed before the callback function";
		return ADDONARG;
	}

	for (int i=0; i < args.Length(); i++) {
		Handle<Value> currentVal = args[i];

		if (currentVal->IsUndefined() || currentVal->IsNull()) {
			errorMessage = "argument is undefined or null";
			return ADDONARG;
		} 

		if (i > 1 && currentVal->IsFunction()) {
			hashInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			hashInfo.hash = Persistent<Value>::New(hashInfo.hash);
			hashInfo.key = Persistent<Value>::New(hashInfo.key);
			return 0;
		}

		switch(i) {
			case 0: //Hash
				if (Internal::ProduceBuffer(currentVal, "hash", errorMessage, hashInfo.hashEncoding)) {
					return ADDONARG;
				}

				hashInfo.hash = currentVal;
				hashInfo.hash_ptr = node::Buffer::Data(currentVal);

				break;

			case 1: //Key
				if (Internal::ProduceBuffer(currentVal, "key", errorMessage, hashInfo.keyEncoding)) {
					return ADDONARG;
				}

				hashInfo.key = currentVal;
				hashInfo.key_ptr = node::Buffer::Data(currentVal);
				hashInfo.keySize = node::Buffer::Length(currentVal);

				break;
		}
	}

	return 0;
}

//
// Work Function: Actual key hash done here
//
void
VerifyWork(HashInfo* hashInfo) {
	hashInfo->result = Verify(
		(const uint8_t*)hashInfo->hash_ptr,
		(const uint8_t*)hashInfo->key_ptr, 
		hashInfo->keySize
	);
}

//
// Asynchronous: Wrapper to actual work function
//
void
VerifyAsyncWork(uv_work_t* req) {
	VerifyWork(static_cast<HashInfo*>(req->data));
}

//
// Synchronous: After work function
//
void
VerifySyncAfterWork(Local<Value>& result, const HashInfo* hashInfo) {
	if (hashInfo->result && hashInfo->result != 11) {
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,hashInfo->result)
		);
	} else {
		result = Local<Value>::New(Boolean::New(hashInfo->result == 0));
	}
}

//
// Asynchonous: After work function
//
void
VerifyAsyncAfterWork(uv_work_t* req) {
	HandleScope scope;
	HashInfo* hashInfo = static_cast<HashInfo*>(req->data);

	Local<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,hashInfo->result),
		Local<Value>::New(Boolean::New(hashInfo->result == 0))
	};

	TryCatch try_catch;
	hashInfo->callback->Call(Context::GetCurrent()->Global(), 2, argv);

	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	//Clean up
	delete hashInfo;
	delete req;
}

//
// Verify: Parses arguments and determines what type (sync or async) this function is
//
Handle<Value> 
Verify(const Arguments& args) {
	HandleScope scope;
	uint8_t parseResult = 0;
	std::string validateMessage;
	HashInfo* hashInfo = new HashInfo(Local<Object>::Cast(args.Holder()->Get(String::New("config"))));
	Local<Value> result;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *hashInfo))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		if (hashInfo->callback.IsEmpty()) {
			//Synchronous
			VerifyWork(hashInfo);
			VerifySyncAfterWork(result, hashInfo);
		} else {
			//Asynchronous work request
			uv_work_t *req = new uv_work_t();
			req->data = hashInfo;
			
			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, VerifyAsyncWork, (uv_after_work_cb)VerifyAsyncAfterWork);
			if (status != 0)
				assert(status == 0); 
		}
	}

	if (hashInfo->callback.IsEmpty()) {
		delete hashInfo;
	}

	return scope.Close(result);
}

} //end of anon namespace

//
// Object Constructor That Is Exposed To JavaScript
//
Handle<Value>
CreateVerifyFunction(const Arguments& arguments) {
	HandleScope scope;

	Local<ObjectTemplate> verify = ObjectTemplate::New();
	verify->SetCallAsFunctionHandler(Verify);
	verify->Set(String::New("config"), CreateScryptConfigObject("verify"), v8::ReadOnly);

	return scope.Close(verify->NewInstance());
}
