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
#include <v8.h>
#include <node_buffer.h>
#include <string>

//C Linkings
extern "C" {
	#include "keyderivation.h"
	#include "salt.h"
}

using namespace v8;
#include "common.h"
#include "scrypt_config_object.h"

namespace 
{

//
// Structure to hold information
//
struct KDFInfo {
	//Encodings
	node::encoding keyEncoding, saltEncoding, outputEncoding;

	//Async Persistent Values
	Persistent<Function> callback;
	Handle<Value> key, salt, hashBuffer;

	//Custom data for scrypt
	int result;
	char *key_ptr, *salt_ptr, *hashBuffer_ptr;
	size_t keySize, saltSize, outputLength;
	bool saltPersist;
	Internal::ScryptParams params;

	//Construtor / destructor   
	KDFInfo(Handle<Object> config) : key_ptr(NULL), salt_ptr(NULL), hashBuffer_ptr(NULL), keySize(0), saltPersist(false) { 
		keyEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_keyEncoding"))->ToUint32()->Value());
		saltEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_saltEncoding"))->ToUint32()->Value());
		outputEncoding = static_cast<node::encoding>(config->GetHiddenValue(v8::String::New("_outputEncoding"))->ToUint32()->Value());
		saltSize = static_cast<node::encoding>(config->Get(v8::String::New("defaultSaltSize"))->ToUint32()->Value());
		outputLength = static_cast<node::encoding>(config->Get(v8::String::New("outputLength"))->ToUint32()->Value());

		callback.Clear(); 
		key.Clear(); 
		salt.Clear(); 
		hashBuffer.Clear(); 
	}

	~KDFInfo() {
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
AssignArguments(const Arguments& args, std::string& errorMessage, KDFInfo &kdfInfo) {
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

		if (currentVal->IsUndefined() || currentVal->IsNull()) {
			errorMessage = "argument is undefined or null";
			return ADDONARG;
		} 

		if (i > 1 && currentVal->IsFunction()) {
			kdfInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			kdfInfo.key = Persistent<Value>::New(kdfInfo.key);
			if (!kdfInfo.salt.IsEmpty()) {
				kdfInfo.saltPersist = true;
				kdfInfo.salt = Persistent<Value>::New(kdfInfo.salt);
			}

			return 0;
		}

		switch(i) {
			case 0: //key
				if (Internal::ProduceBuffer(currentVal, "key", errorMessage, kdfInfo.keyEncoding, false)) {
					return ADDONARG;
				}
				
				kdfInfo.key = currentVal;
				kdfInfo.key_ptr = node::Buffer::Data(currentVal);
				kdfInfo.keySize = node::Buffer::Length(currentVal);

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

				kdfInfo.params = currentVal->ToObject();

				break;

			case 2: //size
				if (!currentVal->IsNumber()) {
					errorMessage = "outputLength must be a number";
					return ADDONARG;
				}
			
				if (currentVal->ToNumber()->Value() <= 0) {
					errorMessage = "outputLength must be greater than 0";
					return ADDONARG;
				}
				
				kdfInfo.outputLength = (size_t)currentVal->ToInteger()->Value();
			
				break;

			case 3: //salt
				if (Internal::ProduceBuffer(currentVal, "salt", errorMessage, kdfInfo.saltEncoding, false)) {
					return ADDONARG;
				}
				
				kdfInfo.salt = currentVal;
				kdfInfo.salt_ptr = node::Buffer::Data(currentVal);
				kdfInfo.saltSize = node::Buffer::Length(kdfInfo.salt);
		}
	}

	return 0;
}

//
// Creates the JSON object returned to JS land
//
void
CreateJSONResult(Handle<Value> &result, KDFInfo* kdfInfo) {
	Local<Object> resultObject = Object::New();
	resultObject->Set(String::NewSymbol("hash"), BUFFER_ENCODED(kdfInfo->hashBuffer, kdfInfo->outputEncoding));

	if (kdfInfo->salt.IsEmpty()) {
		Internal::CreateBuffer(kdfInfo->salt, kdfInfo->salt_ptr, kdfInfo->saltSize);
	}
	resultObject->Set(String::NewSymbol("salt"), BUFFER_ENCODED(kdfInfo->salt, kdfInfo->outputEncoding));

	result = resultObject;
}

//
// Synchronous: After work function
//
void
KDFSyncAfterWork(Handle<Value>& kdf, KDFInfo* kdfInfo) {
	if (kdfInfo->result) { //There has been an error
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,kdfInfo->result)
		);
	} else {
		CreateJSONResult(kdf, kdfInfo);
	}
}

//
// Asynchronous: After work function
//
void 
KDFAsyncAfterWork(uv_work_t *req) {
	HandleScope scope;
	KDFInfo* kdfInfo = static_cast<KDFInfo*>(req->data);
	Local<Value> kdfResult;
	uint8_t argc = (kdfInfo->result) ? 1 : 2;
	if (!kdfInfo->result) {
		CreateJSONResult(kdfResult, kdfInfo);
	}
	
	Handle<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,kdfInfo->result),
		kdfResult
	};

	TryCatch try_catch;
	kdfInfo->callback->Call(Context::GetCurrent()->Global(), argc, argv);
	if (try_catch.HasCaught()) {
		node::FatalException(try_catch);
	}

	//Cleanup
	delete kdfInfo; 
	delete req;
}

//
// Work Function: Actual scrypt key derivation performed here
//
void 
KDFWork(KDFInfo* kdfInfo) {
	if (!kdfInfo->salt_ptr) {
		kdfInfo->salt_ptr = new char[kdfInfo->saltSize];
		getsalt((uint8_t*)kdfInfo->salt_ptr, kdfInfo->saltSize);
	}

	kdfInfo->result = ScryptKeyDerivationFunction(
		(uint8_t*)kdfInfo->key_ptr, kdfInfo->keySize,
		(uint8_t*)kdfInfo->salt_ptr, kdfInfo->saltSize,
		kdfInfo->params.N, kdfInfo->params.r, kdfInfo->params.p,
		(uint8_t*)kdfInfo->hashBuffer_ptr, kdfInfo->outputLength
	);
}

//
// Asynchronous: Wrapper to actual work function
//
void 
KDFAsyncWork(uv_work_t* req) {
	KDFWork(static_cast<KDFInfo*>(req->data));	
}

//
// KDF: Parses arguments and determines what type (sync or async) this function is
//
Handle<Value> 
KDF(const Arguments& args) {
	uint8_t parseResult = 0;
	HandleScope scope;
	std::string validateMessage;
	KDFInfo* kdfInfo = new KDFInfo(Local<Object>::Cast(args.Holder()->Get(String::New("config"))));
	Local<Value> kdf;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *kdfInfo))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		Internal::CreateBuffer(kdfInfo->hashBuffer, kdfInfo->outputLength);
		kdfInfo->hashBuffer_ptr = node::Buffer::Data(kdfInfo->hashBuffer);

		if (kdfInfo->callback.IsEmpty()) {
			//Synchronous 
			KDFWork(kdfInfo);
			KDFSyncAfterWork(kdf, kdfInfo);
		} else {
			//Asynchronous
			kdfInfo->hashBuffer = Persistent<Value>::New(kdfInfo->hashBuffer);

			//Work request 
			uv_work_t *req = new uv_work_t();
			req->data = kdfInfo;

			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, KDFAsyncWork, (uv_after_work_cb)KDFAsyncAfterWork);
			if (status != 0)
				assert(status == 0);
		}
	}

	//Clean up heap only if call is synchronous
	if (kdfInfo->callback.IsEmpty()) {
		delete kdfInfo;
	}

	return scope.Close(kdf);
}

} //end of unnamed namespace

//
// The Constructor Exposed To JavaScript
//
Handle<Value>
CreateKeyDerivationFunction(const Arguments& arguments) {
    HandleScope scope;

    Local<ObjectTemplate> kdf = ObjectTemplate::New();
    kdf->SetCallAsFunctionHandler(KDF);
    kdf->Set(String::New("config"), CreateScryptConfigObject("kdf"), v8::ReadOnly);

    return scope.Close(kdf->NewInstance());
}
