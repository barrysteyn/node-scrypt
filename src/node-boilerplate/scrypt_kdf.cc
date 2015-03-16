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
#include <nan.h>
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
	Nan::Encoding keyEncoding, saltEncoding, outputEncoding;

	//Persistent Values
	Persistent<Function> callback;
	Persistent<Value> key, salt, hashBuffer;

	//Custom data for scrypt
	int result;
	char *key_ptr, *salt_ptr, *hashBuffer_ptr;
	size_t keySize, saltSize, outputLength;
	Internal::ScryptParams params;

	//Dispose and clears memory
	void cleanUp() {
		NanDisposePersistent(callback);
		NanDisposePersistent(key);
		NanDisposePersistent(salt);
		NanDisposePersistent(hashBuffer);
	}

	//Construtor / destructor   
	KDFInfo(Handle<Object> config) : key_ptr(NULL), salt_ptr(NULL), hashBuffer_ptr(NULL), keySize(0) {
		keyEncoding = static_cast<Nan::Encoding>(config->GetHiddenValue(NanNew<String>("_keyEncoding"))->ToUint32()->Value());
		saltEncoding = static_cast<Nan::Encoding>(config->GetHiddenValue(NanNew<String>("_saltEncoding"))->ToUint32()->Value());
		outputEncoding = static_cast<Nan::Encoding>(config->GetHiddenValue(NanNew<String>("_outputEncoding"))->ToUint32()->Value());
		saltSize = static_cast<Nan::Encoding>(config->Get(NanNew<String>("defaultSaltSize"))->ToUint32()->Value());
		outputLength = static_cast<Nan::Encoding>(config->Get(NanNew<String>("outputLength"))->ToUint32()->Value());
		cleanUp(); //probably not needed, but does no harm
	}

	~KDFInfo() {
		cleanUp();
	}
};

//
// Validates and assigns arguments from JS land. Also determines if function is async or sync
//
int 
AssignArguments(_NAN_METHOD_ARGS_TYPE args, std::string& errorMessage, KDFInfo &kdfInfo) {
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
			NanAssignPersistent(kdfInfo.callback, args[i].As<Function>());
			return 0;
		}

		switch(i) {
			case 0: //key
				if (Internal::ProduceBuffer(currentVal, "key", errorMessage, kdfInfo.keyEncoding, false)) {
					return ADDONARG;
				}
				
				NanAssignPersistent(kdfInfo.key,currentVal);
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
				
				NanAssignPersistent(kdfInfo.salt, currentVal);
				kdfInfo.salt_ptr = node::Buffer::Data(currentVal);
				kdfInfo.saltSize = node::Buffer::Length(currentVal);

				break;
		}
	}

	return 0;
}

//
// Creates the JSON object returned to JS land
//
void
CreateJSONResult(Handle<Value> &result, KDFInfo* kdfInfo) {
	Local<Object> resultObject = NanNew<Object>();
	resultObject->Set(NanNew<String>("hash"), BUFFER_ENCODED(kdfInfo->hashBuffer, kdfInfo->outputEncoding));

	//If no salt value specified by user, then a random value was generated by scrypt
	//We must retrieve that value
	if (kdfInfo->salt.IsEmpty()) {
		Handle<Value> salt = NanBufferUse(kdfInfo->salt_ptr, kdfInfo->saltSize);
		NanAssignPersistent(kdfInfo->salt, salt);
	}
	resultObject->Set(NanNew<String>("salt"), BUFFER_ENCODED(kdfInfo->salt, kdfInfo->outputEncoding));
	
	result = resultObject;
}

//
// Synchronous: After work function
//
void
KDFSyncAfterWork(Handle<Value>& kdf, KDFInfo* kdfInfo) {
	if (kdfInfo->result) { //There has been an error
		NanThrowError(
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
	NanScope();

	KDFInfo* kdfInfo = static_cast<KDFInfo*>(req->data);
	Local<Value> kdfResult;
	if (!kdfInfo->result) {
		CreateJSONResult(kdfResult, kdfInfo);
	}
	
	Handle<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,kdfInfo->result),
		kdfResult
	};

	TryCatch try_catch;
	NanMakeCallback(NanGetCurrentContext()->Global(), NanNew(kdfInfo->callback), 2, argv);

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

NAN_METHOD(KDF) {
	NanScope();

	uint8_t parseResult = 0;
	std::string validateMessage;
	KDFInfo* kdfInfo = new KDFInfo(Local<Object>::Cast(args.Holder()->Get(NanNew<String>("config"))));
	Local<Value> kdf;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *kdfInfo))) {
		NanThrowError(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		Handle<Value> hashBuffer = NanNewBufferHandle(kdfInfo->outputLength);
		NanAssignPersistent(kdfInfo->hashBuffer, hashBuffer);
		kdfInfo->hashBuffer_ptr = node::Buffer::Data(hashBuffer);

		if (kdfInfo->callback.IsEmpty()) {
			//Synchronous 
			KDFWork(kdfInfo);
			KDFSyncAfterWork(kdf, kdfInfo);
		} else {
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
		NanReturnValue(kdf);
	}

	NanReturnUndefined();
}

} //end of unnamed namespace

//
// The Constructor Exposed To JavaScript
//

NAN_METHOD(CreateKeyDerivationFunction) {
	NanScope();

	Local<ObjectTemplate> kdf = ObjectTemplate::New();
	kdf->SetCallAsFunctionHandler(KDF);
	kdf->Set(NanNew<String>("config"), CreateScryptConfigObject("kdf"), v8::ReadOnly);

	NanReturnValue(NanNew(kdf)->NewInstance());
}
