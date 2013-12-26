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

#include <iostream>

#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <string>
#include <string.h>

//C Linkings
extern "C" {
    #include "keyderivation.h"
}

using namespace v8;
#include "scrypt_common.h"

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
	Internal::ScryptParams params;

	//Construtor / destructor   
	ScryptInfo() : key_ptr(NULL), salt_ptr(NULL), hashBuffer_ptr(NULL), keySize(0), saltSize(0), hashBufferSize(64) { 
		callback.Clear(); key.Clear(); salt.Clear(); hashBuffer.Clear(); 
	}

	~ScryptInfo() {
		if (!callback.IsEmpty()) {
			Persistent<Value>(key).Dispose();
			if (!salt.IsEmpty()) Persistent<Value>(salt).Dispose();
			Persistent<Value>(hashBuffer).Dispose();
		}
		callback.Dispose();
	}
};

//
// Validates and assigns arguments from JS land. Also determines if function is async or sync
//
int 
AssignArguments(const Arguments& args, std::string& errMessage, ScryptInfo &scryptInfo) {
    if (args.Length() < 2) {
        errMessage = "Wrong number of arguments: At least two arguments are needed - key and a json object representing the scrypt parameters";
        return 1;
    }

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errMessage = "Wrong number of arguments: At least two arguments are needed before the callback function - key and a json object representing the scrypt parameters";
		return 1;
	}

    for (int i=0; i < args.Length(); i++) {
		Handle<Value> currentVal = args[i];
		
		if (i > 1 && currentVal->IsFunction()) {
			scryptInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			scryptInfo.key = Persistent<Value>::New(scryptInfo.key);
			if (scryptInfo.saltSize) {
				scryptInfo.salt = Persistent<Value>::New(scryptInfo.salt);
			}

			return 0;
		}

        switch(i) {
            case 0: //key
                if (!currentVal->IsString() && !currentVal->IsObject()) {
                    errMessage = "key must be a buffer or a string";
                    return 1;
                }
               
				if (currentVal->IsString() || currentVal->IsStringObject()) {
					if (currentVal->ToString()->Length() == 0) {
						errMessage = "key string cannot be empty";
						return 1;
					}
				
					currentVal = node::Buffer::New(currentVal->ToString());	
				}

				if (currentVal->IsObject() && !currentVal->IsStringObject()) {
					if (!node::Buffer::HasInstance(currentVal)) {
						errMessage = "key must be a buffer or a string object";
						return 1;
					}

					if (node::Buffer::Length(currentVal) == 0) {
						errMessage = "key buffer cannot be empty";
						return 1;
					}
				}
				
				scryptInfo.key = currentVal;
				scryptInfo.key_ptr = node::Buffer::Data(currentVal);
				scryptInfo.keySize = node::Buffer::Length(currentVal);
               	
				break;

            case 1: //Scrypt parameters
                if (!currentVal->IsObject()) {
                    errMessage = "expecting scrypt parameters JSON object";
                    return 1;
                }
				
				if (Internal::CheckScryptParameters(currentVal->ToObject(), errMessage)) {
					return 1;
				}
               	
				scryptInfo.params = currentVal->ToObject();

                break;   

			case 2: //length
				if (!currentVal->IsNumber()) {
					errMessage = "length must be a number";
					return 1;
				} 
			
				if (currentVal->ToNumber()->Value() > 64) {
					scryptInfo.hashBufferSize = currentVal->ToNumber()->Value();
				}
			
				break;

			case 3: //salt
                if (!currentVal->IsString() && !currentVal->IsObject()) {
                    errMessage = "salt must be a buffer or a string";
                    return 1;
                }
               
				if (currentVal->IsString() || currentVal->IsStringObject()) {
					if (currentVal->ToString()->Length() == 0) {
						errMessage = "salt string cannot be empty";
						return 1;
					}
					
					currentVal = node::Buffer::New(currentVal->ToString());	
				}

				if (currentVal->IsObject() && !currentVal->IsStringObject()) {
					if (!node::Buffer::HasInstance(currentVal)) {
						errMessage = "salt must be a Buffer object";
						return 1;
					}

					if (node::Buffer::Length(currentVal->ToObject()) == 0) {
						errMessage = "salt buffer cannot be empty";
						return 1;
					}
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
CreateJSONResult(Handle<Value> &result, const ScryptInfo* scryptInfo) {
	Local<Object> resultObject = Object::New();
	resultObject->Set(String::NewSymbol("hash"), scryptInfo->hashBuffer);
	resultObject->Set(String::NewSymbol("salt"), scryptInfo->salt);

	result = resultObject;
}

//
// Synchronous: After work function
//
void
KDFSyncAfterWork(Handle<Value>& kdf, const ScryptInfo* scryptInfo) {
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
    HandleScope scope;
    std::string validateMessage;
	ScryptInfo* scryptInfo = new ScryptInfo(); 
	Local<Value> kdf;

	//Assign and validate arguments
    if (AssignArguments(args, validateMessage, *scryptInfo)) {
        ThrowException(
			Internal::MakeErrorObject(INTERNARG, validateMessage.c_str())
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
