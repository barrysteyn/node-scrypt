/*
	scrypt_password.cc 

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
#include "scrypt_common.h"

namespace 
{

//
// Structure to hold information
//
struct ScryptInfo {
	//Async callback function
	Persistent<Function> callback;
	Handle<Value> password, passwordHash;

	//Custom data for scrypt
	int result;
	
	char *password_ptr, *passwordHash_ptr;
	size_t passwordSize, passwordHashSize;
	Internal::ScryptParams params;

	//Construtor / destructor   
	ScryptInfo() : password_ptr(NULL), passwordHash_ptr(NULL), passwordSize(0),passwordHashSize(96) { 
		result = 3;
		callback.Clear(); 
		password.Clear();
		passwordHash.Clear();
	}
	~ScryptInfo() {
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
AssignArguments(const Arguments& args, std::string& errMessage, ScryptInfo &scryptInfo) {
	uint8_t scryptParameterParseResult = 0;	
	if (args.Length() < 2) {
		errMessage = "Wrong number of arguments: At least two arguments are needed - password and scrypt parameters JSON object";
		return ADDONARG;
	}

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errMessage = "Wrong number of arguments: At least two arguments are needed before the callback function - password and scrypt parameters JSON object";
		return ADDONARG;
	}

	for (int i=0; i < args.Length(); i++) {
		Handle<Value> currentVal = args[i];
		if (i > 1 && currentVal->IsFunction()) {
			scryptInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			scryptInfo.password = Persistent<Value>::New(scryptInfo.password);
			scryptInfo.passwordHash = Persistent<Value>::New(scryptInfo.passwordHash);
			return 0;
		}

		switch(i) {
			case 0: //Password
				if (!currentVal->IsString() && !currentVal->IsObject()) {
					errMessage = "password must be a buffer or a string";
					return ADDONARG;
				}

				if (currentVal->IsString() || currentVal->IsStringObject()) {
					if (currentVal->ToString()->Length() == 0) {
						errMessage = "password cannot be empty";
						return ADDONARG;
					}

					currentVal = node::Buffer::New(currentVal->ToString());
				}

				if (currentVal->IsObject() && !currentVal->IsStringObject()) {
					if (!node::Buffer::HasInstance(currentVal)) {
						errMessage = "password must a buffer or string object";
						return ADDONARG;
					}

					if (node::Buffer::Length(currentVal) == 0) {
						errMessage = "password cannot be empty";
						return ADDONARG;
					}
				}
		
				scryptInfo.password = currentVal;
				scryptInfo.password_ptr = node::Buffer::Data(currentVal);
				scryptInfo.passwordSize = node::Buffer::Length(currentVal);
		
				Internal::CreateBuffer(scryptInfo.passwordHash, scryptInfo.passwordHashSize);
				scryptInfo.passwordHash_ptr = node::Buffer::Data(scryptInfo.passwordHash);

				break;

			case 1: //Scrypt parameters
				if (!currentVal->IsObject()) {
					errMessage = "expecting scrypt parameters JSON object";
					return ADDONARG;
				}

				scryptParameterParseResult = Internal::CheckScryptParameters(currentVal->ToObject(), errMessage);
				if (scryptParameterParseResult) {
					return scryptParameterParseResult;
				}

				scryptInfo.params = currentVal->ToObject();

				break;   
		}
	}

	return 0;
}

//
// Synchronous: After work function
//
void
PasswordHashSyncAfterWork(Handle<Value> &passwordHash, const ScryptInfo* scryptInfo) {
	if (scryptInfo->result) { //There has been an error
		ThrowException(
			Internal::MakeErrorObject(SCRYPT,scryptInfo->result)
		);
	} else {
		passwordHash = scryptInfo->passwordHash;
	}
}

//
// Asynchronous: After work function
//
void 
PasswordHashAsyncAfterWork(uv_work_t *req) {
	HandleScope scope;
	ScryptInfo* scryptInfo = static_cast<ScryptInfo*>(req->data);
	uint8_t argc = (scryptInfo->result) ? 1 : 2;
	Handle<Value> passwordHash;

	Handle<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,scryptInfo->result),
		scryptInfo->passwordHash
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
// Work Function: Actual password hash performed here
//
void 
PasswordHashWork(ScryptInfo* scryptInfo) {
	//perform scrypt password hash
	scryptInfo->result = HashPassword(
		(const uint8_t*)scryptInfo->password_ptr, scryptInfo->passwordSize,
		(uint8_t*)scryptInfo->passwordHash_ptr,
		scryptInfo->params.N, scryptInfo->params.r, scryptInfo->params.p
	);
}

//
// Asynchronous: Wrapper to actual work function
//
void 
PasswordHashAsyncWork(uv_work_t* req) {
	PasswordHashWork(static_cast<ScryptInfo*>(req->data));	
}

} //end of unnamed namespace

//
// PasswordHash: Parses arguments and determines what type (sync or async) this function is
// This function is the "entry" point from JavaScript land
//
Handle<Value> 
PasswordHash(const Arguments& args) {
	uint8_t parseResult = 0;
	HandleScope scope;
	std::string validateMessage;
	ScryptInfo* scryptInfo = new ScryptInfo(); 
	Handle<Value> passwordHash;

	//Assign and validate arguments
	if ((parseResult = AssignArguments(args, validateMessage, *scryptInfo))) {
		ThrowException(
			Internal::MakeErrorObject(parseResult, validateMessage)
		);
	} else {
		if (scryptInfo->callback.IsEmpty()) {
			//Synchronous 
			PasswordHashWork(scryptInfo);
			PasswordHashSyncAfterWork(passwordHash, scryptInfo);
		} else {
			//Work request 
			uv_work_t *req = new uv_work_t();
			req->data = scryptInfo;

			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, PasswordHashAsyncWork, (uv_after_work_cb)PasswordHashAsyncAfterWork);
			assert(status == 0);
		}
	}

	//Clean up heap only if call is synchronous
	if (scryptInfo->callback.IsEmpty()) {
		delete scryptInfo;
	}

	return scope.Close(passwordHash);
}
