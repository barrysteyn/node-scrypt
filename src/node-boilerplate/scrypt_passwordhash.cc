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

#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <string>
#include <cstring>
#include <algorithm>

//C Linkings
extern "C" {
    #include "passwordhash.h"
    #include "base64.h"
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

	//Custom data for scrypt
	bool base64;
	int result;
	std::string password;
	uint8_t* output;
	size_t outputLength;
	Internal::ScryptParams params;

	//Construtor / destructor   
	ScryptInfo() : base64(true), output(NULL) { callback.Clear(); }
	~ScryptInfo() {
		if (output) delete output;
		callback.Dispose(); //V8 persistent object clean up
	}
};

//
// Validates and assigns arguments from JS land. Also determines if function is async or sync
//
int 
AssignArguments(const Arguments& args, std::string& errMessage, ScryptInfo &scryptInfo) {
    if (args.Length() < 2) {
        errMessage = "Wrong number of arguments: At least two arguments are needed - password and max_time";
        return 1;
    }

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errMessage = "Wrong number of arguments: At least two arguments are needed before the callback function - password and max_time";
		return 1;
	}

    for (int i=0; i < args.Length(); i++) {
		Local<Value> currentVal = args[i];
		if (i > 1 && currentVal->IsFunction()) {
			scryptInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			return 0;
		}

        switch(i) {
            case 0: //Password
                if (!currentVal->IsString()) {
                    errMessage = "password must be a string";
                    return 1;
                }
                
                if (currentVal->ToString()->Length() == 0) {
                    errMessage = "password string cannot be empty";
                    return 1;
                }
               
				scryptInfo.password = *String::Utf8Value(currentVal->ToString());
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

			case 2: //Encoding
				if (currentVal->IsString()) {
					std::string encoding(*String::Utf8Value(currentVal));
					std::transform(encoding.begin(), encoding.end(), encoding.begin(), ::tolower);
				
					if (encoding == "buffer") {
						scryptInfo.base64 = false; 
					}
				}
        }
    }

    return 0;
}

//
// Create a NodeJS Buffer 
//
void 
CreateBuffer(Local<Value> &buffer, const char* data, const size_t &dataLength) {
	//Return data in a NodeJS Buffer. This will allow native ability
	//to convert between encodings and will allow the user to take
	//advantage of Node's buffer functions (excellent article: http://www.samcday.com.au/blog/2011/03/03/creating-a-proper-buffer-in-a-node-c-addon/)

	node::Buffer *slowBuffer = node::Buffer::New(dataLength);
	memcpy(node::Buffer::Data(slowBuffer), data, dataLength);

	//Create the node JS "fast" buffer
	Local<Object> globalObj = Context::GetCurrent()->Global();	
	Local<Function> bufferConstructor = Local<Function>::Cast(globalObj->Get(String::New("Buffer")));

	//Constructor arguments for "fast" buffer:
    // First argument is the JS object handle for the "slow buffer"
    // Second argument is the length of the slow buffer
    // Third argument is the offset in the "slow buffer" that "fast buffer" should start at
	Handle<Value> constructorArgs[3] = { slowBuffer->handle_, Integer::New(dataLength), Integer::New(0) };

	//Create the "fast buffer"
	buffer = bufferConstructor->NewInstance(3, constructorArgs);
}

//
// Creates the password hash passed to JS land
//
void
CreatePasswordHash(Local<Value>& passwordHash, const ScryptInfo* scryptInfo) {
	if (scryptInfo->base64) {
		passwordHash = String::New((const char*)scryptInfo->output, scryptInfo->outputLength);
	} else {
		CreateBuffer(passwordHash, (const char*)scryptInfo->output, scryptInfo->outputLength);
	}
}

//
// Synchronous: After work function
//
void
PasswordHashSyncAfterWork(Local<Value> &passwordHash, const ScryptInfo* scryptInfo) {
    if (scryptInfo->result) { //There has been an error
        ThrowException(
			Internal::MakeErrorObject(SCRYPT,scryptInfo->result)
        );
	} else {
		CreatePasswordHash(passwordHash, scryptInfo);
	}
}

//
// Asynchronous: After work function
//
void 
PasswordHashAsyncAfterWork(uv_work_t *req) {
    HandleScope scope;
	uint8_t argc = 1;
	Local<Value> passwordHash;
    ScryptInfo* scryptInfo = static_cast<ScryptInfo*>(req->data);

	if (!scryptInfo->result) {
		CreatePasswordHash(passwordHash, scryptInfo);
		argc++;
	}

	Local<Value> argv[2] = {
		Internal::MakeErrorObject(SCRYPT,scryptInfo->result),
		passwordHash
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
        (const uint8_t*)scryptInfo->password.c_str(),
        &scryptInfo->output,
		scryptInfo->params.N, scryptInfo->params.r, scryptInfo->params.p
    );

	if (scryptInfo->base64) {
		uint8_t* hashOutput = scryptInfo->output;
		scryptInfo->outputLength = base64_encode(hashOutput, 96, (char**)&scryptInfo->output);
		delete hashOutput;
	} else {
		scryptInfo->outputLength = 96;
	}
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
	HandleScope scope;
	std::string validateMessage;
	ScryptInfo* scryptInfo = new ScryptInfo(); 
	Local<Value> hash;

	//Assign and validate arguments
	if (AssignArguments(args, validateMessage, *scryptInfo)) {
		ThrowException(
			Internal::MakeErrorObject(INTERNARG, validateMessage.c_str())
		);
	} else {
		if (scryptInfo->callback.IsEmpty()) {
			//Synchronous 
			PasswordHashWork(scryptInfo);
			PasswordHashSyncAfterWork(hash, scryptInfo);
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

	return scope.Close(hash);
}
