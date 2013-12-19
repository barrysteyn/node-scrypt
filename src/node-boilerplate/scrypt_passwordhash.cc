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

#include "scrypt_common.h"

//C Linkings
extern "C" {
    #include "passwordhash.h"
    #include "base64.h"
}

//Forward Declaration
extern void * memcpy (void *destination, const void *source, size_t num);

using namespace v8;

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
	std::string message;
	std::string password;
	char* output;
	size_t outputLength;
	std::string encoding;
	ScryptParams params;

	//Construtor / destructor   
	ScryptInfo() : base64(true), output(NULL), encoding("base64") { callback.Clear(); }
	~ScryptInfo() {
		if (output) delete output;
		callback.Dispose(); //V8 persistent object clean up
	}
};

//
// Validates JavaScript function arguments for password hash, sets maxmem, maxmemfrac and maxtime and determines if function
// is sync or async
//
int 
ValidatePasswordHashArguments(const Arguments& args, std::string& errMessage, ScryptInfo &scryptInfo) {
	//Set default arguments
    if (args.Length() < 2) {
        errMessage = "Wrong number of arguments: At least two arguments are needed - password and max_time";
        return 1;
    }

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		errMessage = "Wrong number of arguments: At least two arguments are needed before the callback function - password and max_time";
		return 1;
	}

    for (int i=0; i < args.Length(); i++) {
		v8::Handle<v8::Value> currentVal = args[i];
		if (i > 1 && currentVal->IsFunction()) {
			scryptInfo.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
			return 0;
		}

        switch(i) {
            case 0:
                //Check password is a string
                if (!currentVal->IsString()) {
                    errMessage = "password must be a string";
                    return 1;
                }
                
                if (currentVal->ToString()->Length() == 0) {
                    errMessage = "password cannot be empty";
                    return 1;
                }
                
                break;

            case 1:
                //Check Scrypt parameters
                if (!currentVal->IsObject()) {
                    errMessage = "expecting scrypt parameters JSON object";
                    return 1;
                }
				
				if (checkScryptParameters(currentVal->ToObject(), errMessage)) {
					return 1;
				}
               	
				scryptInfo.params = currentVal->ToObject();
                break;   

			case 2:
				//Set encoding if possible, else leave it as default 
				if (currentVal->IsString()) {
					v8::String::Utf8Value bufferValue(currentVal);
					
					//This will be transformed to lower case in JavaScript land
					scryptInfo.encoding = *bufferValue;
					if (scryptInfo.encoding != "buffer") {
						scryptInfo.encoding = "base64"; //set back to default if not buffer	
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
createBuffer(v8::Local<v8::Object> &buffer, const char* data, const size_t &dataLength) {
	//Return data in a NodeJS Buffer. This will allow native ability
	//to convert between encodings and will allow the user to take
	//advantage of Node's buffer functions (excellent article: http://www.samcday.com.au/blog/2011/03/03/creating-a-proper-buffer-in-a-node-c-addon/)

	node::Buffer *slowBuffer = node::Buffer::New(dataLength);
	memcpy(node::Buffer::Data(slowBuffer), data, dataLength);

	//Create the node JS "fast" buffer
	v8::Local<v8::Object> globalObj = v8::Context::GetCurrent()->Global();	
	v8::Local<v8::Function> bufferConstructor = v8::Local<v8::Function>::Cast(globalObj->Get(v8::String::New("Buffer")));

	//Constructor arguments for "fast" buffer:
    // First argument is the JS object handle for the "slow buffer"
    // Second argument is the length of the slow buffer
    // Third argument is the offset in the "slow buffer" that "fast buffer" should start at
	v8::Handle<v8::Value> constructorArgs[3] = { slowBuffer->handle_, v8::Integer::New(dataLength), v8::Integer::New(0) };

	//Create the "fast buffer"
	buffer = bufferConstructor->NewInstance(3, constructorArgs);
}

//
// Synchronous: After work function
//
Handle<Value> 
PasswordHashSyncAfterWork(HandleScope &scope, ScryptInfo* scryptInfo) {
	Local<String> passwordHash;
	int result = scryptInfo->result;

	if (!result) passwordHash = String::New((const char*)scryptInfo->output, scryptInfo->outputLength);

	//cleanup
	delete scryptInfo;

    if (result) { //There has been an error
        ThrowException(
            Exception::TypeError(String::New(ScryptErrorDescr(result).c_str()))
        );
		return scope.Close(Undefined());
	} else { 
		return scope.Close(passwordHash);
	}
}

//
// Asynchronous: After work function
//
void 
PasswordHashAsyncAfterWork(uv_work_t *req) {
    HandleScope scope;
    ScryptInfo* scryptInfo = static_cast<ScryptInfo*>(req->data);

    if (scryptInfo->result) { //There has been an error
        Local<Value> err = Exception::Error(String::New(ScryptErrorDescr(scryptInfo->result).c_str()));

        //Prepare the parameters for the callback function
        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };

        // Wrap the callback function call in a TryCatch so that we can call
        // node's FatalException afterwards. This makes it possible to catch
        // the exception from JavaScript land using the
        // process.on('uncaughtException') event.
        TryCatch try_catch;
        scryptInfo->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    } else {
        const unsigned argc = 2;
        Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(String::New((const char*)scryptInfo->output, scryptInfo->outputLength))
        };

        TryCatch try_catch;
        scryptInfo->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
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
    uint8_t outbuf[96]; //Header size for password derivation is fixed
    char *base64Encode = NULL;

    //perform scrypt password hash
    scryptInfo->result = HashPassword(
        (const uint8_t*)scryptInfo->password.c_str(),
        outbuf,
		scryptInfo->params.N, scryptInfo->params.r, scryptInfo->params.p
    );

    //Base64 encode for storage
    scryptInfo->outputLength = base64_encode(outbuf, 96, &base64Encode);
    scryptInfo->output = base64Encode;
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
//               This function is the "entry" point from JavaScript land
//
Handle<Value> 
PasswordHash(const Arguments& args) {
    HandleScope scope;
    std::string validateMessage;
	ScryptInfo* scryptInfo = new ScryptInfo(); //Will hold data for both async and sync (DRY)

	//Validate arguments
    if (ValidatePasswordHashArguments(args, validateMessage, *scryptInfo)) {
        ThrowException(
            Exception::TypeError(String::New(validateMessage.c_str()))
        );
		delete scryptInfo;
        return scope.Close(Undefined());
    }

	//Password obtained from JavaScript land
    String::Utf8Value password(args[0]->ToString());
	scryptInfo->password = *password;

	if (scryptInfo->callback.IsEmpty()) {
		//Synchronous 

		PasswordHashWork(scryptInfo);
		return PasswordHashSyncAfterWork(scope, scryptInfo);
	} else {
		//Asynchronous

		//Work request 
		uv_work_t *req = new uv_work_t();
		req->data = scryptInfo;

		//Schedule work request
		int status = uv_queue_work(uv_default_loop(), req, PasswordHashAsyncWork, (uv_after_work_cb)PasswordHashAsyncAfterWork);
		assert(status == 0);

        return scope.Close(Undefined());
	}
}
