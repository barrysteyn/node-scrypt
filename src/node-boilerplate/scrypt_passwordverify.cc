/*
scrypt_passwordverify.cc 

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
#include <string>
#include <algorithm>
#include <stdlib.h>


//Scrypt is a C library
extern "C" {
    #include "passwordhash.h"
    #include "base64.h"
}

using namespace v8;
#include "scrypt_common.h"
#include "scrypt_passwordverify.h"

namespace {

struct PasswordHash {
    //Async callback function
    Persistent<Function> callback;

    //Custom data
	bool base64;
    int result;
	std::string hash;
    std::string password;

	PasswordHash() : base64(true) { callback.Clear(); }
	~PasswordHash() { callback.Dispose(); }
};

int
AssignArguments(const Arguments& args, std::string& errMessage, PasswordHash& passwordHash) {
    if (args.Length() < 2) {
        errMessage = "Wrong number of arguments: At least two arguments are needed - hash and password";
        return 1;
    }

    if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
        errMessage = "Wrong number of arguments: At least two arguments are needed before the callback function - hash and password";
        return 1;
    }

    for (int i=0; i < args.Length(); i++) {
		Local<Value> currentVal = args[i];
        if (i > 1 && currentVal->IsFunction()) {
            passwordHash.callback = Persistent<Function>::New(Local<Function>::Cast(args[i]));
            return 0;
        }

        switch(i) {
            case 0: //The hash
                if (!currentVal->IsString()) {
                    errMessage = "hash must be a string";
                    return 1;
                }
                
                if (currentVal->ToString()->Length() == 0) {
                    errMessage = "hash cannot be empty";
                    return 1;
                }
               
				passwordHash.hash = *String::Utf8Value(currentVal); 
                break;
            
            case 1: //The password
                if (!currentVal->IsString()) {
                    errMessage = "password must be a string";
                    return 1;
                }
                
                if (currentVal->ToString()->Length() == 0) {
                    errMessage = "password cannot be empty";
                    return 1;
                }
                
				passwordHash.password = *String::Utf8Value(currentVal); 
                break;

			case 2: //Encoding
				if (currentVal->IsString()) {
                    std::string encoding(*String::Utf8Value(currentVal));
                    std::transform(encoding.begin(), encoding.end(), encoding.begin(), ::tolower);
					
					if (encoding == "raw")
						passwordHash.base64 = false;
				}
        }
    }

    return 0;
}

//
// Work Function: Actual password hash done here
//
void
VerifyHashWork(PasswordHash* passwordHash) {
	uint8_t *hash = NULL;

	if (passwordHash->base64) {
		base64_decode(passwordHash->hash.c_str(), &hash);
	} 
    
	passwordHash->result = VerifyHash(
       	(passwordHash->base64)
			? (const uint8_t*)hash
			: (const uint8_t*)passwordHash->hash.c_str(),
		96, (const uint8_t*)passwordHash->password.c_str()
    );

	if (hash) delete hash;
}

//
// Asynchronous: Wrapper to actual work function
//
void
VerifyHashAsyncWork(uv_work_t* req) {
    VerifyHashWork(static_cast<PasswordHash*>(req->data));
}


//
// Synchronous: After work function
//
void
VerifyHashSyncAfterWork(Local<Value>& result, const PasswordHash* passwordHash) {
	if (passwordHash->result && passwordHash->result != 11) {
        ThrowException(
            Internal::MakeErrorObject(SCRYPT,passwordHash->result)
        );		
	} else {
		result = Local<Value>::New(Boolean::New(passwordHash->result == 0));
	}
}

//
// Asynchonous: After work function
//
void
VerifyHashAsyncAfterWork(uv_work_t* req) {
    HandleScope scope;
    PasswordHash* passwordHash = static_cast<PasswordHash*>(req->data);

    if (passwordHash->result) {
        Local<Value> err = Internal::MakeErrorObject(SCRYPT,passwordHash->result);

        const unsigned argc = 1;
        Local<Value> argv[argc] = { err };

        TryCatch try_catch;
        passwordHash->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    } else {
        const unsigned argc = 2;
        Local<Value> argv[argc] = {
            Local<Value>::New(Null()),
            Local<Value>::New(Boolean::New(true))
        };

        TryCatch try_catch;
        passwordHash->callback->Call(Context::GetCurrent()->Global(), argc, argv);
        if (try_catch.HasCaught()) {
            node::FatalException(try_catch);
        }
    }

    //Clean up
    delete passwordHash;
    delete req;
}

} //end of anon namespace

//
// VerifyPasswordHash: Parses arguments and determines what type (sync or async) this function is
// This function is the "entry" point from JavaScript land
//
Handle<Value> 
VerifyPasswordHash(const Arguments& args) {
    HandleScope scope;
    std::string validateMessage;
	PasswordHash* passwordHash = new PasswordHash();
	Local<Value> result;

    //Assign and validate arguments
	if (AssignArguments(args, validateMessage, *passwordHash)) {
        ThrowException(
			Internal::MakeErrorObject(INTERNARG, validateMessage.c_str())
        );
    } else {
		if (passwordHash->callback.IsEmpty()) {
			//Synchronous
			VerifyHashWork(passwordHash);
			VerifyHashSyncAfterWork(result, passwordHash);
		} else {
			//Asynchronous work request
			uv_work_t *req = new uv_work_t();
			req->data = passwordHash;
			
			//Schedule work request
			int status = uv_queue_work(uv_default_loop(), req, VerifyHashAsyncWork, (uv_after_work_cb)VerifyHashAsyncAfterWork);
			assert(status == 0); 
		}
	}
   
	if (passwordHash->callback.IsEmpty()) {
		delete passwordHash;
	}
	 
    return scope.Close(result);   
}
