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

#include <iostream> //For testing, remove when finished

#include <node.h>
#include <node_buffer.h>
#include <string_bytes.h>
#include <v8.h>
#include <string>
#include <string.h> //Contains memcpy reference

#include "scrypt_passwordhash.h"
#include "scrypt_common.h"

//Scrypt is a C library
extern "C" {
    #include "passwordhash.h"
    #include "base64.h"
}

using namespace v8;

const size_t maxmem_default = 0;
const double maxmemfrac_default = 0.5;

/*
 * Validates JavaScript function arguments for password hash, sets maxmem, maxmemfrac and maxtime and determines if function
 * is sync or async
 */
int ValidateHashArguments(const Arguments& args, std::string& message, size_t& maxmem, double& maxmemfrac, double& maxtime, int &callbackPosition) {
    if (args.Length() < 2) {
        message = "Wrong number of arguments: At least two arguments are needed - password and max_time";
        return 1;
    }

	if (args.Length() >= 2 && (args[0]->IsFunction() || args[1]->IsFunction())) {
		message = "Wrong number of arguments: At least two arguments are needed before the callback function - password and max_time";
		return 1;
	}

    for (int i=0; i < args.Length(); i++) {
		if (i > 1 && args[i]->IsFunction()) {
			callbackPosition = i; //an async function
			return 0;
		}

        switch(i) {
            case 0:
                //Check password is a string
                if (!args[i]->IsString()) {
                    message = "password must be a string";
                    return 1;
                }
                
                if (args[i]->ToString()->Length() == 0) {
                    message = "password cannot be empty";
                    return 1;
                }
                
                break;

            case 1:
                //Check max_time is a number
                if (!args[i]->IsNumber()) {
                    message = "maxtime argument must be a number";
                    return 1;
                }

                //Check that maxtime is not less than or equal to zero (which would not make much sense)
                maxtime = Local<Number>(args[i]->ToNumber())->Value();
                if (maxtime <= 0) {
                    message = "maxtime must be greater than 0";
                    return 1;
                }
                
                break;   

            case 2:
                //Set mexmem if possible, else set it to default
                if (args[i]->IsNumber()) {
                    int maxmemArg = Local<Number>(args[i]->ToNumber())->Value();

                    if (maxmemArg < 0)
                        maxmem = maxmem_default;
                    else
                        maxmem = (size_t)maxmemArg;
                }
                break;

            case 3:
                //Set mexmemfrac if possible, else set it to default
                if (args[i]->IsNumber()) {
                    maxmemfrac = Local<Number>(args[i]->ToNumber())->Value();

                    if (maxmemfrac <=0)
                        maxmemfrac = maxmemfrac_default;
                }                
                break; 
        }
    }

    return 0;
}

/*
 * Create a NodeJS Buffer 
 */
inline void createBuffer(v8::Local<v8::Object> &buffer, const char* data, const size_t &dataLength) {
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

/*
 * Synchronous: Password Hash
 */
Handle<Value> HashSync(HandleScope &scope, const String::Utf8Value &password, const size_t &maxmem, const double &maxmemfrac, const double &maxtime) {
	uint8_t outbuf[96]; //Header size for password derivation is fixed
	size_t hashLength = 96;
    Local<String> passwordHash;
 
	//perform scrypt password hash
    int result = HashPassword(
        (const uint8_t*)*password,
        outbuf,
        maxmem, maxmemfrac, maxtime
    );

    if (!result) {
        //Base64 encode for storage
        char* base64Encode = NULL;
        size_t base64EncodedLength = base64_encode(outbuf, 96, &base64Encode);

        passwordHash = String::New((const char*)base64Encode, base64EncodedLength);

        //Clean up
        if (base64Encode)
            delete base64Encode;
    }

    if (result) { //There has been an error
        ThrowException(
            Exception::TypeError(String::New(ScryptErrorDescr(result).c_str()))
        );
        return scope.Close(Undefined());
	} else {
		//v8::Local<v8::Object> buffer
		//createBuffer(buffer, outbuf, hashLength);
		return scope.Close(passwordHash);
	}
}

Handle<Value> HashTest(const Arguments& args) {
    HandleScope scope;
    size_t maxmem = maxmem_default;
    double maxmemfrac = maxmemfrac_default;
    double maxtime = 0.0;
    std::string validateMessage;
    int callbackPosition = -1;

	//Validate arguments
    if (ValidateHashArguments(args, validateMessage, maxmem, maxmemfrac, maxtime, callbackPosition)) {
        ThrowException(
            Exception::TypeError(String::New(validateMessage.c_str()))
        );
        return scope.Close(Undefined());
    }

    //Arguments from JavaScript land
    String::Utf8Value password(args[0]->ToString());

	if (callbackPosition == -1) {
		return HashSync(scope, password, maxmem, maxmemfrac, maxtime);
	} else {
		//Arguments from JavaScript land
		String::Utf8Value password(args[0]->ToString());
		Local<Function> callback = Local<Function>::Cast(args[callbackPosition]);
        return scope.Close(Undefined());
	}
}
