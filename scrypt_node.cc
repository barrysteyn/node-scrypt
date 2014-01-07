/*
	scrypt_node.cc

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

using namespace v8;
#include "src/node-boilerplate/scrypt_kdf.h"
#include "src/node-boilerplate/scrypt_hash.h"
#include "src/node-boilerplate/scrypt_verifyhash.h"
#include "src/node-boilerplate/scrypt_params.h"
#include "src/node-boilerplate/scrypt_error.h"
#include "src/node-boilerplate/scrypt_config_object.h"

//
// Function Instance Creators
//
Handle<Value>
CreateParameterFunction(const Arguments& arguments) {
    HandleScope scope;

	Local<ObjectTemplate> params = ObjectTemplate::New();
    params->SetCallAsFunctionHandler(Params);
	params->Set(String::New("config"), CreateScryptConfigObject("params"), v8::ReadOnly);
    
    return scope.Close(params->NewInstance());
}

Handle<Value>
CreateHashFunction(const Arguments& arguments) {
    HandleScope scope;

	Local<ObjectTemplate> hash = ObjectTemplate::New();
    hash->SetCallAsFunctionHandler(Hash);
	hash->Set(String::New("config"), CreateScryptConfigObject("hash"), v8::ReadOnly);
    
    return scope.Close(hash->NewInstance());
}

Handle<Value>
CreateKeyDerivationFunction(const Arguments& arguments) {
    HandleScope scope;

	Local<ObjectTemplate> kdf = ObjectTemplate::New();
    kdf->SetCallAsFunctionHandler(KDF);
	kdf->Set(String::New("config"), CreateScryptConfigObject("params"), v8::ReadOnly);
    
    return scope.Close(kdf->NewInstance());
}

Handle<Value>
CreateVerifyHashFunction(const Arguments& arguments) {
    HandleScope scope;

	Local<ObjectTemplate> verify = ObjectTemplate::New();
    verify->SetCallAsFunctionHandler(VerifyHash);
	verify->Set(String::New("config"), CreateScryptConfigObject("params"), v8::ReadOnly);
    
    return scope.Close(verify->NewInstance());
}

//
// Module initialisation function
//
void RegisterModule(Handle<Object> target) {
	//Params (Translation function)
	target->Set(String::NewSymbol("params"), 
            FunctionTemplate::New(CreateParameterFunction)->GetFunction());
    
	//KDF
	target->Set(String::NewSymbol("KDF"), 
            FunctionTemplate::New(CreateKeyDerivationFunction)->GetFunction());

	//Hash function
	target->Set(String::NewSymbol("passwordHash"), 
            FunctionTemplate::New(CreateParameterFunction)->GetFunction());

	//Verify hash
	target->Set(String::NewSymbol("verifyHash"), 
            FunctionTemplate::New(CreateParameterFunction)->GetFunction());

	//Error Object
	target->Set(String::NewSymbol("errorObject"),
		FunctionTemplate::New(MakeErrorObject)->GetFunction());
}

NODE_MODULE(scrypt, RegisterModule)
