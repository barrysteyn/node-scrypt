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
#include <nan.h>
#include <v8.h>

using namespace v8;

//
// Forward declarations
//
NAN_METHOD(paramsSync);
NAN_METHOD(params);
NAN_METHOD(kdfSync);
NAN_METHOD(kdf);
NAN_METHOD(kdfVerifySync);
NAN_METHOD(kdfVerify);
NAN_METHOD(hashSync);
NAN_METHOD(hash);

//
// Module initialisation
//
void RegisterModule(Handle<Object> target) {

	target->Set(NanNew<String>("paramsSync"),
		NanNew<FunctionTemplate>(paramsSync)->GetFunction());

	target->Set(NanNew<String>("params"),
		NanNew<FunctionTemplate>(params)->GetFunction());

	target->Set(NanNew<String>("kdfSync"),
		NanNew<FunctionTemplate>(kdfSync)->GetFunction());

	target->Set(NanNew<String>("kdf"),
		NanNew<FunctionTemplate>(kdf)->GetFunction());

	target->Set(NanNew<String>("verifySync"),
		NanNew<FunctionTemplate>(kdfVerifySync)->GetFunction());

	target->Set(NanNew<String>("verify"),
		NanNew<FunctionTemplate>(kdfVerify)->GetFunction());

	target->Set(NanNew<String>("hashSync"),
		NanNew<FunctionTemplate>(hashSync)->GetFunction());

	target->Set(NanNew<String>("hash"),
		NanNew<FunctionTemplate>(hash)->GetFunction());
}

NODE_MODULE(scrypt, RegisterModule)
