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

using Nan::GetFunction;
using Nan::New;
using Nan::Set;

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
NAN_MODULE_INIT(InitAll) {

	Set(target, Nan::New<String>("paramsSync").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(paramsSync)).ToLocalChecked());

	Set(target, Nan::New<String>("params").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(params)).ToLocalChecked());

	Set(target, Nan::New<String>("kdfSync").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(kdfSync)).ToLocalChecked());

	Set(target, Nan::New<String>("kdf").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(kdf)).ToLocalChecked());

	Set(target, Nan::New<String>("verifySync").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(kdfVerifySync)).ToLocalChecked());

	Set(target, Nan::New<String>("verify").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(kdfVerify)).ToLocalChecked());

	Set(target, Nan::New<String>("hashSync").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(hashSync)).ToLocalChecked());

	Set(target, Nan::New<String>("hash").ToLocalChecked(),
		GetFunction(Nan::New<FunctionTemplate>(hash)).ToLocalChecked());
}

NODE_MODULE(scrypt, InitAll)
