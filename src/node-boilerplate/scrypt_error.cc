/*
	scrypt_error.cc 

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

using namespace v8;

#include "common.h"

//
// Error: Entry point from JavaScript land
//
Handle<Value> 
MakeErrorObject(const Arguments& args) {
	HandleScope scope;
	Local<Value> errObj;
	std::string errString = (args[1]->IsString()) ? std::string(*v8::String::Utf8Value(args[1]->ToString())) : "";
	if (!args[0]->IsNumber()) {
		errObj = Internal::MakeErrorObject(500, errString);
	} else
		errObj = Internal::MakeErrorObject((int)args[0]->ToInteger()->Value(), errString);
	
	return scope.Close(errObj);
}
