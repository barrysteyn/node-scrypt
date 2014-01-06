/*
	scrypt_config_object.cc

	Copyright (C) 2014 Barry Steyn (http://doctrina.org/Scrypt-Authentication-For-Node.html)

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
#include <string>
#include <string.h>
#include <algorithm>

using namespace v8;
#include "common.h"
#include "scrypt_config_object.h"

Handle<Value> configSetter(Local<String> propertyString, Local<Value> value, const AccessorInfo& info) {
	Handle<Value> returnValue;
	std::string errorMessage;
	std::string property(*String::Utf8Value(propertyString));

	if (property == "inputEncoding" || property == "outputEncoding") {
		if (!value->IsString()) {
			errorMessage = "encoding must be string";
			ThrowException(
				Internal::MakeErrorObject(CONFIG, errorMessage)
			);
		}
		property.insert(property.begin(), '_');	
		std::string propertyValue(*String::Utf8Value(value->ToString()));
		std::transform(propertyValue.begin(), propertyValue.end(), propertyValue.begin(), ::tolower);
		
		if (propertyValue == "ascii") {
			info.Holder()->Set(String::New(property.c_str()), Integer::New(node::ASCII));
		} else if (propertyValue == "utf8") {
			info.Holder()->Set(String::New(property.c_str()), Integer::New(node::UTF8));
		} else if (propertyValue == "base64") {
			info.Holder()->Set(String::New(property.c_str()), Integer::New(node::BASE64));
		} else if (propertyValue == "ucs2") {
			info.Holder()->Set(String::New(property.c_str()), Integer::New(node::UCS2));
		} else if (propertyValue == "binary") {
			info.Holder()->Set(String::New(property.c_str()), Integer::New(node::BINARY));
		} else if (propertyValue == "hex") {
			info.Holder()->Set(String::New(property.c_str()), Integer::New(node::HEX));
		} else {
			info.This()->Set(String::New(property.c_str()), Integer::New(node::BUFFER));
		}
	}

	return returnValue;
}

Handle<Object>
CreateScryptConfigObject(const char* objectType) {
	HandleScope scope;
	Local<ObjectTemplate> configTemplate = ObjectTemplate::New();
	configTemplate->SetNamedPropertyHandler(NULL, configSetter); //Ignoring accessor callback

	Local<Object> config = configTemplate->NewInstance();
	config->Set(String::New("inputEncoding"), String::New("buffer"));
	config->Set(String::New("outputEncoding"), String::New("buffer"));

	if (!strcmp(objectType,"params")) {
		config->Set(String::New("maxmem"), Number::New(0.5));
		config->Set(String::New("maxmemfrac"), Number::New(0.5));
	}

	return scope.Close(config);
}
