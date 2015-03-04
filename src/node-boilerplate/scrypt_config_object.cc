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

#include <node.h>
#include <nan.h>
#include <v8.h>
#include <string>
#include <string.h>
#include <algorithm>

using namespace v8;
#include "common.h"

namespace {

NAN_PROPERTY_SETTER(configSetter) {
	NanScope();
	Handle<Value> returnValue;
	std::string errorMessage;
	std::string propertyString(*NanUtf8String(property));

	if (propertyString == "inputEncoding" || propertyString == "outputEncoding" || propertyString == "hashEncoding" || propertyString == "keyEncoding" || propertyString == "saltEncoding") {
		if (!value->IsString()) {
			value = NanNew<String>("buffer");
		}

		propertyString.insert(propertyString.begin(), '_');	
		std::string propertyValue(*NanUtf8String(value->ToString()));
		std::transform(propertyValue.begin(), propertyValue.end(), propertyValue.begin(), ::tolower);
		
		if (propertyValue == "ascii") {
			args.Holder()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::ASCII));
		} else if (propertyValue == "utf8") {
			args.Holder()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::UTF8));
		} else if (propertyValue == "base64") {
			args.Holder()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::BASE64));
		} else if (propertyValue == "ucs2") {
			args.Holder()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::UCS2));
		} else if (propertyValue == "binary") {
			args.Holder()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::BINARY));
		} else if (propertyValue == "hex") {
			args.Holder()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::HEX));
		} else {
			args.This()->SetHiddenValue(NanNew<String>(propertyString.c_str()), NanNew<Integer>(Nan::BUFFER));
		}
	}

	if (propertyString == "maxmem" || propertyString == "maxmemfrac") {
		if (!value->IsNumber()) {
			errorMessage = propertyString + " must be a number";
			NanThrowError(Internal::MakeErrorObject(CONFIG, errorMessage));
		}
	
		if (value->ToNumber()->Value() < 0) {
			errorMessage = propertyString + " cannot be less than zero";
			NanThrowError(Internal::MakeErrorObject(CONFIG, errorMessage));
		}
	}
	
	if (propertyString == "defaultSaltSize" || propertyString == "outputLength") {
		if (!value->IsNumber()) {
			errorMessage = propertyString + " must be a number";
			NanThrowError(Internal::MakeErrorObject(CONFIG, errorMessage));
		}
		
		if (value->ToUint32()->Value() <= 0) {
			errorMessage = propertyString + " must be greater than zero";
			NanThrowError(Internal::MakeErrorObject(CONFIG, errorMessage));
		}
	}

	NanReturnValue(returnValue);
}

} //end anon namespace

Handle<Object>
CreateScryptConfigObject(const char* objectType) {
	NanEscapableScope();
	Local<ObjectTemplate> configTemplate = ObjectTemplate::New();
	configTemplate->SetNamedPropertyHandler(NULL, configSetter); //Ignoring accessor callback

	NanSetTemplate(configTemplate, NanNew<String>("type"), NanNew<String>(objectType), v8::DontDelete);

	if (!strcmp(objectType,"kdf")) {
		NanSetTemplate(configTemplate, NanNew<String>("saltEncoding"), NanNew<String>("buffer"), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("keyEncoding"), NanNew<String>("buffer"), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("outputEncoding"), NanNew<String>("buffer"), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("defaultSaltSize"), NanNew<Integer>(32), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("outputLength"), NanNew<Integer>(64), v8::DontDelete);
	}
	
	if (!strcmp(objectType,"hash") || !strcmp(objectType,"kdf")) {
		NanSetTemplate(configTemplate, NanNew<String>("keyEncoding"), NanNew<String>("buffer"), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("outputEncoding"), NanNew<String>("buffer"), v8::DontDelete);
	}

	if (!strcmp(objectType,"verify")) {
		NanSetTemplate(configTemplate, NanNew<String>("hashEncoding"), NanNew<String>("buffer"), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("keyEncoding"), NanNew<String>("buffer"), v8::DontDelete);
	}

	if (!strcmp(objectType,"params")) {
		NanSetTemplate(configTemplate, NanNew<String>("maxmem"), NanNew<Number>(0.0), v8::DontDelete);
		NanSetTemplate(configTemplate, NanNew<String>("maxmemfrac"), NanNew<Number>(0.5), v8::DontDelete);
	}

	Local<Object> config = NanNew(configTemplate)->NewInstance();

	//Initialize Hidden Values
	config->SetHiddenValue(NanNew<String>("_keyEncoding"), NanNew<Integer>(Nan::BUFFER));
	config->SetHiddenValue(NanNew<String>("_saltEncoding"), NanNew<Integer>(Nan::BUFFER));
	config->SetHiddenValue(NanNew<String>("_outputEncoding"), NanNew<Integer>(Nan::BUFFER));
	config->SetHiddenValue(NanNew<String>("_hashEncoding"), NanNew<Integer>(Nan::BUFFER));
	
	return NanEscapeScope(config);
}
