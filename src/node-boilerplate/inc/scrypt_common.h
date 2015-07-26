/*
scrypt_common.h

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

#ifndef _SCRYPTCOMMON_H_
#define _SCRYPTCOMMON_H_

#include <nan.h>
#include <node.h>

namespace NodeScrypt {

	//
	// Holds N,r and p parameters
	//
	struct Params {
		const uint32_t N;
		const uint32_t r;
		const uint32_t p;

		Params(const v8::Local<v8::Object> &lval) :
			N(lval->Get(NanNew<v8::String>("N"))->Uint32Value()),
			r(lval->Get(NanNew<v8::String>("r"))->Uint32Value()),
			p(lval->Get(NanNew<v8::String>("p"))->Uint32Value()) {}
	};

	//
	// Create a Scrypt error
	//
	v8::Local<v8::Value> ScryptError(const int error);
};

#endif /* _SCRYPTCOMMON_H_ */
