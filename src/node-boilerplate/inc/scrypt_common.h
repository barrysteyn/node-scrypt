#ifndef _SCRYPTERROR_H_
#define _SCRYPTERROR_H_

#include <nan.h>
#include <node.h>

namespace Scrypt {
	//
	// Holds N,r and p parameters
	//
	struct Params {
		const uint32_t N;
		const uint32_t r;
		const uint32_t p;

		Params(const v8::Local<v8::Object> &lval) :
			N(uint32_t(lval->Get(NanNew<v8::String>("N"))->ToInteger()->Value())),
			r(uint32_t(lval->Get(NanNew<v8::String>("r"))->ToInteger()->Value())),
			p(uint32_t(lval->Get(NanNew<v8::String>("p"))->ToInteger()->Value())) {}
	};

	//
	// Create a Scrypt error
	//
	v8::Local<v8::Value> ScryptError(const int error);
};

#endif /* _SCRYPTERROR_H_ */
