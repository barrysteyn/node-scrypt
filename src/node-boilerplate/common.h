#ifndef _SCRYPTERROR_H_
#define _SCRYPTERROR_H_

//Macro expansion to DRY buffer encoding output
#define BUFFER_ENCODED(buffer, encoding) \
	((encoding == Nan::BUFFER) \
		? NanNew(buffer) \
		: NanEncode(node::Buffer::Data(NanNew(buffer)), node::Buffer::Length(NanNew(buffer)), encoding))

namespace Scrypt {
  const char* ScryptErrorDescr(const int error);
  v8::Local<v8::Value> ScryptError(const int error);
};

#endif /* _SCRYPTERROR_H_ */
