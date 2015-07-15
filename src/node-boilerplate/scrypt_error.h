#ifndef _SCRYPTERROR_H_
#define _SCRYPTERROR_H_

namespace Scrypt {
  const char* ScryptErrorDescr(const int error);
  v8::Local<v8::Value> ScryptError(const int error);
};

#endif /* _SCRYPTERROR_H_ */
