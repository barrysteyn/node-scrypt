/*
scrypt_kdf_verify_async.h

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

#ifndef _KDF_VERIFY_ASYNC_H
#define _KDF_VERIFY_ASYNC_H

#include "scrypt_async.h"

class ScryptKDFVerifyAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptKDFVerifyAsyncWorker(_NAN_METHOD_ARGS) :
      ScryptAsyncWorker(new NanCallback(args[2].As<v8::Function>())),
      kdf_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[0]))),
      key_ptr(reinterpret_cast<uint8_t*>(node::Buffer::Data(args[1]))),
      key_size(node::Buffer::Length(args[1])),
      match(false)
    {
      ScryptPeristentObject = NanNew<v8::Object>();
      ScryptPeristentObject->Set(NanNew<v8::String>("KDFBuffer"), args[0]);
      ScryptPeristentObject->Set(NanNew<v8::String>("KeyBuffer"), args[1]);
      SaveToPersistent("ScryptPeristentObject", ScryptPeristentObject);
    };

    void Execute();
    void HandleOKCallback();

  private:
    const uint8_t* kdf_ptr;
    const uint8_t* key_ptr;
    const size_t key_size;
    bool match;
};

#endif /* _KDF_VERIFY_ASYNC_H */
