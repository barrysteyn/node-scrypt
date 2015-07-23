/*
scrypt_params_async.h

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

#ifndef _SCRYPT_PARAMS_ASYNC_H
#define _SCRYPT_PARAMS_ASYNC_H

#include "scrypt_async.h"

// Async class
class ScryptParamsAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptParamsAsyncWorker(_NAN_METHOD_ARGS) :
      ScryptAsyncWorker(new NanCallback(args[3].As<v8::Function>())),
      maxtime(args[0]->NumberValue()),
      maxmemfrac(args[1]->NumberValue()),
      maxmem(args[2]->ToUint32()->Value())
    {
      logN = 0;
      r = 0;
      p = 0;
    };

    void Execute();
    void HandleOKCallback();

  private:
    const double maxtime;
    const double maxmemfrac;
    const size_t maxmem;

    int logN;
    uint32_t r;
    uint32_t p;
};

#endif /* _SCRYPT_PARAMS_ASYNC_H */
