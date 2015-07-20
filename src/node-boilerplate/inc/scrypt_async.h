#ifndef _SCRYPTASYNC_H_
#define _SCRYPTASYNC_H_

#include "scrypt_common.h"

//
// Scrypt Async Worker
//

//Note: This class is implemented for common async
// class properties that applies to Scrypt functionality
// only. These properties are:
//  (1) Creation of Scrypt specific Error Object
//  (2) result integer that denotes the response from the Scrypt C library
//  (3) ScryptPeristentObject that holds input arguments from JS land
class ScryptAsyncWorker : public NanAsyncWorker {
  public:
    ScryptAsyncWorker(NanCallback* callback) : NanAsyncWorker(callback), result(0) {};

    //
    // Overrides Nan implementation by creating Scrypt Error
    //
    void HandleErrorCallback() {
      NanScope();

      v8::Local<v8::Value> argv[] = {
          Scrypt::ScryptError(result)
      };
      callback->Call(1, argv);
    }

    //
    // Overrides Nan implmentation by checking result
    //
    void WorkComplete() {
      NanScope();

      if (result == 0)
        HandleOKCallback();
      else
        HandleErrorCallback();
      delete callback;
      callback = NULL;
    }

  protected:
    //
    // Scrypt specific state
    //
    v8::Local<v8::Object> ScryptPeristentObject;
    int result;
};

#endif /* _SCRYPTASYNC_H_ */
