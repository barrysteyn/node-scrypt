#ifndef _SCRYPTASYNC_H_
#define _SCRYPTASYNC_H_

#include "scrypt_error.h"

//
// Scrypt Async Worker
//

//Note: This class is implemented so as to override the
// the HandleErrorCallback in order to create Scrypt
// error objects. It is still an abstract class
// as it does not implement Execute
class ScryptAsyncWorker : public NanAsyncWorker {
  public:
    ScryptAsyncWorker(NanCallback* callback) : NanAsyncWorker(callback), result(0) {};

    // Overrides Nan implementation by creating Scrypt Error
    void HandleErrorCallback() {
      NanScope();

      v8::Local<v8::Value> argv[] = {
          Scrypt::ScryptError(result)
      };
      callback->Call(1, argv);
    }

    // Overrides Nan implmentation by checking result
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
    int result;
};

#endif /* _SCRYPTASYNC_H_ */
