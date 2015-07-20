#include "scrypt_async.h"

// Async class
class ScryptParamsAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptParamsAsyncWorker(NanCallback* callback, _NAN_METHOD_ARGS) :
      ScryptAsyncWorker(callback),
      maxtime(args[0]->NumberValue()),
      maxmemfrac(args[1]->NumberValue()),
      maxmem(args[2]->NumberValue())
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
