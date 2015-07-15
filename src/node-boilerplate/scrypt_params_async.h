#include <node.h>
#include <nan.h>

#include "scrypt_async.h"

// Async class
class ScryptParamsAsyncWorker : public ScryptAsyncWorker {
  public:
    ScryptParamsAsyncWorker(NanCallback* callback, size_t maxmem, double maxmemfrac, double maxtime)
      : ScryptAsyncWorker(callback), maxmem(maxmem), maxmemfrac(maxmemfrac), maxtime(maxtime) {
        logN = 0;
        r = 0;
        p = 0;
      };

    void Execute();
    void HandleOKCallback();

  private:
    const size_t maxmem;
    const double maxmemfrac;
    const double maxtime;

    int logN;
    uint32_t r;
    uint32_t p;
};
