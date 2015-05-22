#include <node.h>
#include <nan.h>

class ParamsAsyncWorker : public NanAsyncWorker {
  public:
    ParamsAsyncWorker(NanCallback* callback)
      : NanAsyncWorker(callback) {}

    void Execute();
    void HandleOKCallback();
    void HandleErrorCallback();

  private:
    int result;
    size_t maxmem;
    double maxmemfrac;
    double maxtime;
    int N;
    uint32_t r;
    uint32_t p;
}
