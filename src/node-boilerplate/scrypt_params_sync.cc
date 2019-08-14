#include <nan.h>
#include <node.h>

#include "scrypt_common.h"

//Scrypt is a C library and there needs c linkings
extern "C" {
  #include "pickparams.h"
}

using namespace v8;

//Synchronous access to scrypt params
NAN_METHOD(paramsSync) {
  //
  // Variable Declaration
  //
  int logN = 0;
  uint32_t r = 0;
  uint32_t p = 0;

  //
  // Arguments from JavaScript
  //
  const double maxtime = Nan::To<double>(info[0]).ToChecked();
  const size_t maxmem = Nan::To<int64_t>(info[2]).ToChecked();
  const double maxmemfrac = Nan::To<double>(info[1]).ToChecked();
  const size_t osfreemem = Nan::To<int64_t>(info[3]).ToChecked();

  //
  // Scrypt: calculate input parameters
  //
  const unsigned int result = pickparams(&logN, &r, &p, maxtime, maxmem, maxmemfrac, osfreemem);

  //
  // Error handling
  //
  if (result) {
    Nan::ThrowError(NodeScrypt::ScryptError(result));
  }

  //
  // Return values in JSON object
  //
  Local <Object> obj = Nan::New<Object>();
  Nan::Set(obj, Nan::New("N").ToLocalChecked(), Nan::New<Integer>(logN));
  Nan::Set(obj, Nan::New("r").ToLocalChecked(), Nan::New<Integer>(r));
  Nan::Set(obj, Nan::New("p").ToLocalChecked(), Nan::New<Integer>(p));

  info.GetReturnValue().Set(obj);
}
