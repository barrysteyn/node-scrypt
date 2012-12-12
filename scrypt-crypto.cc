#include <node.h>
#include <v8.h>
#include <string>

//Scrypt is a C library
extern "C" {
    #include "scryptenc.h"
}

using namespace v8;

//Defaults parameters for Scrypt
struct defaults {
    static size_t maxmem;
    static double maxmemfrac;
};
size_t defaults::maxmem = 0;
double defaults::maxmemfrac = 0.5;

//Asynchronous work request data
struct Baton {
    //Asynch callback function
    Persistent<Function> callback;

    //Error data
    bool error;
    std::string error_message;

    //Custom data
    int32_t test;
};

/*
 * Validates JavaScript function arguments and sets maxmem, maxmemfrac and maxtime
 */
int ValidateArguments(const Arguments& args, char** message, size_t& maxmem, double& maxmemfrac, double& maxtime) {
    uint32_t callbackPosition = 0;

    for (int i=0; i < args.Length(); i++) {
        if (args[i]->IsFunction()) {
            callbackPosition = i;

            //once we have reached callback function, we will stop processing arguments.
            //but we need to be sure that the arguments we have processed so far is enough.
            if (i < 3) {
                *message = "arguments missing before callback. make sure at least message, password and max_time have been set before callback";
                return 0;
            }

            //Success
            *message = NULL;
            return callbackPosition;
        }

        switch(i) {
            case 0:
                //Check message is a string
                if (!args[i]->IsString()) {
                    *message = "message must be a string";
                    return 0;
                }
                
                if (args[i]->ToString()->Length() == 0) {
                    *message = "message cannot be empty";
                    return 0;
                }
                
                break;

            case 1:
                //Check password is a string
                if (!args[i]->IsString()) {
                    *message = "password must be a string";
                    return 0;
                }
               
                if (args[i]->ToString()->Length() == 0) {
                    *message = "password cannot be empty";
                    return 0;
                }
                
                break;

            case 2:
                //Check max_time is a number
                if (!args[i]->IsNumber()) {
                    *message = "max_time argument must be a number";
                    return 0;
                }

                //Check that maxtime is not less than or equal to zero (which would not make much sense)
                maxtime = Local<Number>(args[i]->ToNumber())->Value();
                if (maxtime <= 0) {
                    *message = "max_time must be greater than 0";
                    return 0;
                }
                
                break;   

            case 3:
                //Set mexmem if possible, else set it to default
                if (args[i]->IsNumber()) {
                    maxmem = Local<Number>(args[i]->ToNumber())->Value();

                    if (maxmem < 0)
                        maxmem = defaults::maxmem;
                }
                break;

            case 4:
                //Set mexmemfrac if possible, else set it to default
                if (args[i]->IsNumber()) {
                    maxmemfrac = Local<Number>(args[i]->ToNumber())->Value();

                    if (maxmemfrac <=0)
                        maxmemfrac = defaults::maxmemfrac;
                }                
                break; 
        }
    }
  
    if (!callbackPosition) { 
        *message = "callback function not present";
        return 0;
    }
}


/*
 * Encrypt Functions
 */
Handle<Value> Encrypt(const Arguments& args) {
    HandleScope scope;

    size_t maxmem = defaults::maxmem;
    double maxmemfrac = defaults::maxmemfrac;
    double maxtime = 0.0;
    char* validateMessage;
    uint32_t callbackPosition;

    if (args.Length() < 4) {
        ThrowException(
            Exception::TypeError(String::New("Wrong number of arguments: At least four arguments are needed - data, password, max_time and a callback function"))
        );
        return scope.Close(Undefined());
    }

    //Validate arguments
    if (!(callbackPosition = ValidateArguments(args, &validateMessage, maxmem, maxmemfrac, maxtime))) {
        ThrowException(
            Exception::TypeError(String::New(validateMessage))
        );
        return scope.Close(Undefined());
    }

    //Local variables
    String::Utf8Value message(args[0]->ToString());
    String::Utf8Value password(args[1]->ToString());
    Local<Function> callback = Local<Function>::Cast(args[callbackPosition]);

    //Asynchronous call baton that holds data passed to asynch function
    Baton* baton = new Baton();
    baton->error = false;
    baton->test = 42;
    baton->callback = Persistent<Function>::New(callback);

    //Asynchronous work request
    uv_work_t *req = new uv_work_t();
    req->data = baton;
    
    //Schedule work request
    int status = uv_queue_work(uv_default_loop(), req, AsyncWork, AsyncAfter);
    assert(status == 0); 
    
    return scope.Close(Undefined());   

    
    uint8_t outbuf[message.length() + 128];
    /*result = scryptenc_buf(
                (uint8_t*)*message, 
                message.length(), 
                outbuf, 
                (uint8_t*)*password,
                password.length(),
                maxmem, maxmemfrac, maxtime); 
*/
}

/*
 * Decrypt Functions
 */
Handle<Value> Decrypt(const Arguments& args) {
  HandleScope scope;
  return scope.Close(String::New("decrypt"));
}

/*
 * Hash Functions
 */
Handle<Value> Hash(const Arguments& args) {
  HandleScope scope;
  return scope.Close(String::New("hash"));
}

/*
 * Module initialisation function
 */
void RegisterModule(Handle<Object> target) {
    target->Set(String::NewSymbol("encrypt"),
        FunctionTemplate::New(Encrypt)->GetFunction());

    target->Set(String::NewSymbol("decrypt"),
        FunctionTemplate::New(Decrypt)->GetFunction());

    target->Set(String::NewSymbol("hash"),
        FunctionTemplate::New(Hash)->GetFunction());
}
NODE_MODULE(scrypt-crypto, RegisterModule)
