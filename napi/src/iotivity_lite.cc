#include "iotivity_lite.h"

using namespace Napi;

Napi::FunctionReference OCUuid::constructor;

OCUuid::OCUuid(const Napi::CallbackInfo& info) : ObjectWrap(info) {
	printf("OCUuid\n");
}
/*
OCUuid::OCUuid(const Napi::Env& env, Napi::Object& wrapper) {
  //napi_env env = callbackInfo.Env();
  //napi_value wrapper = callbackInfo.This();
  napi_status status;
  napi_ref ref;
  OCUuid* instance = static_cast<OCUuid*>(this);
  status = napi_wrap(env, wrapper, instance, MyFinalizeCallback, nullptr, &ref);
  NAPI_THROW_IF_FAILED_VOID(env, status);

  Reference<Object>* instanceRef = instance;
  *instanceRef = Reference<Object>(env, ref);
}
*/

Napi::Function OCUuid::GetClass(Napi::Env env) {
    Napi::Function func = DefineClass(env, "OCUuid", {
		    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}
//IotivityLite::InstanceAccessor("device", &IotivityLite::GetDevice, &IotivityLite::SetDevice),
 //       IotivityLite::InstanceAccessor("di", &IotivityLite::GetDi, &IotivityLite::SetDi),
  //      IotivityLite::InstanceAccessor("greet", &IotivityLite::Greet, nullptr),

IotivityLite::IotivityLite(const Napi::CallbackInfo& info) : ObjectWrap(info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "You need to name yourself")
          .ThrowAsJavaScriptException();
        return;
    }

    //OCUuid* uuid = new OCUuid(info);
    this->_greeterName = info[0].As<Napi::String>().Utf8Value();
}

Napi::Value IotivityLite::Greet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "You need to introduce yourself to greet")
          .ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::String name = info[0].As<Napi::String>();

    printf("Hello %s\n", name.Utf8Value().c_str());
    printf("I am %s\n", this->_greeterName.c_str());

    return Napi::String::New(env, this->_greeterName);
}

Napi::Function IotivityLite::GetClass(Napi::Env env) {
    return DefineClass(env, "IotivityLite", {
        IotivityLite::InstanceAccessor("device", &IotivityLite::GetDevice, &IotivityLite::SetDevice),
        IotivityLite::InstanceAccessor("di", &IotivityLite::GetDi, &IotivityLite::SetDi),
        IotivityLite::InstanceAccessor("greet", &IotivityLite::Greet, nullptr),
    });
}

Napi::Value IotivityLite::GetDevice(const Napi::CallbackInfo& info) {
    printf("GetDevice\n");
    Napi::Env env = info.Env();
    //OCUuid* uuid = new OCUuid(info);
    return Napi::Number::New(env, endpoint.device);
}

void IotivityLite::SetDevice(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDevice\n");
}

Napi::Value IotivityLite::GetDi(const Napi::CallbackInfo& info) {
    printf("GetDi\n");
    Napi::Env env = info.Env();
    //Object obj = Object::New(env);
    //OCUuid* uuid = new OCUuid(env, obj);
    return OCUuid::constructor.New({});
    //return Napi::Number::New(env, 0);
}

void IotivityLite::SetDi(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDi\n");
}



Napi::Object Init(Napi::Env env, Napi::Object exports) {
    Napi::String name = Napi::String::New(env, "IotivityLite");
    exports.Set(name, IotivityLite::GetClass(env));
    Napi::String name2 = Napi::String::New(env, "OCUuid");
    exports.Set(name2, OCUuid::GetClass(env));
    return exports;
}

NODE_API_MODULE(addon, Init)
