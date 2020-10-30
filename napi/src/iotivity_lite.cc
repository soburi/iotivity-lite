#include "iotivity_lite.h"
#include "structs.h"
#include "functions.h"
using namespace Napi;

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

    //XOCUuid* uuid = new XOCUuid(info);
    this->_greeterName = info[0].As<Napi::String>().Utf8Value();
}

Napi::FunctionReference IotivityLite::callback_helper;

Napi::Value IotivityLite::Callback(const Napi::CallbackInfo& info) {
	OCIPv4Addr* ipv4 = OCIPv4Addr::Unwrap(info[0].As<Object>());
printf("Unwrap %p\n", ipv4);

	Napi::Function func = info[0].As<Napi::Function>();

	IotivityLite::callback_helper = Napi::Persistent(func);
	IotivityLite::callback_helper.SuppressDestruct();

	callback_helper.Call({});

	return info.Env().Null();
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
        IotivityLite::InstanceMethod("callback", &IotivityLite::Callback),
    });
}

Napi::Value IotivityLite::GetDevice(const Napi::CallbackInfo& info) {
    printf("GetDevice\n");
    Napi::Env env = info.Env();
    //XOCUuid* uuid = new XOCUuid(info);
    return Napi::Number::New(env, endpoint.device);
}

void IotivityLite::SetDevice(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDevice\n");
}

Napi::Value IotivityLite::GetDi(const Napi::CallbackInfo& info) {
    printf("GetDi\n");
    //Napi::Env env = info.Env();
    //Object obj = Object::New(env);
    //XOCUuid* uuid = new XOCUuid(env, obj);
    //return XOCUuid::constructor.New({});
    return Napi::Number::New(info.Env(), 0);
}

void IotivityLite::SetDi(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDi\n");
}

OCMain::OCMain(const Napi::CallbackInfo& info) : ObjectWrap(info) { }
Napi::Value OCMain::main_init(const Napi::CallbackInfo& info) { return N_oc_main_init(info); }
Napi::Value OCMain::main_shutdown(const Napi::CallbackInfo& info) { return N_oc_main_shutdown(info); }
Napi::Value OCMain::set_factory_presets_handler(const Napi::CallbackInfo& info) { return N_oc_set_factory_presets_cb(info); }


Napi::Function OCMain::GetClass(Napi::Env env) {
    return DefineClass(env, "OCMain", {
        OCMain::StaticMethod("main_init", &OCMain::main_init),
        OCMain::StaticMethod("main_shutdown", &OCMain::main_shutdown),
        OCMain::StaticMethod("set_factory_presets_handler", &OCMain::set_factory_presets_handler),
    });
}


Napi::Object module_init(Napi::Env env, Napi::Object exports);

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("IotivityLite", IotivityLite::GetClass(env));
    exports.Set("OCMain", OCMain::GetClass(env));
    return module_init(env, exports);
}

NODE_API_MODULE(addon, Init)

