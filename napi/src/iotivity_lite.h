#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>
#include <memory>

using namespace std;

class IotivityLite : public Napi::ObjectWrap<IotivityLite>
{
public:
    IotivityLite(const Napi::CallbackInfo&);
    Napi::Value Greet(const Napi::CallbackInfo&);

    Napi::Value Callback(const Napi::CallbackInfo&);

    Napi::Value GetDevice(const Napi::CallbackInfo&);
    void SetDevice(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value GetDi(const Napi::CallbackInfo&);
    void SetDi(const Napi::CallbackInfo&, const Napi::Value&);

    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference callback_helper;

private:
    std::string _greeterName;
    oc_endpoint_t endpoint;
};

class OCMain : public Napi::ObjectWrap<OCMain>
{
public:
    OCMain(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::Value OCMain::main_init(const Napi::CallbackInfo& info);
    static Napi::Value OCMain::main_shutdown(const Napi::CallbackInfo& info);
};


