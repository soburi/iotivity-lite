#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>

class OCUuid: public Napi::ObjectWrap<OCUuid>
{
public:
    OCUuid(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);

    static Napi::FunctionReference constructor;

private:
    oc_uuid_t* uuid;
};

class IotivityLite : public Napi::ObjectWrap<IotivityLite>
{
public:
    IotivityLite(const Napi::CallbackInfo&);
    Napi::Value Greet(const Napi::CallbackInfo&);

    Napi::Value GetDevice(const Napi::CallbackInfo&);
    void SetDevice(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value GetDi(const Napi::CallbackInfo&);
    void SetDi(const Napi::CallbackInfo&, const Napi::Value&);

    static Napi::Function GetClass(Napi::Env);

private:
    std::string _greeterName;
    oc_endpoint_t endpoint;
};
