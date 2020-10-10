#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>
#include <memory>

using namespace std;

/*
{
  "oc_ipv4_addr_t": {
    "address": "uint8_t",
    "port": "uint16_t"
  },
  "oc_ipv6_addr_t": {
    "address": "uint8_t",
    "port": "uint16_t",
    "scope": "uint8_t"
  },
  "oc_le_addr_t": {
    "address": "uint8_t",
    "type": "uint8_t"
  },
  "oc_endpoint_t::dev_addr": {
    "bt": "oc_le_addr_t",
    "ipv4": "oc_ipv4_addr_t",
    "ipv6": "oc_ipv6_addr_t"
  }
}
*/

class XOCIPv4Addr : public Napi::ObjectWrap<XOCIPv4Addr>
{
friend Napi::Object Init(Napi::Env env, Napi::Object exports);
public:
  static Napi::FunctionReference constructor;
  XOCIPv4Addr(const Napi::CallbackInfo&);

private:
  static Napi::Function GetClass(Napi::Env);
  Napi::Value get_address(const Napi::CallbackInfo&);
         void set_address(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_port(const Napi::CallbackInfo&);
         void set_port(const Napi::CallbackInfo&, const Napi::Value&);
  shared_ptr<oc_ipv4_addr_t> m_pvalue;
  //oc_ipv4_addr_t* value; //to be smart!
};

class XOCEndpointDevAddr : public Napi::ObjectWrap<XOCEndpointDevAddr>
{
friend Napi::Object Init(Napi::Env env, Napi::Object exports);

public:
  static Napi::FunctionReference constructor;
  XOCEndpointDevAddr(const Napi::CallbackInfo&);

private:
  Napi::Value get_ipv4(const Napi::CallbackInfo&);
         void set_ipv4(const Napi::CallbackInfo&, const Napi::Value&);
  static Napi::Function GetClass(Napi::Env);
//  shared_ptr<oc_ipv4_addr_t> ipv4;
  shared_ptr<oc_ipv6_addr_t> ipv6;
  shared_ptr<oc_le_addr_t> bt;
  shared_ptr<oc_endpoint_t::dev_addr> m_pvalue;
  //oc_endpoint_t::dev_addr *value; //to be smart!
};

class XOCUuid: public Napi::ObjectWrap<XOCUuid>
{
public:
    XOCUuid(const Napi::CallbackInfo&);
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
