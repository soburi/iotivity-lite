#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>

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

class OCIPv4Addr : public Napi::ObjectWrap<OCIPv4Addr>
{
public:
  OCIPv4Addr(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;

private:
  Napi::Value get_address(const Napi::CallbackInfo&);
         void set_address(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_port(const Napi::CallbackInfo&);
         void set_port(const Napi::CallbackInfo&, const Napi::Value&);
  oc_ipv4_addr_t* value; //to be smart!
};

class OCEndpointDevAddr : public Napi::ObjectWrap<OCEndpointDevAddr>
{
public:
  OCEndpointDevAddr(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;

  Napi::Value get_ipv4(const Napi::CallbackInfo&);
         void set_ipv4(const Napi::CallbackInfo&, const Napi::Value&);

private:
  oc_endpoint_t::dev_addr *value; //to be smart!
};

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
