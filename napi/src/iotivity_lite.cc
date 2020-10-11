#include "iotivity_lite.h"
#include "structs.h"
using namespace Napi;

Napi::FunctionReference XOCIPv4Addr::constructor;

XOCIPv4Addr::XOCIPv4Addr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = shared_ptr<oc_ipv4_addr_t>(new oc_ipv4_addr_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<External<shared_ptr<oc_ipv4_addr_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::Function XOCIPv4Addr::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "XOCIPv4Addr", {
    //XOCIPv4Addr::InstanceAccessor("addr", &XOCIPv4Addr::get_address, &XOCIPv4Addr::set_address),
    XOCIPv4Addr::InstanceAccessor("port", &XOCIPv4Addr::get_port, &XOCIPv4Addr::set_port),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}

Napi::Value XOCIPv4Addr::get_address(const Napi::CallbackInfo& info)
{
   auto array = Napi::Uint8Array::New(info.Env(), 4);
   array[0] = m_pvalue->address[0];
   array[1] = m_pvalue->address[1];
   array[2] = m_pvalue->address[2];
   array[3] = m_pvalue->address[3];
   return array;
}

Napi::Value XOCIPv4Addr::get_port(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->port);
}
void XOCIPv4Addr::set_port(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  this->m_pvalue->port = (uint32_t)info[0].As<Napi::Number>();
}


Napi::FunctionReference XOCUuid::constructor;


XOCEndpointDevAddr::XOCEndpointDevAddr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  printf("XOCIPv4Addr\n");
  m_pvalue = shared_ptr<oc_endpoint_t::dev_addr>(new oc_endpoint_t::dev_addr());
}
Napi::Function XOCEndpointDevAddr::GetClass(Napi::Env env)
{
  auto func = DefineClass(env, "XOCEndpointDevAddr", {
    XOCEndpointDevAddr::InstanceAccessor("ipv4", &XOCEndpointDevAddr::get_ipv4, &XOCEndpointDevAddr::set_ipv4),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}

Napi::FunctionReference XOCEndpointDevAddr::constructor;

Napi::Value XOCEndpointDevAddr::get_ipv4(const Napi::CallbackInfo& info)
{
  shared_ptr<oc_ipv4_addr_t> sp(&m_pvalue->ipv4);
  auto accessor = Napi::External<shared_ptr<oc_ipv4_addr_t>>::New(info.Env(), &sp);
  return XOCIPv4Addr::constructor.New({accessor});
}
void XOCEndpointDevAddr::set_ipv4(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ipv4 = *(*(value.As<External<shared_ptr<oc_ipv4_addr_t>>>().Data()));
}


XOCUuid::XOCUuid(const Napi::CallbackInfo& info) : ObjectWrap(info) {
	printf("XOCUuid\n");
}
/*
XOCUuid::XOCUuid(const Napi::Env& env, Napi::Object& wrapper) {
  //napi_env env = callbackInfo.Env();
  //napi_value wrapper = callbackInfo.This();
  napi_status status;
  napi_ref ref;
  XOCUuid* instance = static_cast<XOCUuid*>(this);
  status = napi_wrap(env, wrapper, instance, MyFinalizeCallback, nullptr, &ref);
  NAPI_THROW_IF_FAILED_VOID(env, status);

  Reference<Object>* instanceRef = instance;
  *instanceRef = Reference<Object>(env, ref);
}
*/

Napi::Function XOCUuid::GetClass(Napi::Env env) {
    Napi::Function func = DefineClass(env, "XOCUuid", {
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
    return XOCUuid::constructor.New({});
    //return Napi::Number::New(env, 0);
}

void IotivityLite::SetDi(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDi\n");
}


Napi::Object module_init(Napi::Env env, Napi::Object exports);

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("IotivityLite", IotivityLite::GetClass(env));
    exports.Set("OCUuid", OCUuid::GetClass(env));
    exports.Set("OCIPv4Addr", OCIPv4Addr::GetClass(env));
    exports.Set("DevAddr", DevAddr::GetClass(env));
    return module_init(env, exports);
}

NODE_API_MODULE(addon, Init)
