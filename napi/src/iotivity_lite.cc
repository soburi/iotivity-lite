#include "iotivity_lite.h"
#include "structs.h"
#include "functions.h"
#include "helper.h"
using namespace Napi;

Napi::Object module_init(Napi::Env env, Napi::Object exports);
Napi::Object Init(Napi::Env env, Napi::Object exports);
NODE_API_MODULE(addon, Init)

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("OCMain", OCMain::GetClass(env));
    exports.Set("OCObt", OCObt::GetClass(env));
    exports.Set("OCBufferSettings", OCBufferSettings::GetClass(env));
    exports.Set("OCClock", OCClock::GetClass(env));
    exports.Set("OCCloud", OCCloud::GetClass(env));
    exports.Set("OCCredUtil", OCCredUtil::GetClass(env));
    exports.Set("OCEndpointUtil", OCEndpointUtil::GetClass(env));
    exports.Set("OCEnumUtil", OCEnumUtil::GetClass(env));
    exports.Set("OCIntrospection", OCIntrospection::GetClass(env));
    exports.Set("OCPki", OCPki::GetClass(env));
    exports.Set("OCRandom", OCRandom::GetClass(env));
    exports.Set("OCSessionEvents", OCSessionEvents::GetClass(env));
    exports.Set("OCSoftwareUpdate", OCSoftwareUpdate::GetClass(env));
    exports.Set("OCStorage", OCStorage::GetClass(env));
    exports.Set("OCUuidUtil", OCUuidUtil::GetClass(env));
    exports.Set("OCCoreRes", OCCoreRes::GetClass(env));
    exports.Set("OCRep", OCRep::GetClass(env));
    return module_init(env, exports);
}
OCMain::OCMain(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCMain::GetClass(Napi::Env env) {
    return DefineClass(env, "OCMain", {
        OCMain::StaticMethod("add_collection", &OCMain::add_collection),
        OCMain::StaticMethod("add_device", &OCMain::add_device),
        OCMain::StaticMethod("add_ownership_status_cb", &OCMain::add_ownership_status_cb),
        OCMain::StaticMethod("add_resource", &OCMain::add_resource),
        OCMain::StaticMethod("assert_all_roles", &OCMain::assert_all_roles),
        OCMain::StaticMethod("assert_role", &OCMain::assert_role),
        OCMain::StaticMethod("auto_assert_roles", &OCMain::auto_assert_roles),
        OCMain::StaticMethod("close_session", &OCMain::close_session),
        OCMain::StaticMethod("collection_add_link", &OCMain::collection_add_link),
        OCMain::StaticMethod("collection_add_mandatory_rt", &OCMain::collection_add_mandatory_rt),
        OCMain::StaticMethod("collection_add_supported_rt", &OCMain::collection_add_supported_rt),
        OCMain::StaticMethod("collection_get_collections", &OCMain::collection_get_collections),
        OCMain::StaticMethod("collection_get_links", &OCMain::collection_get_links),
        OCMain::StaticMethod("collection_remove_link", &OCMain::collection_remove_link),
        OCMain::StaticMethod("delete_collection", &OCMain::delete_collection),
        OCMain::StaticMethod("delete_link", &OCMain::delete_link),
        OCMain::StaticMethod("delete_resource", &OCMain::delete_resource),
        OCMain::StaticMethod("device_bind_resource_type", &OCMain::device_bind_resource_type),
        OCMain::StaticMethod("do_delete", &OCMain::do_delete),
        OCMain::StaticMethod("do_get", &OCMain::do_get),
        OCMain::StaticMethod("do_ip_discovery", &OCMain::do_ip_discovery),
        OCMain::StaticMethod("do_ip_discovery_all", &OCMain::do_ip_discovery_all),
        OCMain::StaticMethod("do_ip_discovery_all_at_endpoint", &OCMain::do_ip_discovery_all_at_endpoint),
        OCMain::StaticMethod("do_ip_discovery_at_endpoint", &OCMain::do_ip_discovery_at_endpoint),
        OCMain::StaticMethod("do_ip_multicast", &OCMain::do_ip_multicast),
        OCMain::StaticMethod("do_observe", &OCMain::do_observe),
        OCMain::StaticMethod("do_post", &OCMain::do_post),
        OCMain::StaticMethod("do_put", &OCMain::do_put),
        OCMain::StaticMethod("do_realm_local_ipv6_discovery", &OCMain::do_realm_local_ipv6_discovery),
        OCMain::StaticMethod("do_realm_local_ipv6_discovery_all", &OCMain::do_realm_local_ipv6_discovery_all),
        OCMain::StaticMethod("do_realm_local_ipv6_multicast", &OCMain::do_realm_local_ipv6_multicast),
        OCMain::StaticMethod("do_site_local_ipv6_discovery", &OCMain::do_site_local_ipv6_discovery),
        OCMain::StaticMethod("do_site_local_ipv6_discovery_all", &OCMain::do_site_local_ipv6_discovery_all),
        OCMain::StaticMethod("do_site_local_ipv6_multicast", &OCMain::do_site_local_ipv6_multicast),
        OCMain::StaticMethod("free_server_endpoints", &OCMain::free_server_endpoints),
        OCMain::StaticMethod("get_all_roles", &OCMain::get_all_roles),
        OCMain::StaticMethod("get_con_res_announced", &OCMain::get_con_res_announced),
        OCMain::StaticMethod("ignore_request", &OCMain::ignore_request),
        OCMain::StaticMethod("indicate_separate_response", &OCMain::indicate_separate_response),
        OCMain::StaticMethod("init_platform", &OCMain::init_platform),
        OCMain::StaticMethod("init_post", &OCMain::init_post),
        OCMain::StaticMethod("init_put", &OCMain::init_put),
        OCMain::StaticMethod("is_owned_device", &OCMain::is_owned_device),
        OCMain::StaticMethod("link_add_link_param", &OCMain::link_add_link_param),
        OCMain::StaticMethod("link_add_rel", &OCMain::link_add_rel),
        OCMain::StaticMethod("main_init", &OCMain::main_init),
        OCMain::StaticMethod("main_loop", &OCMain::main_loop),
        OCMain::StaticMethod("main_shutdown", &OCMain::main_shutdown),
        OCMain::StaticMethod("new_collection", &OCMain::new_collection),
        OCMain::StaticMethod("new_link", &OCMain::new_link),
        OCMain::StaticMethod("new_resource", &OCMain::new_resource),
        OCMain::StaticMethod("notify_observers", &OCMain::notify_observers),
        OCMain::StaticMethod("process_baseline_interface", &OCMain::process_baseline_interface),
        OCMain::StaticMethod("remove_delayed_callback", &OCMain::remove_delayed_callback),
        OCMain::StaticMethod("remove_ownership_status_cb", &OCMain::remove_ownership_status_cb),
        OCMain::StaticMethod("reset", &OCMain::reset),
        OCMain::StaticMethod("reset_device", &OCMain::reset_device),
        OCMain::StaticMethod("resource_bind_resource_interface", &OCMain::resource_bind_resource_interface),
        OCMain::StaticMethod("resource_bind_resource_type", &OCMain::resource_bind_resource_type),
        OCMain::StaticMethod("resource_make_public", &OCMain::resource_make_public),
        OCMain::StaticMethod("resource_set_default_interface", &OCMain::resource_set_default_interface),
        OCMain::StaticMethod("resource_set_discoverable", &OCMain::resource_set_discoverable),
        OCMain::StaticMethod("resource_set_observable", &OCMain::resource_set_observable),
        OCMain::StaticMethod("resource_set_periodic_observable", &OCMain::resource_set_periodic_observable),
        OCMain::StaticMethod("resource_set_properties_cbs", &OCMain::resource_set_properties_cbs),
        OCMain::StaticMethod("resource_set_request_handler", &OCMain::resource_set_request_handler),
        OCMain::StaticMethod("ri_is_app_resource_valid", &OCMain::ri_is_app_resource_valid),
        OCMain::StaticMethod("send_diagnostic_message", &OCMain::send_diagnostic_message),
        OCMain::StaticMethod("send_ping", &OCMain::send_ping),
        OCMain::StaticMethod("send_response", &OCMain::send_response),
        OCMain::StaticMethod("send_response_raw", &OCMain::send_response_raw),
        OCMain::StaticMethod("send_separate_response", &OCMain::send_separate_response),
        OCMain::StaticMethod("set_con_res_announced", &OCMain::set_con_res_announced),
        OCMain::StaticMethod("set_con_write_cb", &OCMain::set_con_write_cb),
        OCMain::StaticMethod("set_delayed_callback", &OCMain::set_delayed_callback),
        OCMain::StaticMethod("set_factory_presets_cb", &OCMain::set_factory_presets_cb),
        OCMain::StaticMethod("set_random_pin_callback", &OCMain::set_random_pin_callback),
        OCMain::StaticMethod("set_separate_response_buffer", &OCMain::set_separate_response_buffer),
        OCMain::StaticMethod("stop_multicast", &OCMain::stop_multicast),
        OCMain::StaticMethod("stop_observe", &OCMain::stop_observe),
    });
}

Napi::Value OCMain::add_collection(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_add_collection(collection);
  return info.Env().Undefined();
}

Napi::Value OCMain::add_device(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string rt_ = info[1].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  std::string name_ = info[2].As<Napi::String>().Utf8Value();
  const char* name = name_.c_str();
  std::string spec_version_ = info[3].As<Napi::String>().Utf8Value();
  const char* spec_version = spec_version_.c_str();
  std::string data_model_version_ = info[4].As<Napi::String>().Utf8Value();
  const char* data_model_version = data_model_version_.c_str();
  oc_add_device_cb_t add_device_cb = oc_add_device_helper;
callback_helper_t* data = new_callback_helper_t(info, 5, 6);
if(!data) add_device_cb = nullptr;
  return Napi::Number::New(info.Env(), oc_add_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data));
}

#if defined(OC_SECURITY)
Napi::Value OCMain::add_ownership_status_cb(const Napi::CallbackInfo& info) {
  oc_ownership_status_cb_t cb = helper_oc_ownership_status_cb; if(!info[0].IsFunction()) { cb = nullptr; }
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[0].As<Napi::Function>(), info[1]);
  (void)oc_add_ownership_status_cb(cb, user_data);
  return info.Env().Undefined();
}
#endif

Napi::Value OCMain::add_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_add_resource(resource));
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCMain::assert_all_roles(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[1].IsFunction()) { handler = nullptr; }
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[1].As<Napi::Function>(), info[2]);
  (void)oc_assert_all_roles(endpoint, handler, user_data);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCMain::assert_role(const Napi::CallbackInfo& info) {
  std::string role_ = info[0].As<Napi::String>().Utf8Value();
  const char* role = role_.c_str();
  std::string authority_ = info[1].As<Napi::String>().Utf8Value();
  const char* authority = authority_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[4]);
  return Napi::Boolean::New(info.Env(), oc_assert_role(role, authority, endpoint, handler, user_data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCMain::auto_assert_roles(const Napi::CallbackInfo& info) {
  bool auto_assert = info[0].As<Napi::Boolean>().Value();
  (void)oc_auto_assert_roles(auto_assert);
  return info.Env().Undefined();
}
#endif

Napi::Value OCMain::close_session(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_close_session(endpoint);
  return info.Env().Undefined();
}

Napi::Value OCMain::collection_add_link(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCLink& link = *OCLink::Unwrap(info[1].As<Napi::Object>());
  (void)oc_collection_add_link(collection, link);
  return info.Env().Undefined();
}

Napi::Value OCMain::collection_add_mandatory_rt(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string rt_ = info[1].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  return Napi::Boolean::New(info.Env(), oc_collection_add_mandatory_rt(collection, rt));
}

Napi::Value OCMain::collection_add_supported_rt(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string rt_ = info[1].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  return Napi::Boolean::New(info.Env(), oc_collection_add_supported_rt(collection, rt));
}

Napi::Value OCMain::collection_get_collections(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_collection_get_collections());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value OCMain::collection_get_links(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_link_t> sp(oc_collection_get_links(collection));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value OCMain::collection_remove_link(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCLink& link = *OCLink::Unwrap(info[1].As<Napi::Object>());
  (void)oc_collection_remove_link(collection, link);
  return info.Env().Undefined();
}

Napi::Value OCMain::delete_collection(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_delete_collection(collection);
  return info.Env().Undefined();
}

Napi::Value OCMain::delete_link(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  (void)oc_delete_link(link);
  return info.Env().Undefined();
}

Napi::Value OCMain::delete_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_delete_resource(resource));
}

Napi::Value OCMain::device_bind_resource_type(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string type_ = info[1].As<Napi::String>().Utf8Value();
  const char* type = type_.c_str();
  (void)oc_device_bind_resource_type(device, type);
  return info.Env().Undefined();
}

Napi::Value OCMain::do_delete(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  const char* query = nullptr; if (info[2].IsString()) { query = info[2].As<Napi::String>().Utf8Value().c_str(); }
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[5]);
  return Napi::Boolean::New(info.Env(), oc_do_delete(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value OCMain::do_get(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  const char* query = nullptr; if (info[2].IsString()) { query = info[2].As<Napi::String>().Utf8Value().c_str(); }
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[5]);
  return Napi::Boolean::New(info.Env(), oc_do_get(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value OCMain::do_ip_discovery(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = helper_oc_discovery_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[1].As<Napi::Function>(), info[2]);
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery(rt, handler, user_data));
}

Napi::Value OCMain::do_ip_discovery_all(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = helper_oc_discovery_all_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[0].As<Napi::Function>(), info[1]);
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_all(handler, user_data));
}

Napi::Value OCMain::do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = helper_oc_discovery_all_handler;
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[0].As<Napi::Function>(), info[2]);
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_all_at_endpoint(handler, endpoint, user_data));
}

Napi::Value OCMain::do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = helper_oc_discovery_handler;
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[1].As<Napi::Function>(), info[3]);
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, user_data));
}

Napi::Value OCMain::do_ip_multicast(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string query_ = info[1].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = helper_oc_response_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[2].As<Napi::Function>(), info[3]);
  return Napi::Boolean::New(info.Env(), oc_do_ip_multicast(uri, query, handler, user_data));
}

Napi::Value OCMain::do_observe(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  const char* query = nullptr; if (info[2].IsString()) { query = info[2].As<Napi::String>().Utf8Value().c_str(); }
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[5]);
  return Napi::Boolean::New(info.Env(), oc_do_observe(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value OCMain::do_post(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_do_post());
}

Napi::Value OCMain::do_put(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_do_put());
}

Napi::Value OCMain::do_realm_local_ipv6_discovery(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = helper_oc_discovery_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[1].As<Napi::Function>(), info[2]);
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery(rt, handler, user_data));
}

Napi::Value OCMain::do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = helper_oc_discovery_all_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[0].As<Napi::Function>(), info[1]);
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery_all(handler, user_data));
}

Napi::Value OCMain::do_realm_local_ipv6_multicast(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string query_ = info[1].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = helper_oc_response_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[2].As<Napi::Function>(), info[3]);
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_multicast(uri, query, handler, user_data));
}

Napi::Value OCMain::do_site_local_ipv6_discovery(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = helper_oc_discovery_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[1].As<Napi::Function>(), info[2]);
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery(rt, handler, user_data));
}

Napi::Value OCMain::do_site_local_ipv6_discovery_all(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = helper_oc_discovery_all_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[0].As<Napi::Function>(), info[1]);
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery_all(handler, user_data));
}

Napi::Value OCMain::do_site_local_ipv6_multicast(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string query_ = info[1].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = helper_oc_response_handler;
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[2].As<Napi::Function>(), info[3]);
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_multicast(uri, query, handler, user_data));
}

Napi::Value OCMain::free_server_endpoints(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_free_server_endpoints(endpoint);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCMain::get_all_roles(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_role_t> sp(oc_get_all_roles());
  auto args = Napi::External<std::shared_ptr<oc_role_t>>::New(info.Env(), &sp);
  return OCRole::constructor.New({args});
}
#endif

Napi::Value OCMain::get_con_res_announced(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_get_con_res_announced());
}

Napi::Value OCMain::ignore_request(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  (void)oc_ignore_request(request);
  return info.Env().Undefined();
}

Napi::Value OCMain::indicate_separate_response(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  OCSeparateResponse& response = *OCSeparateResponse::Unwrap(info[1].As<Napi::Object>());
  (void)oc_indicate_separate_response(request, response);
  return info.Env().Undefined();
}

Napi::Value OCMain::init_platform(const Napi::CallbackInfo& info) {
  std::string mfg_name_ = info[0].As<Napi::String>().Utf8Value();
  const char* mfg_name = mfg_name_.c_str();
  oc_init_platform_cb_t init_platform_cb = oc_init_platform_helper;
callback_helper_t* data = new_callback_helper_t(info, 1, 2);
if(!data) init_platform_cb = nullptr;
  return Napi::Number::New(info.Env(), oc_init_platform(mfg_name, init_platform_cb, data));
}

Napi::Value OCMain::init_post(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  const char* query = nullptr; if (info[2].IsString()) { query = info[2].As<Napi::String>().Utf8Value().c_str(); }
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[5]);
  return Napi::Boolean::New(info.Env(), oc_init_post(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value OCMain::init_put(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  const char* query = nullptr; if (info[2].IsString()) { query = info[2].As<Napi::String>().Utf8Value().c_str(); }
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[5]);
  return Napi::Boolean::New(info.Env(), oc_init_put(uri, endpoint, query, handler, qos, user_data));
}

#if defined(OC_SECURITY)
Napi::Value OCMain::is_owned_device(const Napi::CallbackInfo& info) {
  size_t device_index = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_is_owned_device(device_index));
}
#endif

Napi::Value OCMain::link_add_link_param(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::string value_ = info[2].As<Napi::String>().Utf8Value();
  const char* value = value_.c_str();
  (void)oc_link_add_link_param(link, key, value);
  return info.Env().Undefined();
}

Napi::Value OCMain::link_add_rel(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  std::string rel_ = info[1].As<Napi::String>().Utf8Value();
  const char* rel = rel_.c_str();
  (void)oc_link_add_rel(link, rel);
  return info.Env().Undefined();
}

Napi::Value OCMain::main_init(const Napi::CallbackInfo& info) {
  OCHandler& handler = *OCHandler::Unwrap(info[0].As<Napi::Object>());
//
  struct main_context_t* mainctx = new main_context_t();

  handler.m_pvalue->signal_event_loop = helper_oc_handler_signal_event_loop;
  handler.m_pvalue->init = nullptr;
  handler.m_pvalue->register_resources = nullptr;
  handler.m_pvalue->requests_entry = nullptr;
  if(handler.init.Value().IsFunction() ) {
    mainctx->oc_handler_init_ref.Reset(handler.init.Value());
    handler.m_pvalue->init = helper_oc_handler_init;
  }
  else {
    Napi::TypeError::New(info.Env(), "init callback is not set.").ThrowAsJavaScriptException();
  }
  if(handler.register_resources.Value().IsFunction() ) {
    mainctx->oc_handler_register_resources_ref.Reset(handler.register_resources.Value());
    handler.m_pvalue->register_resources = helper_oc_handler_register_resources;
  }
  if(handler.requests_entry.Value().IsFunction() ) {
    mainctx->oc_handler_requests_entry_ref.Reset(handler.requests_entry.Value());
    handler.m_pvalue->requests_entry = helper_oc_handler_requests_entry;
  }

  try {
    mainctx->helper_poll_event_thread = std::thread(helper_poll_event_thread, mainctx);
    mainctx->helper_poll_event_thread.detach();
  }
  catch(system_error) {
    Napi::TypeError::New(info.Env(), "Fail to initialize poll_event thread.").ThrowAsJavaScriptException();
  }

  return Napi::Number::New(info.Env(), oc_main_init(handler));

}
extern main_loop_t* main_loop_ctx;
Napi::Value OCMain::main_loop(const Napi::CallbackInfo& info) {
//
  main_loop_ctx = new main_loop_t{ Napi::Promise::Deferred::New(info.Env()),
                               Napi::ThreadSafeFunction::New(info.Env(), Napi::Function::New(info.Env(), [](const Napi::CallbackInfo& info) {
  main_loop_ctx->deferred.Resolve(info.Env().Undefined() );
  delete main_loop_ctx;
  main_loop_ctx = nullptr;
  }), "main_loop_resolve", 0, 1) };
  return main_loop_ctx->deferred.Promise();

}

Napi::Value OCMain::main_shutdown(const Napi::CallbackInfo& info) {
  terminate_main_loop();
  (void)oc_main_shutdown();
  return info.Env().Undefined();
}

Napi::Value OCMain::new_collection(const Napi::CallbackInfo& info) {
  std::string name_ = info[0].As<Napi::String>().Utf8Value();
  const char* name = name_.c_str();
  std::string uri_ = info[1].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  uint8_t num_resource_types = static_cast<uint8_t>(info[2].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_new_collection(name, uri, num_resource_types, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value OCMain::new_link(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_link_t> sp(oc_new_link(resource));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value OCMain::new_resource(const Napi::CallbackInfo& info) {
  std::string name_ = info[0].As<Napi::String>().Utf8Value();
  const char* name = name_.c_str();
  std::string uri_ = info[1].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  uint8_t num_resource_types = static_cast<uint8_t>(info[2].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_new_resource(name, uri, num_resource_types, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value OCMain::notify_observers(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_notify_observers(resource));
}

Napi::Value OCMain::process_baseline_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_process_baseline_interface(resource);
  return info.Env().Undefined();
}

Napi::Value OCMain::remove_delayed_callback(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t callback = nullptr;
  Napi::Function callback_ = info[1].As<Napi::Function>();
  (void)oc_remove_delayed_callback(cb_data, callback);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value OCMain::remove_ownership_status_cb(const Napi::CallbackInfo& info) {
  oc_ownership_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  (void)oc_remove_ownership_status_cb(cb, user_data);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCMain::reset(const Napi::CallbackInfo& info) {
  (void)oc_reset();
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCMain::reset_device(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_reset_device(device);
  return info.Env().Undefined();
}
#endif

Napi::Value OCMain::resource_bind_resource_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_bind_resource_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value OCMain::resource_bind_resource_type(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string type_ = info[1].As<Napi::String>().Utf8Value();
  const char* type = type_.c_str();
  (void)oc_resource_bind_resource_type(resource, type);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value OCMain::resource_make_public(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_resource_make_public(resource);
  return info.Env().Undefined();
}
#endif

Napi::Value OCMain::resource_set_default_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_default_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value OCMain::resource_set_discoverable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_discoverable(resource, state);
  return info.Env().Undefined();
}

Napi::Value OCMain::resource_set_observable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_observable(resource, state);
  return info.Env().Undefined();
}

Napi::Value OCMain::resource_set_periodic_observable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  uint16_t seconds = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_periodic_observable(resource, seconds);
  return info.Env().Undefined();
}

Napi::Value OCMain::resource_set_properties_cbs(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_get_properties_cb_t get_properties = oc_resource_set_properties_cbs_get_helper;
//
  callback_helper_t* get_propr_user_data = new_callback_helper_t(info, 1, 2);
  if(!get_propr_user_data) get_properties = nullptr;
  oc_set_properties_cb_t set_properties = oc_resource_set_properties_cbs_set_helper;
//
  callback_helper_t* set_props_user_data = new_callback_helper_t(info, 3, 4);
  if(!set_props_user_data) set_properties = nullptr;
  (void)oc_resource_set_properties_cbs(resource, get_properties, get_propr_user_data, set_properties, set_props_user_data);
  return info.Env().Undefined();
}

Napi::Value OCMain::resource_set_request_handler(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_request_callback_t callback = nullptr;
callback_helper_t* user_data = new_callback_helper_t(info, 2, 3);
if(!user_data) callback = nullptr;
  (void)oc_resource_set_request_handler(resource, method, callback, user_data);
  return info.Env().Undefined();
}

Napi::Value OCMain::ri_is_app_resource_valid(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_is_app_resource_valid(resource));
}

Napi::Value OCMain::send_diagnostic_message(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  std::string msg_ = info[1].As<Napi::String>().Utf8Value();
  const char* msg = msg_.c_str();
  size_t msg_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_status_t response_code = static_cast<oc_status_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)oc_send_diagnostic_message(request, msg, msg_len, response_code);
  return info.Env().Undefined();
}

#if defined(OC_TCP)
Napi::Value OCMain::send_ping(const Napi::CallbackInfo& info) {
  bool custody = info[0].As<Napi::Boolean>().Value();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  uint16_t timeout_seconds = static_cast<uint16_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_response_handler_t handler = helper_oc_response_handler; if(!info[3].IsFunction()) { handler = nullptr; }
  SafeCallbackHelper* user_data = new SafeCallbackHelper(info[3].As<Napi::Function>(), info[4]);
  return Napi::Boolean::New(info.Env(), oc_send_ping(custody, endpoint, timeout_seconds, handler, user_data));
}
#endif

Napi::Value OCMain::send_response(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  oc_status_t response_code = static_cast<oc_status_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_send_response(request, response_code);
  return info.Env().Undefined();
}

Napi::Value OCMain::send_response_raw(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  const uint8_t* payload = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_content_format_t content_format = static_cast<oc_content_format_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_status_t response_code = static_cast<oc_status_t>(info[4].As<Napi::Number>().Uint32Value());
  (void)oc_send_response_raw(request, payload, size, content_format, response_code);
  return info.Env().Undefined();
}

Napi::Value OCMain::send_separate_response(const Napi::CallbackInfo& info) {
  OCSeparateResponse& handle = *OCSeparateResponse::Unwrap(info[0].As<Napi::Object>());
  oc_status_t response_code = static_cast<oc_status_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_send_separate_response(handle, response_code);
  return info.Env().Undefined();
}

Napi::Value OCMain::set_con_res_announced(const Napi::CallbackInfo& info) {
  bool announce = info[0].As<Napi::Boolean>().Value();
  (void)oc_set_con_res_announced(announce);
  return info.Env().Undefined();
}

Napi::Value OCMain::set_con_write_cb(const Napi::CallbackInfo& info) {
  oc_con_write_cb_t callback = nullptr;
  Napi::Function callback_ = info[0].As<Napi::Function>();
  (void)oc_set_con_write_cb(callback);
  return info.Env().Undefined();
}

Napi::Value OCMain::set_delayed_callback(const Napi::CallbackInfo& info) {
  SafeCallbackHelper* cb_data = new SafeCallbackHelper(info[1].As<Napi::Function>(), info[0]);
  oc_trigger_t callback = helper_oc_trigger; if(!info[1].IsFunction()) { callback = nullptr; }
  uint16_t seconds = static_cast<uint16_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_set_delayed_callback(cb_data, callback, seconds);
  return info.Env().Undefined();
}

Napi::Value OCMain::set_factory_presets_cb(const Napi::CallbackInfo& info) {
  oc_factory_presets_cb_t cb = helper_oc_factory_presets_cb; if(!info[0].IsFunction()) { cb = nullptr; }
  void* data = info[1];
  (void)oc_set_factory_presets_cb(cb, data);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value OCMain::set_random_pin_callback(const Napi::CallbackInfo& info) {
  oc_random_pin_cb_t cb = helper_oc_random_pin_cb; if(!info[0].IsFunction()) { cb = nullptr; }
  void* data = info[1];
  (void)oc_set_random_pin_callback(cb, data);
  return info.Env().Undefined();
}
#endif

Napi::Value OCMain::set_separate_response_buffer(const Napi::CallbackInfo& info) {
  OCSeparateResponse& handle = *OCSeparateResponse::Unwrap(info[0].As<Napi::Object>());
  (void)oc_set_separate_response_buffer(handle);
  return info.Env().Undefined();
}

Napi::Value OCMain::stop_multicast(const Napi::CallbackInfo& info) {
  OCClientResponse& response = *OCClientResponse::Unwrap(info[0].As<Napi::Object>());
  (void)oc_stop_multicast(response);
  return info.Env().Undefined();
}

Napi::Value OCMain::stop_observe(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_stop_observe(uri, endpoint));
}

Napi::FunctionReference OCMain::constructor;

OCObt::OCObt(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCObt::GetClass(Napi::Env env) {
    return DefineClass(env, "OCObt", {
        OCObt::StaticMethod("ace_add_permission", &OCObt::ace_add_permission),
        OCObt::StaticMethod("ace_new_resource", &OCObt::ace_new_resource),
        OCObt::StaticMethod("ace_resource_set_href", &OCObt::ace_resource_set_href),
        OCObt::StaticMethod("ace_resource_set_wc", &OCObt::ace_resource_set_wc),
        OCObt::StaticMethod("add_roleid", &OCObt::add_roleid),
        OCObt::StaticMethod("delete_ace_by_aceid", &OCObt::delete_ace_by_aceid),
        OCObt::StaticMethod("delete_cred_by_credid", &OCObt::delete_cred_by_credid),
        OCObt::StaticMethod("delete_own_cred_by_credid", &OCObt::delete_own_cred_by_credid),
        OCObt::StaticMethod("device_hard_reset", &OCObt::device_hard_reset),
        OCObt::StaticMethod("discover_all_resources", &OCObt::discover_all_resources),
        OCObt::StaticMethod("discover_owned_devices", &OCObt::discover_owned_devices),
        OCObt::StaticMethod("discover_owned_devices_realm_local_ipv6", &OCObt::discover_owned_devices_realm_local_ipv6),
        OCObt::StaticMethod("discover_owned_devices_site_local_ipv6", &OCObt::discover_owned_devices_site_local_ipv6),
        OCObt::StaticMethod("discover_unowned_devices", &OCObt::discover_unowned_devices),
        OCObt::StaticMethod("discover_unowned_devices_realm_local_ipv6", &OCObt::discover_unowned_devices_realm_local_ipv6),
        OCObt::StaticMethod("discover_unowned_devices_site_local_ipv6", &OCObt::discover_unowned_devices_site_local_ipv6),
        OCObt::StaticMethod("free_ace", &OCObt::free_ace),
        OCObt::StaticMethod("free_acl", &OCObt::free_acl),
        OCObt::StaticMethod("free_creds", &OCObt::free_creds),
        OCObt::StaticMethod("free_roleid", &OCObt::free_roleid),
        OCObt::StaticMethod("init", &OCObt::init),
        OCObt::StaticMethod("new_ace_for_connection", &OCObt::new_ace_for_connection),
        OCObt::StaticMethod("new_ace_for_role", &OCObt::new_ace_for_role),
        OCObt::StaticMethod("new_ace_for_subject", &OCObt::new_ace_for_subject),
        OCObt::StaticMethod("perform_cert_otm", &OCObt::perform_cert_otm),
        OCObt::StaticMethod("perform_just_works_otm", &OCObt::perform_just_works_otm),
        OCObt::StaticMethod("perform_random_pin_otm", &OCObt::perform_random_pin_otm),
        OCObt::StaticMethod("provision_ace", &OCObt::provision_ace),
        OCObt::StaticMethod("provision_auth_wildcard_ace", &OCObt::provision_auth_wildcard_ace),
        OCObt::StaticMethod("provision_identity_certificate", &OCObt::provision_identity_certificate),
        OCObt::StaticMethod("provision_pairwise_credentials", &OCObt::provision_pairwise_credentials),
        OCObt::StaticMethod("provision_role_certificate", &OCObt::provision_role_certificate),
        OCObt::StaticMethod("provision_role_wildcard_ace", &OCObt::provision_role_wildcard_ace),
        OCObt::StaticMethod("request_random_pin", &OCObt::request_random_pin),
        OCObt::StaticMethod("retrieve_acl", &OCObt::retrieve_acl),
        OCObt::StaticMethod("retrieve_creds", &OCObt::retrieve_creds),
        OCObt::StaticMethod("retrieve_own_creds", &OCObt::retrieve_own_creds),
        OCObt::StaticMethod("set_sd_info", &OCObt::set_sd_info),
        OCObt::StaticMethod("shutdown", &OCObt::shutdown),
    });
}

#if defined(OC_SECURITY)
Napi::Value OCObt::ace_add_permission(const Napi::CallbackInfo& info) {
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[0].As<Napi::Object>());
  oc_ace_permissions_t permission = static_cast<oc_ace_permissions_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_obt_ace_add_permission(ace, permission);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::ace_new_resource(const Napi::CallbackInfo& info) {
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_ace_res_t> sp(oc_obt_ace_new_resource(ace));
  auto args = Napi::External<std::shared_ptr<oc_ace_res_t>>::New(info.Env(), &sp);
  return OCAceResource::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::ace_resource_set_href(const Napi::CallbackInfo& info) {
  OCAceResource& resource = *OCAceResource::Unwrap(info[0].As<Napi::Object>());
  std::string href_ = info[1].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  (void)oc_obt_ace_resource_set_href(resource, href);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::ace_resource_set_wc(const Napi::CallbackInfo& info) {
  OCAceResource& resource = *OCAceResource::Unwrap(info[0].As<Napi::Object>());
  oc_ace_wildcard_t wc = static_cast<oc_ace_wildcard_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_obt_ace_resource_set_wc(resource, wc);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCObt::add_roleid(const Napi::CallbackInfo& info) {
  OCRole& roles = *OCRole::Unwrap(info[0].As<Napi::Object>());
  std::string role_ = info[1].As<Napi::String>().Utf8Value();
  const char* role = role_.c_str();
  std::string authority_ = info[2].As<Napi::String>().Utf8Value();
  const char* authority = authority_.c_str();
  std::shared_ptr<oc_role_t> sp(oc_obt_add_roleid(roles, role, authority));
  auto args = Napi::External<std::shared_ptr<oc_role_t>>::New(info.Env(), &sp);
  return OCRole::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::delete_ace_by_aceid(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  int aceid = static_cast<int>(info[1].As<Napi::Number>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_delete_ace_by_aceid(uuid, aceid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::delete_cred_by_credid(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  int credid = static_cast<int>(info[1].As<Napi::Number>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_delete_cred_by_credid(uuid, credid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::delete_own_cred_by_credid(const Napi::CallbackInfo& info) {
  int credid = static_cast<int>(info[0].As<Napi::Number>());
  return Napi::Number::New(info.Env(), oc_obt_delete_own_cred_by_credid(credid));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::device_hard_reset(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_device_hard_reset(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_all_resources(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_discover_all_resources(uuid, handler, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_owned_devices(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_unowned_devices(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::free_ace(const Napi::CallbackInfo& info) {
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_ace(ace);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::free_acl(const Napi::CallbackInfo& info) {
  OCSecurityAcl& acl = *OCSecurityAcl::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_acl(acl);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::free_creds(const Napi::CallbackInfo& info) {
  OCCreds& creds = *OCCreds::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_creds(creds);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCObt::free_roleid(const Napi::CallbackInfo& info) {
  OCRole& roles = *OCRole::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_roleid(roles);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::init(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_obt_init());
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::new_ace_for_connection(const Napi::CallbackInfo& info) {
  oc_ace_connection_type_t conn = static_cast<oc_ace_connection_type_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_connection(conn));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::new_ace_for_role(const Napi::CallbackInfo& info) {
  std::string role_ = info[0].As<Napi::String>().Utf8Value();
  const char* role = role_.c_str();
  std::string authority_ = info[1].As<Napi::String>().Utf8Value();
  const char* authority = authority_.c_str();
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_role(role, authority));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::new_ace_for_subject(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_subject(uuid));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCObt::perform_cert_otm(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_perform_cert_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::perform_just_works_otm(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_perform_just_works_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::perform_random_pin_otm(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  const unsigned char* pin = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t pin_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[3].As<Napi::Function>();
  void* data = info[4];
  return Napi::Number::New(info.Env(), oc_obt_perform_random_pin_otm(uuid, pin, pin_len, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::provision_ace(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[1].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_ace(subject, ace, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::provision_auth_wildcard_ace(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_provision_auth_wildcard_ace(subject, cb, data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCObt::provision_identity_certificate(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_provision_identity_certificate(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::provision_pairwise_credentials(const Napi::CallbackInfo& info) {
  OCUuid& uuid1 = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  OCUuid& uuid2 = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_pairwise_credentials(uuid1, uuid2, cb, data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCObt::provision_role_certificate(const Napi::CallbackInfo& info) {
  OCRole& roles = *OCRole::Unwrap(info[0].As<Napi::Object>());
  OCUuid& uuid = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_role_certificate(roles, uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::provision_role_wildcard_ace(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  std::string role_ = info[1].As<Napi::String>().Utf8Value();
  const char* role = role_.c_str();
  std::string authority_ = info[2].As<Napi::String>().Utf8Value();
  const char* authority = authority_.c_str();
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[3].As<Napi::Function>();
  void* data = info[4];
  return Napi::Number::New(info.Env(), oc_obt_provision_role_wildcard_ace(subject, role, authority, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::request_random_pin(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_request_random_pin(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::retrieve_acl(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_acl_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_retrieve_acl(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::retrieve_creds(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_creds_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_retrieve_creds(subject, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::retrieve_own_creds(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_sec_creds_t> sp(oc_obt_retrieve_own_creds());
  auto args = Napi::External<std::shared_ptr<oc_sec_creds_t>>::New(info.Env(), &sp);
  return OCCreds::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::set_sd_info(const Napi::CallbackInfo& info) {
  char* name = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  bool priv = info[1].As<Napi::Boolean>().Value();
  (void)oc_obt_set_sd_info(name, priv);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCObt::shutdown(const Napi::CallbackInfo& info) {
  (void)oc_obt_shutdown();
  return info.Env().Undefined();
}
#endif

Napi::FunctionReference OCObt::constructor;

OCBufferSettings::OCBufferSettings(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCBufferSettings::GetClass(Napi::Env env) {
    return DefineClass(env, "OCBufferSettings", {
        OCBufferSettings::StaticMethod("set_mtu_size", &OCBufferSettings::set_mtu_size),
        OCBufferSettings::StaticMethod("get_mtu_size", &OCBufferSettings::get_mtu_size),
        OCBufferSettings::StaticMethod("set_max_app_data_size", &OCBufferSettings::set_max_app_data_size),
        OCBufferSettings::StaticMethod("get_max_app_data_size", &OCBufferSettings::get_max_app_data_size),
        OCBufferSettings::StaticMethod("get_block_size", &OCBufferSettings::get_block_size),
    });
}

Napi::Value OCBufferSettings::set_mtu_size(const Napi::CallbackInfo& info) {
  size_t mtu_size = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_set_mtu_size(mtu_size));
}

Napi::Value OCBufferSettings::get_mtu_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_get_mtu_size());
}

Napi::Value OCBufferSettings::set_max_app_data_size(const Napi::CallbackInfo& info) {
  size_t size = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_set_max_app_data_size(size);
  return info.Env().Undefined();
}

Napi::Value OCBufferSettings::get_max_app_data_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_get_max_app_data_size());
}

Napi::Value OCBufferSettings::get_block_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_get_block_size());
}

Napi::FunctionReference OCBufferSettings::constructor;

OCClock::OCClock(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCClock::GetClass(Napi::Env env) {
    return DefineClass(env, "OCClock", {
        OCClock::StaticMethod("clock_init", &OCClock::clock_init),
        OCClock::StaticMethod("clock_time", &OCClock::clock_time),
        OCClock::StaticMethod("clock_seconds", &OCClock::clock_seconds),
        OCClock::StaticMethod("clock_wait", &OCClock::clock_wait),
    });
}

Napi::Value OCClock::clock_init(const Napi::CallbackInfo& info) {
  (void)oc_clock_init();
  return info.Env().Undefined();
}

Napi::Value OCClock::clock_time(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_clock_time());
}

Napi::Value OCClock::clock_seconds(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_clock_seconds());
}

Napi::Value OCClock::clock_wait(const Napi::CallbackInfo& info) {
  oc_clock_time_t t = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
  (void)oc_clock_wait(t);
  return info.Env().Undefined();
}

Napi::FunctionReference OCClock::constructor;

OCCloud::OCCloud(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCloud::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCloud", {
        OCCloud::StaticMethod("get_context", &OCCloud::get_context),
        OCCloud::StaticMethod("manager_start", &OCCloud::manager_start),
        OCCloud::StaticMethod("manager_stop", &OCCloud::manager_stop),
        OCCloud::StaticMethod("login", &OCCloud::login),
        OCCloud::StaticMethod("logout", &OCCloud::logout),
        OCCloud::StaticMethod("refresh_token", &OCCloud::refresh_token),
        OCCloud::StaticMethod("get_token_expiry", &OCCloud::get_token_expiry),
        OCCloud::StaticMethod("add_resource", &OCCloud::add_resource),
        OCCloud::StaticMethod("delete_resource", &OCCloud::delete_resource),
        OCCloud::StaticMethod("publish_resources", &OCCloud::publish_resources),
        OCCloud::StaticMethod("discover_resources", &OCCloud::discover_resources),
        OCCloud::StaticMethod("provision_conf_resource", &OCCloud::provision_conf_resource),
    });
}

#if defined(OC_CLOUD)
Napi::Value OCCloud::get_context(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_cloud_context_t> sp(oc_cloud_get_context(device));
  auto args = Napi::External<std::shared_ptr<oc_cloud_context_t>>::New(info.Env(), &sp);
  return OCCloudContext::constructor.New({args});
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::manager_start(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_manager_start(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::manager_stop(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cloud_manager_stop(ctx));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::login(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_login(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::logout(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_logout(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::refresh_token(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_refresh_token(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::get_token_expiry(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cloud_get_token_expiry(ctx));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::add_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cloud_add_resource(resource));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::delete_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_cloud_delete_resource(resource);
  return info.Env().Undefined();
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::publish_resources(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_cloud_publish_resources(device));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::discover_resources(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_discover_resources(ctx, handler, user_data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCloud::provision_conf_resource(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  std::string server_ = info[1].As<Napi::String>().Utf8Value();
  const char* server = server_.c_str();
  std::string access_token_ = info[2].As<Napi::String>().Utf8Value();
  const char* access_token = access_token_.c_str();
  std::string server_id_ = info[3].As<Napi::String>().Utf8Value();
  const char* server_id = server_id_.c_str();
  std::string auth_provider_ = info[4].As<Napi::String>().Utf8Value();
  const char* auth_provider = auth_provider_.c_str();
  return Napi::Number::New(info.Env(), oc_cloud_provision_conf_resource(ctx, server, access_token, server_id, auth_provider));
}
#endif

Napi::FunctionReference OCCloud::constructor;

OCCredUtil::OCCredUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCredUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCredUtil", {
        OCCredUtil::StaticMethod("read_credusage", &OCCredUtil::read_credusage),
        OCCredUtil::StaticMethod("read_encoding", &OCCredUtil::read_encoding),
        OCCredUtil::StaticMethod("parse_credusage", &OCCredUtil::parse_credusage),
        OCCredUtil::StaticMethod("parse_encoding", &OCCredUtil::parse_encoding),
        OCCredUtil::StaticMethod("credtype_string", &OCCredUtil::credtype_string),
    });
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCCredUtil::read_credusage(const Napi::CallbackInfo& info) {
  oc_sec_credusage_t credusage = static_cast<oc_sec_credusage_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_cred_read_credusage(credusage));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCredUtil::read_encoding(const Napi::CallbackInfo& info) {
  oc_sec_encoding_t encoding = static_cast<oc_sec_encoding_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_cred_read_encoding(encoding));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCCredUtil::parse_credusage(const Napi::CallbackInfo& info) {
  OCMmem& credusage_string = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cred_parse_credusage(credusage_string));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCredUtil::parse_encoding(const Napi::CallbackInfo& info) {
  OCMmem& encoding_string = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cred_parse_encoding(encoding_string));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCredUtil::credtype_string(const Napi::CallbackInfo& info) {
  oc_sec_credtype_t credtype = static_cast<oc_sec_credtype_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_cred_credtype_string(credtype));
}
#endif

Napi::FunctionReference OCCredUtil::constructor;

OCEndpointUtil::OCEndpointUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCEndpointUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCEndpointUtil", {
        OCEndpointUtil::StaticMethod("to_string", &OCEndpointUtil::to_string),
        OCEndpointUtil::StaticMethod("compare", &OCEndpointUtil::compare),
        OCEndpointUtil::StaticMethod("copy", &OCEndpointUtil::copy),
        OCEndpointUtil::StaticMethod("free_endpoint", &OCEndpointUtil::free_endpoint),
        OCEndpointUtil::StaticMethod("string_to_endpoint", &OCEndpointUtil::string_to_endpoint),
        OCEndpointUtil::StaticMethod("new_endpoint", &OCEndpointUtil::new_endpoint),
        OCEndpointUtil::StaticMethod("endpoint_string_parse_path", &OCEndpointUtil::endpoint_string_parse_path),
        OCEndpointUtil::StaticMethod("set_di", &OCEndpointUtil::set_di),
        OCEndpointUtil::StaticMethod("ipv6_endpoint_is_link_local", &OCEndpointUtil::ipv6_endpoint_is_link_local),
        OCEndpointUtil::StaticMethod("compare_address", &OCEndpointUtil::compare_address),
        OCEndpointUtil::StaticMethod("set_local_address", &OCEndpointUtil::set_local_address),
    });
}

Napi::Value OCEndpointUtil::to_string(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCMmem& endpoint_str = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_to_string(endpoint, endpoint_str));
}

Napi::Value OCEndpointUtil::compare(const Napi::CallbackInfo& info) {
  OCEndpoint& ep1 = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& ep2 = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_compare(ep1, ep2));
}

Napi::Value OCEndpointUtil::copy(const Napi::CallbackInfo& info) {
  OCEndpoint& dst = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& src = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  (void)oc_endpoint_copy(dst, src);
  return info.Env().Undefined();
}

Napi::Value OCEndpointUtil::free_endpoint(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_free_endpoint(endpoint);
  return info.Env().Undefined();
}

Napi::Value OCEndpointUtil::string_to_endpoint(const Napi::CallbackInfo& info) {
  OCMmem& endpoint_str = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  OCMmem& uri = *OCMmem::Unwrap(info[2].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_string_to_endpoint(endpoint_str, endpoint, uri));
}

Napi::Value OCEndpointUtil::new_endpoint(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_endpoint_t> sp(oc_new_endpoint());
  auto args = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({args});
}

Napi::Value OCEndpointUtil::endpoint_string_parse_path(const Napi::CallbackInfo& info) {
  OCMmem& endpoint_str = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  OCMmem& path = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_string_parse_path(endpoint_str, path));
}

Napi::Value OCEndpointUtil::set_di(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCUuid& di = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  (void)oc_endpoint_set_di(endpoint, di);
  return info.Env().Undefined();
}

Napi::Value OCEndpointUtil::ipv6_endpoint_is_link_local(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_ipv6_endpoint_is_link_local(endpoint));
}

Napi::Value OCEndpointUtil::compare_address(const Napi::CallbackInfo& info) {
  OCEndpoint& ep1 = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& ep2 = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_compare_address(ep1, ep2));
}

Napi::Value OCEndpointUtil::set_local_address(const Napi::CallbackInfo& info) {
  OCEndpoint& ep = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  int interface_index = static_cast<int>(info[1].As<Napi::Number>());
  (void)oc_endpoint_set_local_address(ep, interface_index);
  return info.Env().Undefined();
}

Napi::FunctionReference OCEndpointUtil::constructor;

OCEnumUtil::OCEnumUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCEnumUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCEnumUtil", {
        OCEnumUtil::StaticMethod("enum_to_str", &OCEnumUtil::enum_to_str),
        OCEnumUtil::StaticMethod("pos_desc_to_str", &OCEnumUtil::pos_desc_to_str),
    });
}

Napi::Value OCEnumUtil::enum_to_str(const Napi::CallbackInfo& info) {
  oc_enum_t val = static_cast<oc_enum_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_enum_to_str(val));
}

Napi::Value OCEnumUtil::pos_desc_to_str(const Napi::CallbackInfo& info) {
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_enum_pos_desc_to_str(pos));
}

Napi::FunctionReference OCEnumUtil::constructor;

OCIntrospection::OCIntrospection(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCIntrospection::GetClass(Napi::Env env) {
    return DefineClass(env, "OCIntrospection", {
        OCIntrospection::StaticMethod("set_introspection_data", &OCIntrospection::set_introspection_data),
    });
}

#if defined(OC_IDD_API)
Napi::Value OCIntrospection::set_introspection_data(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  uint8_t* IDD = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t IDD_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_set_introspection_data(device, IDD, IDD_size);
  return info.Env().Undefined();
}
#endif

Napi::FunctionReference OCIntrospection::constructor;

OCPki::OCPki(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCPki::GetClass(Napi::Env env) {
    return DefineClass(env, "OCPki", {
        OCPki::StaticMethod("add_mfg_cert", &OCPki::add_mfg_cert),
        OCPki::StaticMethod("add_mfg_trust_anchor", &OCPki::add_mfg_trust_anchor),
        OCPki::StaticMethod("add_mfg_intermediate_cert", &OCPki::add_mfg_intermediate_cert),
        OCPki::StaticMethod("add_trust_anchor", &OCPki::add_trust_anchor),
        OCPki::StaticMethod("set_security_profile", &OCPki::set_security_profile),
    });
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCPki::add_mfg_cert(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  const unsigned char* key = info[3].As<Napi::Buffer<const uint8_t>>().Data();
  size_t key_size = static_cast<size_t>(info[4].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_cert(device, cert, cert_size, key, key_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCPki::add_mfg_trust_anchor(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_trust_anchor(device, cert, cert_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCPki::add_mfg_intermediate_cert(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  int credid = static_cast<int>(info[1].As<Napi::Number>());
  const unsigned char* cert = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_intermediate_cert(device, credid, cert, cert_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCPki::add_trust_anchor(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_trust_anchor(device, cert, cert_size));
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCPki::set_security_profile(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_sp_types_t supported_profiles = static_cast<oc_sp_types_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_sp_types_t current_profile = static_cast<oc_sp_types_t>(info[2].As<Napi::Number>().Uint32Value());
  int mfg_credid = static_cast<int>(info[3].As<Napi::Number>());
  (void)oc_pki_set_security_profile(device, supported_profiles, current_profile, mfg_credid);
  return info.Env().Undefined();
}
#endif

Napi::FunctionReference OCPki::constructor;

OCRandom::OCRandom(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCRandom::GetClass(Napi::Env env) {
    return DefineClass(env, "OCRandom", {
        OCRandom::StaticMethod("init", &OCRandom::init),
        OCRandom::StaticMethod("destroy", &OCRandom::destroy),
        OCRandom::StaticMethod("random_value", &OCRandom::random_value),
    });
}

Napi::Value OCRandom::init(const Napi::CallbackInfo& info) {
  (void)oc_random_init();
  return info.Env().Undefined();
}

Napi::Value OCRandom::destroy(const Napi::CallbackInfo& info) {
  (void)oc_random_destroy();
  return info.Env().Undefined();
}

Napi::Value OCRandom::random_value(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_random_value());
}

Napi::FunctionReference OCRandom::constructor;

OCSessionEvents::OCSessionEvents(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCSessionEvents::GetClass(Napi::Env env) {
    return DefineClass(env, "OCSessionEvents", {
        OCSessionEvents::StaticMethod("start_event", &OCSessionEvents::start_event),
        OCSessionEvents::StaticMethod("end_event", &OCSessionEvents::end_event),
        OCSessionEvents::StaticMethod("set_event_delay", &OCSessionEvents::set_event_delay),
    });
}

#if defined(OC_TCP)
Napi::Value OCSessionEvents::start_event(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_session_start_event(endpoint);
  return info.Env().Undefined();
}
#endif

#if defined(OC_TCP)
Napi::Value OCSessionEvents::end_event(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_session_end_event(endpoint);
  return info.Env().Undefined();
}
#endif

#if defined(OC_TCP)
Napi::Value OCSessionEvents::set_event_delay(const Napi::CallbackInfo& info) {
  int secs = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_session_events_set_event_delay(secs);
  return info.Env().Undefined();
}
#endif

Napi::FunctionReference OCSessionEvents::constructor;

OCSoftwareUpdate::OCSoftwareUpdate(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCSoftwareUpdate::GetClass(Napi::Env env) {
    return DefineClass(env, "OCSoftwareUpdate", {
        OCSoftwareUpdate::StaticMethod("notify_downloaded", &OCSoftwareUpdate::notify_downloaded),
        OCSoftwareUpdate::StaticMethod("notify_upgrading", &OCSoftwareUpdate::notify_upgrading),
        OCSoftwareUpdate::StaticMethod("notify_done", &OCSoftwareUpdate::notify_done),
        OCSoftwareUpdate::StaticMethod("notify_new_version_available", &OCSoftwareUpdate::notify_new_version_available),
        OCSoftwareUpdate::StaticMethod("set_impl", &OCSoftwareUpdate::set_impl),
    });
}

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCSoftwareUpdate::notify_downloaded(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string version_ = info[1].As<Napi::String>().Utf8Value();
  const char* version = version_.c_str();
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_downloaded(device, version, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCSoftwareUpdate::notify_upgrading(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string version_ = info[1].As<Napi::String>().Utf8Value();
  const char* version = version_.c_str();
  oc_clock_time_t timestamp = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_upgrading(device, version, timestamp, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCSoftwareUpdate::notify_done(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_done(device, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCSoftwareUpdate::notify_new_version_available(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string version_ = info[1].As<Napi::String>().Utf8Value();
  const char* version = version_.c_str();
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_new_version_available(device, version, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCSoftwareUpdate::set_impl(const Napi::CallbackInfo& info) {
  OCSoftwareUpdateHandler& swupdate_impl = *OCSoftwareUpdateHandler::Unwrap(info[0].As<Napi::Object>());
  oc_swupdate_cb_validate_purl_ref.Reset(swupdate_impl.validate_purl.Value());
  oc_swupdate_cb_check_new_version_ref.Reset(swupdate_impl.check_new_version.Value());
  oc_swupdate_cb_download_update_ref.Reset(swupdate_impl.download_update.Value());
  oc_swupdate_cb_perform_upgrade_ref.Reset(swupdate_impl.perform_upgrade.Value());
  swupdate_impl.m_pvalue->validate_purl = oc_swupdate_cb_validate_purl_helper;
  swupdate_impl.m_pvalue->check_new_version = oc_swupdate_cb_check_new_version_helper;
  swupdate_impl.m_pvalue->download_update = oc_swupdate_cb_download_update_helper;
  swupdate_impl.m_pvalue->perform_upgrade = oc_swupdate_cb_perform_upgrade_helper;
  (void)oc_swupdate_set_impl(swupdate_impl);
  return info.Env().Undefined();
}
#endif

Napi::FunctionReference OCSoftwareUpdate::constructor;

OCStorage::OCStorage(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCStorage::GetClass(Napi::Env env) {
    return DefineClass(env, "OCStorage", {
        OCStorage::StaticMethod("storage_config", &OCStorage::storage_config),
    });
}

Napi::Value OCStorage::storage_config(const Napi::CallbackInfo& info) {
  std::string store_ = info[0].As<Napi::String>().Utf8Value();
  const char* store = store_.c_str();
  return Napi::Number::New(info.Env(), oc_storage_config(store));
}

Napi::FunctionReference OCStorage::constructor;

OCUuidUtil::OCUuidUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCUuidUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCUuidUtil", {
        OCUuidUtil::StaticMethod("str_to_uuid", &OCUuidUtil::str_to_uuid),
        OCUuidUtil::StaticMethod("uuid_to_str", &OCUuidUtil::uuid_to_str),
        OCUuidUtil::StaticMethod("gen_uuid", &OCUuidUtil::gen_uuid),
    });
}

Napi::Value OCUuidUtil::str_to_uuid(const Napi::CallbackInfo& info) {
  std::string str_ = info[0].As<Napi::String>().Utf8Value();
  const char* str = str_.c_str();
  OCUuid& uuid = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  (void)oc_str_to_uuid(str, uuid);
  return info.Env().Undefined();
}

Napi::Value OCUuidUtil::uuid_to_str(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  char* buffer = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  int buflen = static_cast<int>(info[2].As<Napi::Number>());
  (void)oc_uuid_to_str(uuid, buffer, buflen);
  return info.Env().Undefined();
}

Napi::Value OCUuidUtil::gen_uuid(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  (void)oc_gen_uuid(uuid);
  return info.Env().Undefined();
}

Napi::FunctionReference OCUuidUtil::constructor;

OCCoreRes::OCCoreRes(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCoreRes::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCoreRes", {
        OCCoreRes::StaticMethod("init", &OCCoreRes::init),
        OCCoreRes::StaticMethod("init_platform", &OCCoreRes::init_platform),
        OCCoreRes::StaticMethod("shutdown", &OCCoreRes::shutdown),
        OCCoreRes::StaticMethod("get_num_devices", &OCCoreRes::get_num_devices),
        OCCoreRes::StaticMethod("get_device_id", &OCCoreRes::get_device_id),
        OCCoreRes::StaticMethod("get_device_info", &OCCoreRes::get_device_info),
        OCCoreRes::StaticMethod("get_platform_info", &OCCoreRes::get_platform_info),
        OCCoreRes::StaticMethod("get_resource_by_uri", &OCCoreRes::get_resource_by_uri),
        OCCoreRes::StaticMethod("filter_resource_by_rt", &OCCoreRes::filter_resource_by_rt),
        OCCoreRes::StaticMethod("is_DCR", &OCCoreRes::is_DCR),
        OCCoreRes::StaticMethod("set_latency", &OCCoreRes::set_latency),
        OCCoreRes::StaticMethod("get_latency", &OCCoreRes::get_latency),
        OCCoreRes::StaticMethod("add_new_device", &OCCoreRes::add_new_device),
    });
}

Napi::Value OCCoreRes::init(const Napi::CallbackInfo& info) {
  (void)oc_core_init();
  return info.Env().Undefined();
}

Napi::Value OCCoreRes::init_platform(const Napi::CallbackInfo& info) {
  std::string mfg_name_ = info[0].As<Napi::String>().Utf8Value();
  const char* mfg_name = mfg_name_.c_str();
  oc_core_init_platform_cb_t init_cb = nullptr;
  Napi::Function init_cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  std::shared_ptr<oc_platform_info_t> sp(oc_core_init_platform(mfg_name, init_cb, data));
  auto args = Napi::External<std::shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({args});
}

Napi::Value OCCoreRes::shutdown(const Napi::CallbackInfo& info) {
  (void)oc_core_shutdown();
  return info.Env().Undefined();
}

Napi::Value OCCoreRes::get_num_devices(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_core_get_num_devices());
}

Napi::Value OCCoreRes::get_device_id(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_uuid_t> sp(oc_core_get_device_id(device));
  auto args = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({args});
}

Napi::Value OCCoreRes::get_device_info(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_device_info_t> sp(oc_core_get_device_info(device));
  auto args = Napi::External<std::shared_ptr<oc_device_info_t>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({args});
}

Napi::Value OCCoreRes::get_platform_info(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_platform_info_t> sp(oc_core_get_platform_info());
  auto args = Napi::External<std::shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({args});
}

Napi::Value OCCoreRes::get_resource_by_uri(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_core_get_resource_by_uri(uri, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value OCCoreRes::filter_resource_by_rt(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCRequest& request = *OCRequest::Unwrap(info[1].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_filter_resource_by_rt(resource, request));
}

Napi::Value OCCoreRes::is_DCR(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_core_is_DCR(resource, device));
}

Napi::Value OCCoreRes::set_latency(const Napi::CallbackInfo& info) {
  int latency = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_core_set_latency(latency);
  return info.Env().Undefined();
}

Napi::Value OCCoreRes::get_latency(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_core_get_latency());
}

Napi::Value OCCoreRes::add_new_device(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string rt_ = info[1].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  std::string name_ = info[2].As<Napi::String>().Utf8Value();
  const char* name = name_.c_str();
  std::string spec_version_ = info[3].As<Napi::String>().Utf8Value();
  const char* spec_version = spec_version_.c_str();
  std::string data_model_version_ = info[4].As<Napi::String>().Utf8Value();
  const char* data_model_version = data_model_version_.c_str();
  oc_core_add_device_cb_t add_device_cb = nullptr;
  Napi::Function add_device_cb_ = info[5].As<Napi::Function>();
  void* data = info[6];
  std::shared_ptr<oc_device_info_t> sp(oc_core_add_new_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data));
  auto args = Napi::External<std::shared_ptr<oc_device_info_t>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({args});
}

Napi::FunctionReference OCCoreRes::constructor;

OCRep::OCRep(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCRep::GetClass(Napi::Env env) {
    return DefineClass(env, "OCRep", {
        OCRep::StaticMethod("add_boolean", &OCRep::add_boolean),
        OCRep::StaticMethod("add_byte_string", &OCRep::add_byte_string),
        OCRep::StaticMethod("add_double", &OCRep::add_double),
        OCRep::StaticMethod("add_text_string", &OCRep::add_text_string),
        OCRep::StaticMethod("start_array", &OCRep::start_array),
        OCRep::StaticMethod("start_links_array", &OCRep::start_links_array),
        OCRep::StaticMethod("start_object", &OCRep::start_object),
        OCRep::StaticMethod("start_root_object", &OCRep::start_root_object),
        OCRep::StaticMethod("clear_cbor_errno", &OCRep::clear_cbor_errno),
        OCRep::StaticMethod("close_array", &OCRep::close_array),
        OCRep::StaticMethod("close_object", &OCRep::close_object),
        OCRep::StaticMethod("delete_buffer", &OCRep::delete_buffer),
        OCRep::StaticMethod("end_array", &OCRep::end_array),
        OCRep::StaticMethod("end_links_array", &OCRep::end_links_array),
        OCRep::StaticMethod("end_object", &OCRep::end_object),
        OCRep::StaticMethod("end_root_object", &OCRep::end_root_object),
        OCRep::StaticMethod("get_bool", &OCRep::get_bool),
        OCRep::StaticMethod("get_bool_array", &OCRep::get_bool_array),
        OCRep::StaticMethod("get_byte_string", &OCRep::get_byte_string),
        OCRep::StaticMethod("get_byte_string_array", &OCRep::get_byte_string_array),
        OCRep::StaticMethod("get_cbor_errno", &OCRep::get_cbor_errno),
        OCRep::StaticMethod("get_double", &OCRep::get_double),
        OCRep::StaticMethod("get_double_array", &OCRep::get_double_array),
        OCRep::StaticMethod("get_object", &OCRep::get_object),
        OCRep::StaticMethod("get_object_array", &OCRep::get_object_array),
        OCRep::StaticMethod("get_rep_from_root_object", &OCRep::get_rep_from_root_object),
        OCRep::StaticMethod("get_string", &OCRep::get_string),
        OCRep::StaticMethod("get_string_array", &OCRep::get_string_array),
        OCRep::StaticMethod("new_buffer", &OCRep::new_buffer),
        OCRep::StaticMethod("object_array_start_item", &OCRep::object_array_start_item),
        OCRep::StaticMethod("object_array_end_item", &OCRep::object_array_end_item),
        OCRep::StaticMethod("oc_array_to_bool_array", &OCRep::oc_array_to_bool_array),
        OCRep::StaticMethod("oc_array_to_double_array", &OCRep::oc_array_to_double_array),
        OCRep::StaticMethod("oc_array_to_int_array", &OCRep::oc_array_to_int_array),
        OCRep::StaticMethod("oc_array_to_string_array", &OCRep::oc_array_to_string_array),
        OCRep::StaticMethod("open_array", &OCRep::open_array),
        OCRep::StaticMethod("open_object", &OCRep::open_object),
        OCRep::StaticMethod("set_boolean", &OCRep::set_boolean),
        OCRep::StaticMethod("set_bool_array", &OCRep::set_bool_array),
        OCRep::StaticMethod("set_byte_string", &OCRep::set_byte_string),
        OCRep::StaticMethod("set_double", &OCRep::set_double),
        OCRep::StaticMethod("set_double_array", &OCRep::set_double_array),
        OCRep::StaticMethod("set_key", &OCRep::set_key),
        OCRep::StaticMethod("set_long", &OCRep::set_long),
        OCRep::StaticMethod("set_long_array", &OCRep::set_long_array),
        OCRep::StaticMethod("set_string_array", &OCRep::set_string_array),
        OCRep::StaticMethod("set_text_string", &OCRep::set_text_string),
        OCRep::StaticMethod("set_uint", &OCRep::set_uint),
        OCRep::StaticMethod("to_json", &OCRep::to_json),
    });
}

Napi::Value OCRep::add_boolean(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
// 1 value, const bool
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::add_byte_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  const unsigned char* value = info[1].As<Napi::Buffer<const uint8_t>>().Data();
// 2 length, const size_t
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::add_double(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
// 1 value, const double
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::add_text_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string value_ = info[1].As<Napi::String>().Utf8Value();
  const char* value = value_.c_str();
  (void)helper_rep_add_text_string(arrayObject, value);
  return info.Env().Undefined();
}

Napi::Value OCRep::start_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<CborEncoder> sp(helper_rep_start_array(parent));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::start_links_array(const Napi::CallbackInfo& info) {
  std::shared_ptr<CborEncoder> sp(helper_rep_start_links_array());
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::start_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<CborEncoder> sp(helper_rep_start_object(parent));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::start_root_object(const Napi::CallbackInfo& info) {
  std::shared_ptr<CborEncoder> sp(helper_rep_start_root_object());
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::clear_cbor_errno(const Napi::CallbackInfo& info) {
  (void)helper_rep_clear_cbor_errno();
  return info.Env().Undefined();
}

Napi::Value OCRep::close_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_close_array(object, arrayObject);
  return info.Env().Undefined();
}

Napi::Value OCRep::close_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_close_object(parent, object);
  return info.Env().Undefined();
}

Napi::Value OCRep::delete_buffer(const Napi::CallbackInfo& info) {
  (void)helper_rep_delete_buffer();
  return info.Env().Undefined();
}

Napi::Value OCRep::end_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_end_array(parent, arrayObject);
  return info.Env().Undefined();
}

Napi::Value OCRep::end_links_array(const Napi::CallbackInfo& info) {
  (void)helper_rep_end_links_array();
  return info.Env().Undefined();
}

Napi::Value OCRep::end_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_end_object(parent, object);
  return info.Env().Undefined();
}

Napi::Value OCRep::end_root_object(const Napi::CallbackInfo& info) {
  (void)helper_rep_end_root_object();
  return info.Env().Undefined();
}

Napi::Value OCRep::get_bool(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, bool*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_bool_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, bool**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_byte_string(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_byte_string_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  OCStringArray& value = *OCStringArray::Unwrap(info[2].As<Napi::Object>());
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), oc_rep_get_byte_string_array(rep, key, value, size));
}

Napi::Value OCRep::get_cbor_errno(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_rep_get_cbor_errno());
}

Napi::Value OCRep::get_double(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, double*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_double_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, double**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_object(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, oc_rep_t**
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_object_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, oc_rep_t**
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_rep_from_root_object(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_rep_t> sp(helper_rep_get_rep_from_root_object());
  auto args = Napi::External<std::shared_ptr<oc_rep_t>>::New(info.Env(), &sp);
  return OCRep::constructor.New({args});
}

Napi::Value OCRep::get_string(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value OCRep::get_string_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  OCStringArray& value = *OCStringArray::Unwrap(info[2].As<Napi::Object>());
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), oc_rep_get_string_array(rep, key, value, size));
}

Napi::Value OCRep::new_buffer(const Napi::CallbackInfo& info) {
  int size = static_cast<int>(info[0].As<Napi::Number>());
  (void)helper_rep_new_buffer(size);
  return info.Env().Undefined();
}

Napi::Value OCRep::object_array_start_item(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<CborEncoder> sp(helper_rep_object_array_start_item(arrayObject));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::object_array_end_item(const Napi::CallbackInfo& info) {
  OCCborEncoder& parentArrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_object_array_end_item(parentArrayObject, arrayObject);
  return info.Env().Undefined();
}

Napi::Value OCRep::oc_array_to_bool_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
      return Napi::Buffer<bool>::New(info.Env(), oc_bool_array(*static_cast<oc_array_t*>(array)), oc_bool_array_size(*(oc_array_t*)array));
}

Napi::Value OCRep::oc_array_to_double_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
      return Napi::Buffer<double>::New(info.Env(), oc_double_array(*static_cast<oc_array_t*>(array)), oc_double_array_size(*(oc_array_t*)array));
}

Napi::Value OCRep::oc_array_to_int_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
      return Napi::Buffer<int64_t>::New(info.Env(), oc_int_array(*static_cast<oc_array_t*>(array)), oc_int_array_size(*(oc_array_t*)array));
}

Napi::Value OCRep::oc_array_to_string_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
    size_t sz = oc_string_array_get_allocated_size(*(oc_array_t*)array);
    oc_string_array_t* strarray = reinterpret_cast<oc_string_array_t*>((oc_array_t*)array);
    auto buf = Napi::Array::New(info.Env(), sz);
    for(uint32_t i=0; i<sz; i++) {
      auto str = Napi::String::New(info.Env(), oc_string_array_get_item(*strarray, i));
      buf[i] = str;
    }
    return buf;
}

Napi::Value OCRep::open_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::shared_ptr<CborEncoder> sp(helper_rep_open_array(parent, key));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::open_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::shared_ptr<CborEncoder> sp(helper_rep_open_object(parent, key));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value OCRep::set_boolean(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  bool value = info[2].As<Napi::Boolean>().Value();
  (void)helper_rep_set_boolean(object, key, value);
  return info.Env().Undefined();
}

Napi::Value OCRep::set_bool_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, bool*
  int length = static_cast<int>(info[3].As<Napi::Number>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::set_byte_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  const unsigned char* value = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  size_t length = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)helper_rep_set_byte_string(object, key, value, length);
  return info.Env().Undefined();
}

Napi::Value OCRep::set_double(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  double value = info[2].As<Napi::Number>().DoubleValue();
  (void)helper_rep_set_double(object, key, value);
  return info.Env().Undefined();
}

Napi::Value OCRep::set_double_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, double*
  int length = static_cast<int>(info[3].As<Napi::Number>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::set_key(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  (void)helper_rep_set_key(parent, key);
  return info.Env().Undefined();
}

Napi::Value OCRep::set_long(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  int64_t value = static_cast<int64_t>(info[2].As<Napi::Number>());
  (void)helper_rep_set_long(object, key, value);
  return info.Env().Undefined();
}

Napi::Value OCRep::set_long_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, int64_t*
  int length = static_cast<int>(info[3].As<Napi::Number>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::set_string_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, oc_string_array_t
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::set_text_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::string value_ = info[2].As<Napi::String>().Utf8Value();
  const char* value = value_.c_str();
  (void)helper_rep_set_text_string(object, key, value);
  return info.Env().Undefined();
}

Napi::Value OCRep::set_uint(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, unsigned int
  (void)0;
  return info.Env().Undefined();
}

Napi::Value OCRep::to_json(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  char* buf = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  size_t buf_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  bool pretty_print = info[3].As<Napi::Boolean>().Value();
  return Napi::Number::New(info.Env(), oc_rep_to_json(rep, buf, buf_size, pretty_print));
}

Napi::FunctionReference OCRep::constructor;

