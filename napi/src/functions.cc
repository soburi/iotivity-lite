#include "functions.h"
#include "iotivity_lite.h"
#include "helper.h"
Napi::Value N_handle_coap_signal_message(const Napi::CallbackInfo& info) {
  void* packet = info[0];
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), handle_coap_signal_message(packet, endpoint));
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_assert_all_roles(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  (void)oc_assert_all_roles(endpoint, handler, user_data);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_assert_role(const Napi::CallbackInfo& info) {
  std::string role_ = info[0].As<Napi::String>().Utf8Value();
  const char* role = role_.c_str();
  std::string authority_ = info[1].As<Napi::String>().Utf8Value();
  const char* authority = authority_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  void* user_data = info[4];
  return Napi::Boolean::New(info.Env(), oc_assert_role(role, authority, endpoint, handler, user_data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_auto_assert_roles(const Napi::CallbackInfo& info) {
  bool auto_assert = info[0].As<Napi::Boolean>().Value();
  (void)oc_auto_assert_roles(auto_assert);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_get_all_roles(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_role_t> sp(oc_get_all_roles());
  auto args = Napi::External<std::shared_ptr<oc_role_t>>::New(info.Env(), &sp);
  return OCRole::constructor.New({args});
}
#endif

Napi::Value N_oc_close_session(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_close_session(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_do_delete(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  std::string query_ = info[2].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_do_delete(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_do_get(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  std::string query_ = info[2].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_do_get(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_do_ip_discovery(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery(rt, handler, user_data));
}

Napi::Value N_oc_do_ip_discovery_all(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_all(handler, user_data));
}

Napi::Value N_oc_do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[0].As<Napi::Function>();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  void* user_data = info[2];
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_all_at_endpoint(handler, endpoint, user_data));
}

Napi::Value N_oc_do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, user_data));
}

Napi::Value N_oc_do_ip_multicast(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string query_ = info[1].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_ip_multicast(uri, query, handler, user_data));
}

Napi::Value N_oc_do_observe(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  std::string query_ = info[2].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_do_observe(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_do_post(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_do_post());
}

Napi::Value N_oc_do_put(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_do_put());
}

Napi::Value N_oc_do_realm_local_ipv6_discovery(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery(rt, handler, user_data));
}

Napi::Value N_oc_do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery_all(handler, user_data));
}

Napi::Value N_oc_do_realm_local_ipv6_multicast(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string query_ = info[1].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_multicast(uri, query, handler, user_data));
}

Napi::Value N_oc_do_site_local_ipv6_discovery(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  oc_discovery_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery(rt, handler, user_data));
}

Napi::Value N_oc_do_site_local_ipv6_discovery_all(const Napi::CallbackInfo& info) {
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery_all(handler, user_data));
}

Napi::Value N_oc_do_site_local_ipv6_multicast(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  std::string query_ = info[1].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_multicast(uri, query, handler, user_data));
}

Napi::Value N_oc_free_server_endpoints(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_free_server_endpoints(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_init_post(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  std::string query_ = info[2].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_init_post(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_init_put(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  std::string query_ = info[2].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_init_put(uri, endpoint, query, handler, qos, user_data));
}

#if defined(OC_TCP)
Napi::Value N_oc_send_ping(const Napi::CallbackInfo& info) {
  bool custody = info[0].As<Napi::Boolean>().Value();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  uint16_t timeout_seconds = static_cast<uint16_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  void* user_data = info[4];
  return Napi::Boolean::New(info.Env(), oc_send_ping(custody, endpoint, timeout_seconds, handler, user_data));
}
#endif

Napi::Value N_oc_stop_multicast(const Napi::CallbackInfo& info) {
  OCClientResponse& response = *OCClientResponse::Unwrap(info[0].As<Napi::Object>());
  (void)oc_stop_multicast(response);
  return info.Env().Undefined();
}

Napi::Value N_oc_stop_observe(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_stop_observe(uri, endpoint));
}

Napi::Value N_oc_add_collection(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_add_collection(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_add_link(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCLink& link = *OCLink::Unwrap(info[1].As<Napi::Object>());
  (void)oc_collection_add_link(collection, link);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_add_mandatory_rt(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string rt_ = info[1].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  return Napi::Boolean::New(info.Env(), oc_collection_add_mandatory_rt(collection, rt));
}

Napi::Value N_oc_collection_add_supported_rt(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string rt_ = info[1].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
  return Napi::Boolean::New(info.Env(), oc_collection_add_supported_rt(collection, rt));
}

Napi::Value N_oc_collection_get_collections(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_collection_get_collections());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_collection_get_links(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_link_t> sp(oc_collection_get_links(collection));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value N_oc_collection_remove_link(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCLink& link = *OCLink::Unwrap(info[1].As<Napi::Object>());
  (void)oc_collection_remove_link(collection, link);
  return info.Env().Undefined();
}

#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_add_rt_factory(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
// 1 get_instance, oc_resource_get_instance_t
// 2 free_instance, oc_resource_free_instance_t
  return Napi::Boolean::New(info.Env(), 0);
}
#endif

Napi::Value N_oc_delete_collection(const Napi::CallbackInfo& info) {
  OCResource& collection = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_delete_collection(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_delete_link(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  (void)oc_delete_link(link);
  return info.Env().Undefined();
}

Napi::Value N_oc_link_add_link_param(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::string value_ = info[2].As<Napi::String>().Utf8Value();
  const char* value = value_.c_str();
  (void)oc_link_add_link_param(link, key, value);
  return info.Env().Undefined();
}

Napi::Value N_oc_link_add_rel(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  std::string rel_ = info[1].As<Napi::String>().Utf8Value();
  const char* rel = rel_.c_str();
  (void)oc_link_add_rel(link, rel);
  return info.Env().Undefined();
}

Napi::Value N_oc_new_collection(const Napi::CallbackInfo& info) {
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

Napi::Value N_oc_new_link(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_link_t> sp(oc_new_link(resource));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value N_oc_remove_delayed_callback(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t callback = nullptr;
  Napi::Function callback_ = info[1].As<Napi::Function>();
  (void)oc_remove_delayed_callback(cb_data, callback);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_delayed_callback(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t callback = nullptr;
  Napi::Function callback_ = info[1].As<Napi::Function>();
  uint16_t seconds = static_cast<uint16_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_set_delayed_callback(cb_data, callback, seconds);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_immutable_device_identifier(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  OCUuid& piid = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  (void)oc_set_immutable_device_identifier(device, piid);
  return info.Env().Undefined();
}

Napi::Value N_oc_add_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_add_resource(resource));
}

Napi::Value N_oc_delete_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_delete_resource(resource));
}

Napi::Value N_oc_device_bind_resource_type(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string type_ = info[1].As<Napi::String>().Utf8Value();
  const char* type = type_.c_str();
  (void)oc_device_bind_resource_type(device, type);
  return info.Env().Undefined();
}

Napi::Value N_oc_get_diagnostic_message(const Napi::CallbackInfo& info) {
  OCClientResponse& response = *OCClientResponse::Unwrap(info[0].As<Napi::Object>());
// 1 msg, const char**
  size_t* size = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_get_query_value(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_get_request_payload_raw(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
// 1 payload, const uint8_t**
  size_t* size = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
// 3 content_format, oc_content_format_t*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_get_response_payload_raw(const Napi::CallbackInfo& info) {
  OCClientResponse& response = *OCClientResponse::Unwrap(info[0].As<Napi::Object>());
// 1 payload, const uint8_t**
  size_t* size = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
// 3 content_format, oc_content_format_t*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_ignore_request(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  (void)oc_ignore_request(request);
  return info.Env().Undefined();
}

Napi::Value N_oc_indicate_separate_response(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  OCSeparateResponse& response = *OCSeparateResponse::Unwrap(info[1].As<Napi::Object>());
  (void)oc_indicate_separate_response(request, response);
  return info.Env().Undefined();
}

Napi::Value N_oc_init_query_iterator(const Napi::CallbackInfo& info) {
  (void)oc_init_query_iterator();
  return info.Env().Undefined();
}

Napi::Value N_oc_iterate_query(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
// 1 key, char**
  size_t* key_len = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
// 3 value, char**
  size_t* value_len = reinterpret_cast<size_t*>(info[4].As<Napi::Uint32Array>().Data());
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_iterate_query_get_values(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
// 3 value_len, int*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_new_resource(const Napi::CallbackInfo& info) {
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

Napi::Value N_oc_notify_observers(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_notify_observers(resource));
}

Napi::Value N_oc_process_baseline_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_process_baseline_interface(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_bind_resource_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_bind_resource_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_bind_resource_type(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string type_ = info[1].As<Napi::String>().Utf8Value();
  const char* type = type_.c_str();
  (void)oc_resource_bind_resource_type(resource, type);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value N_oc_resource_make_public(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_resource_make_public(resource);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_resource_set_default_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_default_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_discoverable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_discoverable(resource, state);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_observable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_observable(resource, state);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_periodic_observable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  uint16_t seconds = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_periodic_observable(resource, seconds);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_properties_cbs(const Napi::CallbackInfo& info) {
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

Napi::Value N_oc_resource_set_request_handler(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_request_callback_t callback = oc_resource_set_request_handler_helper;
callback_helper_t* user_data = new_callback_helper_t(info, 2, 3);
if(!user_data) callback = nullptr;
  (void)oc_resource_set_request_handler(resource, method, callback, user_data);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_func_desc(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_enum_t func = static_cast<oc_enum_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_func_desc(resource, func);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_pos_desc(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_pos_desc(resource, pos);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_pos_rel(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  double x = info[1].As<Napi::Number>().DoubleValue();
  double y = info[2].As<Napi::Number>().DoubleValue();
  double z = info[3].As<Napi::Number>().DoubleValue();
  (void)oc_resource_tag_pos_rel(resource, x, y, z);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_diagnostic_message(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  std::string msg_ = info[1].As<Napi::String>().Utf8Value();
  const char* msg = msg_.c_str();
  size_t msg_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_status_t response_code = static_cast<oc_status_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)oc_send_diagnostic_message(request, msg, msg_len, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_response(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  oc_status_t response_code = static_cast<oc_status_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_send_response(request, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_response_raw(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  const uint8_t* payload = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_content_format_t content_format = static_cast<oc_content_format_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_status_t response_code = static_cast<oc_status_t>(info[4].As<Napi::Number>().Uint32Value());
  (void)oc_send_response_raw(request, payload, size, content_format, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_separate_response(const Napi::CallbackInfo& info) {
  OCSeparateResponse& handle = *OCSeparateResponse::Unwrap(info[0].As<Napi::Object>());
  oc_status_t response_code = static_cast<oc_status_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_send_separate_response(handle, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_con_write_cb(const Napi::CallbackInfo& info) {
  oc_con_write_cb_t callback = nullptr;
  Napi::Function callback_ = info[0].As<Napi::Function>();
  (void)oc_set_con_write_cb(callback);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_separate_response_buffer(const Napi::CallbackInfo& info) {
  OCSeparateResponse& handle = *OCSeparateResponse::Unwrap(info[0].As<Napi::Object>());
  (void)oc_set_separate_response_buffer(handle);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_expired(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_timer_expired(t));
}

Napi::Value N_oc_timer_remaining(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_timer_remaining(t));
}

Napi::Value N_oc_timer_reset(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  (void)oc_timer_reset(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_restart(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  (void)oc_timer_restart(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_set(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  oc_clock_time_t interval = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
  (void)oc_timer_set(t, interval);
  return info.Env().Undefined();
}

Napi::Value N_oc_add_device(const Napi::CallbackInfo& info) {
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
Napi::Value N_oc_add_ownership_status_cb(const Napi::CallbackInfo& info) {
  oc_ownership_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  (void)oc_add_ownership_status_cb(cb, user_data);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_get_con_res_announced(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_get_con_res_announced());
}

Napi::Value N_oc_init_platform(const Napi::CallbackInfo& info) {
  std::string mfg_name_ = info[0].As<Napi::String>().Utf8Value();
  const char* mfg_name = mfg_name_.c_str();
  oc_init_platform_cb_t init_platform_cb = oc_init_platform_helper;
callback_helper_t* data = new_callback_helper_t(info, 1, 2);
if(!data) init_platform_cb = nullptr;
  return Napi::Number::New(info.Env(), oc_init_platform(mfg_name, init_platform_cb, data));
}

#if defined(OC_SECURITY)
Napi::Value N_oc_is_owned_device(const Napi::CallbackInfo& info) {
  size_t device_index = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_is_owned_device(device_index));
}
#endif

Napi::Value N_oc_main_init(const Napi::CallbackInfo& info) {
  OCHandler& handler = *OCHandler::Unwrap(info[0].As<Napi::Object>());
//
  main_context = new main_context_t(info.Env());

  handler.m_pvalue->signal_event_loop = [](){ main_context->helper_cv.notify_all(); };
  handler.m_pvalue->init = nullptr;
  handler.m_pvalue->register_resources = nullptr;
  handler.m_pvalue->requests_entry = nullptr;
  if(handler.init.Value().IsFunction() ) {
    main_context->oc_handler_init_ref.Reset(handler.init.Value());
    handler.m_pvalue->init = [](){
      Napi::Value ret = main_context->oc_handler_init_ref.Call({});
      if(ret.IsNumber()) return ret.As<Napi::Number>().Int32Value();
      return 0;
    };
  }
  else {
    Napi::TypeError::New(info.Env(), "init callback is not set.").ThrowAsJavaScriptException();
  }
  if(handler.register_resources.Value().IsFunction() ) {
    main_context->oc_handler_register_resources_ref.Reset(handler.register_resources.Value());
    handler.m_pvalue->register_resources = [](){ main_context->oc_handler_register_resources_ref.Call({}); };
  }
  if(handler.requests_entry.Value().IsFunction() ) {
    main_context->oc_handler_requests_entry_ref.Reset(handler.requests_entry.Value());
    handler.m_pvalue->requests_entry = [](){ main_context->oc_handler_requests_entry_ref.Call({}); };
  }

  try {
    main_context->helper_poll_event_thread = std::thread(helper_poll_event);
    main_context->helper_poll_event_thread.detach();
  }
  catch(system_error) {
    Napi::TypeError::New(info.Env(), "Fail to initialize poll_event thread.").ThrowAsJavaScriptException();
  }

  return Napi::Number::New(info.Env(), oc_main_init(handler));

}

Napi::Value N_oc_main_poll(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_main_poll());
}

Napi::Value N_oc_main_shutdown(const Napi::CallbackInfo& info) {
  terminate_main_loop();
  (void)oc_main_shutdown();
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value N_oc_remove_ownership_status_cb(const Napi::CallbackInfo& info) {
  oc_ownership_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  (void)oc_remove_ownership_status_cb(cb, user_data);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_reset(const Napi::CallbackInfo& info) {
  (void)oc_reset();
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_reset_device(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_reset_device(device);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_set_con_res_announced(const Napi::CallbackInfo& info) {
  bool announce = info[0].As<Napi::Boolean>().Value();
  (void)oc_set_con_res_announced(announce);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_factory_presets_cb(const Napi::CallbackInfo& info) {
  oc_factory_presets_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  (void)oc_set_factory_presets_cb(cb, data);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value N_oc_set_random_pin_callback(const Napi::CallbackInfo& info) {
  oc_random_pin_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  (void)oc_set_random_pin_callback(cb, data);
  return info.Env().Undefined();
}
#endif

Napi::Value N_abort_impl(const Napi::CallbackInfo& info) {
  (void)abort_impl();
  return info.Env().Undefined();
}

Napi::Value N_exit_impl(const Napi::CallbackInfo& info) {
  int status = static_cast<int>(info[0].As<Napi::Number>());
  (void)exit_impl(status);
  return info.Env().Undefined();
}

Napi::Value N_oc_abort(const Napi::CallbackInfo& info) {
  std::string msg_ = info[0].As<Napi::String>().Utf8Value();
  const char* msg = msg_.c_str();
  (void)oc_abort(msg);
  return info.Env().Undefined();
}

Napi::Value N_oc_exit(const Napi::CallbackInfo& info) {
  int status = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_exit(status);
  return info.Env().Undefined();
}

Napi::Value N_oc_base64_decode(const Napi::CallbackInfo& info) {
  uint8_t* str = info[0].As<Napi::Buffer<uint8_t>>().Data();
  size_t len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_base64_decode(str, len));
}

Napi::Value N_oc_base64_encode(const Napi::CallbackInfo& info) {
  const uint8_t* input = info[0].As<Napi::Buffer<const uint8_t>>().Data();
  size_t input_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  uint8_t* output_buffer = info[2].As<Napi::Buffer<uint8_t>>().Data();
  size_t output_buffer_len = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_base64_encode(input, input_len, output_buffer, output_buffer_len));
}

Napi::Value N_oc_blockwise_alloc_request_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[4].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_alloc_request_buffer(href, href_len, endpoint, method, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_alloc_response_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[4].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_alloc_response_buffer(href, href_len, endpoint, method, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

#if defined(XXX)
Napi::Value N_oc_blockwise_dispatch_block(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  uint32_t block_offset = static_cast<uint32_t>(info[1].As<Napi::Number>().Uint32Value());
  uint32_t requested_block_size = static_cast<uint32_t>(info[2].As<Napi::Number>().Uint32Value());
// 3 payload_size, uint32_t*
  //func return const void*
}
#endif

Napi::Value N_oc_blockwise_find_request_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  std::string query_ = info[4].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[5].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[6].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer(href, href_len, endpoint, method, query, query_len, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_client_cb(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  void* client_cb = info[1];
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer_by_client_cb(endpoint, client_cb));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer_by_mid(mid));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_token(const Napi::CallbackInfo& info) {
  uint8_t* token = info[0].As<Napi::Buffer<uint8_t>>().Data();
  uint8_t token_len = static_cast<uint8_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer_by_token(token, token_len));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  std::string query_ = info[4].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[5].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[6].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer(href, href_len, endpoint, method, query, query_len, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_client_cb(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  void* client_cb = info[1];
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer_by_client_cb(endpoint, client_cb));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer_by_mid(mid));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_token(const Napi::CallbackInfo& info) {
  uint8_t* token = info[0].As<Napi::Buffer<uint8_t>>().Data();
  uint8_t token_len = static_cast<uint8_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer_by_token(token, token_len));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_free_request_buffer(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  (void)oc_blockwise_free_request_buffer(buffer);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_free_response_buffer(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  (void)oc_blockwise_free_response_buffer(buffer);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_handle_block(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  uint32_t incoming_block_offset = static_cast<uint32_t>(info[1].As<Napi::Number>().Uint32Value());
  const uint8_t* incoming_block = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  uint32_t incoming_block_size = static_cast<uint32_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_blockwise_handle_block(buffer, incoming_block_offset, incoming_block, incoming_block_size));
}

Napi::Value N_oc_blockwise_scrub_buffers(const Napi::CallbackInfo& info) {
  bool all = info[0].As<Napi::Boolean>().Value();
  (void)oc_blockwise_scrub_buffers(all);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_scrub_buffers_for_client_cb(const Napi::CallbackInfo& info) {
  void* cb = info[0];
  (void)oc_blockwise_scrub_buffers_for_client_cb(cb);
  return info.Env().Undefined();
}

Napi::Value N_oc_allocate_message(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_message_t> sp(oc_allocate_message());
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

Napi::Value N_oc_allocate_message_from_pool(const Napi::CallbackInfo& info) {
  OCMemb& pool = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_message_t> sp(oc_allocate_message_from_pool(pool));
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions(const Napi::CallbackInfo& info) {
  (void)oc_close_all_tls_sessions();
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions_for_device(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_close_all_tls_sessions_for_device(device);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_internal_allocate_outgoing_message(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_message_t> sp(oc_internal_allocate_outgoing_message());
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

Napi::Value N_oc_message_add_ref(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_message_add_ref(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_message_unref(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_message_unref(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_recv_message(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_recv_message(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_message(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_send_message(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_buffers_avail_cb(const Napi::CallbackInfo& info) {
  oc_memb_buffers_avail_callback_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  (void)oc_set_buffers_avail_cb(cb);
  return info.Env().Undefined();
}

Napi::Value N_oc_get_block_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_get_block_size());
}

Napi::Value N_oc_get_max_app_data_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_get_max_app_data_size());
}

Napi::Value N_oc_get_mtu_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_get_mtu_size());
}

Napi::Value N_oc_set_max_app_data_size(const Napi::CallbackInfo& info) {
  size_t size = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_set_max_app_data_size(size);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_mtu_size(const Napi::CallbackInfo& info) {
  size_t mtu_size = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_set_mtu_size(mtu_size));
}

Napi::Value N_oc_ri_alloc_client_cb(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[2].As<Napi::Number>().Uint32Value());
  std::string query_ = info[3].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
// 4 handler, oc_client_handler_t
  oc_qos_t qos = static_cast<oc_qos_t>(info[5].As<Napi::Number>().Uint32Value());
  void* user_data = info[6];
  std::shared_ptr<oc_client_cb_t> sp(0);
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_find_client_cb_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_find_client_cb_by_mid(mid));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_find_client_cb_by_token(const Napi::CallbackInfo& info) {
  uint8_t* token = info[0].As<Napi::Buffer<uint8_t>>().Data();
  uint8_t token_len = static_cast<uint8_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_find_client_cb_by_token(token, token_len));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_free_client_cbs_by_endpoint(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_ri_free_client_cbs_by_endpoint(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_free_client_cbs_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_ri_free_client_cbs_by_mid(mid);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_get_client_cb(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_get_client_cb(uri, endpoint, method));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_invoke_client_cb(const Napi::CallbackInfo& info) {
  void* response = info[0];
// 1 response_state, oc_blockwise_state_t**
  OCClientCallback& cb = *OCClientCallback::Unwrap(info[2].As<Napi::Object>());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[3].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_ri_is_client_cb_valid(const Napi::CallbackInfo& info) {
  OCClientCallback& client_cb = *OCClientCallback::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_is_client_cb_valid(client_cb));
}

Napi::Value N_oc_ri_process_discovery_payload(const Napi::CallbackInfo& info) {
  uint8_t* payload = info[0].As<Napi::Buffer<uint8_t>>().Data();
  int len = static_cast<int>(info[1].As<Napi::Number>());
// 2 handler, oc_client_handler_t
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[3].As<Napi::Object>());
  void* user_data = info[4];
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_clock_init(const Napi::CallbackInfo& info) {
  (void)oc_clock_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_clock_seconds(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_clock_seconds());
}

Napi::Value N_oc_clock_time(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_clock_time());
}

Napi::Value N_oc_clock_wait(const Napi::CallbackInfo& info) {
  oc_clock_time_t t = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
  (void)oc_clock_wait(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_clock_encode_time_rfc3339(const Napi::CallbackInfo& info) {
  oc_clock_time_t time = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
  char* out_buf = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  size_t out_buf_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_encode_time_rfc3339(time, out_buf, out_buf_len));
}

Napi::Value N_oc_clock_parse_time_rfc3339(const Napi::CallbackInfo& info) {
  std::string in_buf_ = info[0].As<Napi::String>().Utf8Value();
  const char* in_buf = in_buf_.c_str();
  size_t in_buf_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_parse_time_rfc3339(in_buf, in_buf_len));
}

Napi::Value N_oc_clock_time_rfc3339(const Napi::CallbackInfo& info) {
  char* out_buf = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  size_t out_buf_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_time_rfc3339(out_buf, out_buf_len));
}

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_add_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cloud_add_resource(resource));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_delete_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_cloud_delete_resource(resource);
  return info.Env().Undefined();
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_deregister(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_deregister(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_discover_resources(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_discover_resources(ctx, handler, user_data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_get_context(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_cloud_context_t> sp(oc_cloud_get_context(device));
  auto args = Napi::External<std::shared_ptr<oc_cloud_context_t>>::New(info.Env(), &sp);
  return OCCloudContext::constructor.New({args});
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_get_token_expiry(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cloud_get_token_expiry(ctx));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_login(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_login(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_logout(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_logout(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_manager_start(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_manager_start(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_manager_stop(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cloud_manager_stop(ctx));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_provision_conf_resource(const Napi::CallbackInfo& info) {
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

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_publish_resources(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_cloud_publish_resources(device));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_refresh_token(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_refresh_token(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_register(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_register(ctx, cb, data));
}
#endif

Napi::Value N_oc_check_if_collection(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_check_if_collection(resource));
}

Napi::Value N_oc_collection_add(const Napi::CallbackInfo& info) {
  OCCollection& collection = *OCCollection::Unwrap(info[0].As<Napi::Object>());
  (void)oc_collection_add(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_alloc(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_collection_t> sp(oc_collection_alloc());
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_collection_free(const Napi::CallbackInfo& info) {
  OCCollection& collection = *OCCollection::Unwrap(info[0].As<Napi::Object>());
  (void)oc_collection_free(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_get_all(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_collection_t> sp(oc_collection_get_all());
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_free_rt_factories(const Napi::CallbackInfo& info) {
  (void)oc_collections_free_rt_factories();
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_get_collection_by_uri(const Napi::CallbackInfo& info) {
  std::string uri_path_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri_path = uri_path_.c_str();
  size_t uri_path_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_collection_t> sp(oc_get_collection_by_uri(uri_path, uri_path_len, device));
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_get_link_by_uri(const Napi::CallbackInfo& info) {
  OCCollection& collection = *OCCollection::Unwrap(info[0].As<Napi::Object>());
  std::string uri_path_ = info[1].As<Napi::String>().Utf8Value();
  const char* uri_path = uri_path_.c_str();
  int uri_path_len = static_cast<int>(info[2].As<Napi::Number>());
  std::shared_ptr<oc_link_t> sp(oc_get_link_by_uri(collection, uri_path, uri_path_len));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value N_oc_get_next_collection_with_link(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCCollection& start = *OCCollection::Unwrap(info[1].As<Napi::Object>());
  std::shared_ptr<oc_collection_t> sp(oc_get_next_collection_with_link(resource, start));
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_handle_collection_request(const Napi::CallbackInfo& info) {
  oc_method_t method = static_cast<oc_method_t>(info[0].As<Napi::Number>().Uint32Value());
  OCRequest& request = *OCRequest::Unwrap(info[1].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[2].As<Napi::Number>().Uint32Value());
  OCResource& notify_resource = *OCResource::Unwrap(info[3].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_handle_collection_request(method, request, iface_mask, notify_resource));
}

Napi::Value N_oc_link_set_interfaces(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t new_interfaces = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_link_set_interfaces(link, new_interfaces);
  return info.Env().Undefined();
}

Napi::Value N_handle_network_interface_event_callback(const Napi::CallbackInfo& info) {
  oc_interface_event_t event = static_cast<oc_interface_event_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)handle_network_interface_event_callback(event);
  return info.Env().Undefined();
}

Napi::Value N_handle_session_event_callback(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  oc_session_state_t state = static_cast<oc_session_state_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)handle_session_event_callback(endpoint, state);
  return info.Env().Undefined();
}

#if defined(OC_TCP)
Napi::Value N_oc_connectivity_end_session(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_connectivity_end_session(endpoint);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_connectivity_get_endpoints(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_endpoint_t> sp(oc_connectivity_get_endpoints(device));
  auto args = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({args});
}

Napi::Value N_oc_connectivity_init(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_connectivity_init(device));
}

Napi::Value N_oc_connectivity_shutdown(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_connectivity_shutdown(device);
  return info.Env().Undefined();
}

Napi::Value N_oc_dns_lookup(const Napi::CallbackInfo& info) {
  std::string domain_ = info[0].As<Napi::String>().Utf8Value();
  const char* domain = domain_.c_str();
  OCMmem& addr = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  enum transport_flags flags = static_cast<enum transport_flags>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_dns_lookup(domain, addr, flags));
}

Napi::Value N_oc_send_buffer(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_send_buffer(message));
}

Napi::Value N_oc_send_discovery_request(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_send_discovery_request(message);
  return info.Env().Undefined();
}

#if defined(OC_TCP)
Napi::Value N_oc_tcp_get_csm_state(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_tcp_get_csm_state(endpoint));
}
#endif

#if defined(OC_TCP)
Napi::Value N_oc_tcp_update_csm_state(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  tcp_csm_state_t csm = static_cast<tcp_csm_state_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_tcp_update_csm_state(endpoint, csm));
}
#endif

Napi::Value N_oc_core_add_new_device(const Napi::CallbackInfo& info) {
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

Napi::Value N_oc_core_encode_interfaces_mask(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_core_encode_interfaces_mask(parent, iface_mask);
  return info.Env().Undefined();
}

Napi::Value N_oc_core_get_device_id(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_uuid_t> sp(oc_core_get_device_id(device));
  auto args = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({args});
}

Napi::Value N_oc_core_get_device_info(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_device_info_t> sp(oc_core_get_device_info(device));
  auto args = Napi::External<std::shared_ptr<oc_device_info_t>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({args});
}

Napi::Value N_oc_core_get_latency(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_core_get_latency());
}

Napi::Value N_oc_core_get_num_devices(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_core_get_num_devices());
}

Napi::Value N_oc_core_get_platform_info(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_platform_info_t> sp(oc_core_get_platform_info());
  auto args = Napi::External<std::shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({args});
}

Napi::Value N_oc_core_get_resource_by_index(const Napi::CallbackInfo& info) {
  int type = static_cast<int>(info[0].As<Napi::Number>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_core_get_resource_by_index(type, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_core_get_resource_by_uri(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_core_get_resource_by_uri(uri, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_core_init(const Napi::CallbackInfo& info) {
  (void)oc_core_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_core_init_platform(const Napi::CallbackInfo& info) {
  std::string mfg_name_ = info[0].As<Napi::String>().Utf8Value();
  const char* mfg_name = mfg_name_.c_str();
  oc_core_init_platform_cb_t init_cb = nullptr;
  Napi::Function init_cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  std::shared_ptr<oc_platform_info_t> sp(oc_core_init_platform(mfg_name, init_cb, data));
  auto args = Napi::External<std::shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({args});
}

Napi::Value N_oc_core_is_DCR(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_core_is_DCR(resource, device));
}

Napi::Value N_oc_core_populate_resource(const Napi::CallbackInfo& info) {
  int core_resource = static_cast<int>(info[0].As<Napi::Number>());
  size_t device_index = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::string uri_ = info[2].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_interface_mask_t default_interface = static_cast<oc_interface_mask_t>(info[4].As<Napi::Number>().Uint32Value());
  int properties = static_cast<int>(info[5].As<Napi::Number>());
  oc_request_callback_t get_cb = nullptr;
  Napi::Function get_cb_ = info[6].As<Napi::Function>();
  oc_request_callback_t put_cb = nullptr;
  Napi::Function put_cb_ = info[7].As<Napi::Function>();
  oc_request_callback_t post_cb = nullptr;
  Napi::Function post_cb_ = info[8].As<Napi::Function>();
  oc_request_callback_t delete_cb = nullptr;
  Napi::Function delete_cb_ = info[9].As<Napi::Function>();
  int num_resource_types = static_cast<int>(info[10].As<Napi::Number>());
  (void)oc_core_populate_resource(core_resource, device_index, uri, iface_mask, default_interface, properties, get_cb, put_cb, post_cb, delete_cb, num_resource_types);
  return info.Env().Undefined();
}

Napi::Value N_oc_core_set_latency(const Napi::CallbackInfo& info) {
  int latency = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_core_set_latency(latency);
  return info.Env().Undefined();
}

Napi::Value N_oc_core_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_core_shutdown();
  return info.Env().Undefined();
}

Napi::Value N_oc_filter_resource_by_rt(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCRequest& request = *OCRequest::Unwrap(info[1].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_filter_resource_by_rt(resource, request));
}

Napi::Value N_oc_store_uri(const Napi::CallbackInfo& info) {
  std::string s_uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* s_uri = s_uri_.c_str();
  OCMmem& d_uri = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  (void)oc_store_uri(s_uri, d_uri);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value N_oc_cred_credtype_string(const Napi::CallbackInfo& info) {
  oc_sec_credtype_t credtype = static_cast<oc_sec_credtype_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_cred_credtype_string(credtype));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_cred_parse_credusage(const Napi::CallbackInfo& info) {
  OCMmem& credusage_string = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cred_parse_credusage(credusage_string));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_cred_parse_encoding(const Napi::CallbackInfo& info) {
  OCMmem& encoding_string = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_cred_parse_encoding(encoding_string));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_cred_read_credusage(const Napi::CallbackInfo& info) {
  oc_sec_credusage_t credusage = static_cast<oc_sec_credusage_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_cred_read_credusage(credusage));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_cred_read_encoding(const Napi::CallbackInfo& info) {
  oc_sec_encoding_t encoding = static_cast<oc_sec_encoding_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_cred_read_encoding(encoding));
}
#endif

Napi::Value N_oc_create_discovery_resource(const Napi::CallbackInfo& info) {
  int resource_idx = static_cast<int>(info[0].As<Napi::Number>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_create_discovery_resource(resource_idx, device);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_compare(const Napi::CallbackInfo& info) {
  OCEndpoint& ep1 = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& ep2 = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_compare(ep1, ep2));
}

Napi::Value N_oc_endpoint_compare_address(const Napi::CallbackInfo& info) {
  OCEndpoint& ep1 = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& ep2 = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_compare_address(ep1, ep2));
}

Napi::Value N_oc_endpoint_copy(const Napi::CallbackInfo& info) {
  OCEndpoint& dst = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& src = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  (void)oc_endpoint_copy(dst, src);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_list_copy(const Napi::CallbackInfo& info) {
// 0 dst, oc_endpoint_t**
  OCEndpoint& src = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_set_di(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCUuid& di = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  (void)oc_endpoint_set_di(endpoint, di);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_set_local_address(const Napi::CallbackInfo& info) {
  OCEndpoint& ep = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  int interface_index = static_cast<int>(info[1].As<Napi::Number>());
  (void)oc_endpoint_set_local_address(ep, interface_index);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_string_parse_path(const Napi::CallbackInfo& info) {
  OCMmem& endpoint_str = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  OCMmem& path = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_string_parse_path(endpoint_str, path));
}

Napi::Value N_oc_endpoint_to_string(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  OCMmem& endpoint_str = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_endpoint_to_string(endpoint, endpoint_str));
}

Napi::Value N_oc_free_endpoint(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_free_endpoint(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_ipv6_endpoint_is_link_local(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_ipv6_endpoint_is_link_local(endpoint));
}

Napi::Value N_oc_new_endpoint(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_endpoint_t> sp(oc_new_endpoint());
  auto args = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({args});
}

Napi::Value N_oc_string_to_endpoint(const Napi::CallbackInfo& info) {
  OCMmem& endpoint_str = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  OCMmem& uri = *OCMmem::Unwrap(info[2].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_string_to_endpoint(endpoint_str, endpoint, uri));
}

Napi::Value N_oc_enum_pos_desc_to_str(const Napi::CallbackInfo& info) {
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_enum_pos_desc_to_str(pos));
}

Napi::Value N_oc_enum_to_str(const Napi::CallbackInfo& info) {
  oc_enum_t val = static_cast<oc_enum_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::String::New(info.Env(), oc_enum_to_str(val));
}

Napi::Value N__oc_alloc_string(const Napi::CallbackInfo& info) {
  OCMmem& ocstring = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_alloc_string(ocstring, size);
  return info.Env().Undefined();
}

Napi::Value N__oc_alloc_string_array(const Napi::CallbackInfo& info) {
  OCMmem& ocstringarray = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_alloc_string_array(ocstringarray, size);
  return info.Env().Undefined();
}

Napi::Value N__oc_free_array(const Napi::CallbackInfo& info) {
  OCArray& ocarray = *OCArray::Unwrap(info[0].As<Napi::Object>());
  pool type = static_cast<pool>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_free_array(ocarray, type);
  return info.Env().Undefined();
}

Napi::Value N__oc_free_string(const Napi::CallbackInfo& info) {
  OCMmem& ocstring = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  (void)_oc_free_string(ocstring);
  return info.Env().Undefined();
}

Napi::Value N__oc_new_array(const Napi::CallbackInfo& info) {
  OCArray& ocarray = *OCArray::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  pool type = static_cast<pool>(info[2].As<Napi::Number>().Uint32Value());
  (void)_oc_new_array(ocarray, size, type);
  return info.Env().Undefined();
}

Napi::Value N__oc_new_string(const Napi::CallbackInfo& info) {
  OCMmem& ocstring = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  std::string str_ = info[1].As<Napi::String>().Utf8Value();
  const char* str = str_.c_str();
  size_t str_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)_oc_new_string(ocstring, str, str_len);
  return info.Env().Undefined();
}

Napi::Value N_oc_concat_strings(const Napi::CallbackInfo& info) {
  OCMmem& concat = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  std::string str1_ = info[1].As<Napi::String>().Utf8Value();
  const char* str1 = str1_.c_str();
  std::string str2_ = info[2].As<Napi::String>().Utf8Value();
  const char* str2 = str2_.c_str();
  (void)oc_concat_strings(concat, str1, str2);
  return info.Env().Undefined();
}

Napi::Value N_oc_join_string_array(const Napi::CallbackInfo& info) {
  OCMmem& ocstringarray = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  OCMmem& ocstring = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  (void)oc_join_string_array(ocstringarray, ocstring);
  return info.Env().Undefined();
}

#if defined(OC_IDD_API)
Napi::Value N_oc_set_introspection_data(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  uint8_t* IDD = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t IDD_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_set_introspection_data(device, IDD, IDD_size);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_memb_init(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  (void)oc_memb_init(m);
  return info.Env().Undefined();
}

Napi::Value N_oc_memb_inmemb(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  void* ptr = info[1];
  return Napi::Number::New(info.Env(), oc_memb_inmemb(m, ptr));
}

Napi::Value N_oc_memb_numfree(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_memb_numfree(m));
}

Napi::Value N_oc_memb_set_buffers_avail_cb(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  oc_memb_buffers_avail_callback_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  (void)oc_memb_set_buffers_avail_cb(m, cb);
  return info.Env().Undefined();
}

#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_add_pace(const Napi::CallbackInfo& info) {
  std::string func_ = info[0].As<Napi::String>().Utf8Value();
  const char* func = func_.c_str();
  int size = static_cast<int>(info[1].As<Napi::Number>());
  int type = static_cast<int>(info[2].As<Napi::Number>());
  void* address = info[3];
  (void)oc_mem_trace_add_pace(func, size, type, address);
  return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_init(const Napi::CallbackInfo& info) {
  (void)oc_mem_trace_init();
  return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_mem_trace_shutdown();
  return info.Env().Undefined();
}
#endif

Napi::Value N__oc_mmem_alloc(const Napi::CallbackInfo& info) {
  OCMmem& m = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  pool pool_type = static_cast<pool>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), _oc_mmem_alloc(m, size, pool_type));
}

Napi::Value N__oc_mmem_free(const Napi::CallbackInfo& info) {
  OCMmem& m = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  pool pool_type = static_cast<pool>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_mmem_free(m, pool_type);
  return info.Env().Undefined();
}

Napi::Value N_oc_mmem_init(const Napi::CallbackInfo& info) {
  (void)oc_mmem_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_network_event(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_network_interface_event(const Napi::CallbackInfo& info) {
  oc_interface_event_t event = static_cast<oc_interface_event_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_network_interface_event(event);
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_destroy(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_destroy();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_init(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_lock(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_lock();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_unlock(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_unlock();
  return info.Env().Undefined();
}

Napi::Value N_oc_add_network_interface_event_callback(const Napi::CallbackInfo& info) {
  interface_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_add_network_interface_event_callback(cb));
}

Napi::Value N_oc_add_session_event_callback(const Napi::CallbackInfo& info) {
  session_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_add_session_event_callback(cb));
}

Napi::Value N_oc_remove_network_interface_event_callback(const Napi::CallbackInfo& info) {
  interface_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_remove_network_interface_event_callback(cb));
}

Napi::Value N_oc_remove_session_event_callback(const Napi::CallbackInfo& info) {
  session_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_remove_session_event_callback(cb));
}

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_add_permission(const Napi::CallbackInfo& info) {
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[0].As<Napi::Object>());
  oc_ace_permissions_t permission = static_cast<oc_ace_permissions_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_obt_ace_add_permission(ace, permission);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_new_resource(const Napi::CallbackInfo& info) {
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_ace_res_t> sp(oc_obt_ace_new_resource(ace));
  auto args = Napi::External<std::shared_ptr<oc_ace_res_t>>::New(info.Env(), &sp);
  return OCAceResource::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_resource_set_href(const Napi::CallbackInfo& info) {
  OCAceResource& resource = *OCAceResource::Unwrap(info[0].As<Napi::Object>());
  std::string href_ = info[1].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  (void)oc_obt_ace_resource_set_href(resource, href);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_resource_set_wc(const Napi::CallbackInfo& info) {
  OCAceResource& resource = *OCAceResource::Unwrap(info[0].As<Napi::Object>());
  oc_ace_wildcard_t wc = static_cast<oc_ace_wildcard_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_obt_ace_resource_set_wc(resource, wc);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_add_roleid(const Napi::CallbackInfo& info) {
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
Napi::Value N_oc_obt_delete_ace_by_aceid(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  int aceid = static_cast<int>(info[1].As<Napi::Number>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_delete_ace_by_aceid(uuid, aceid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_delete_cred_by_credid(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  int credid = static_cast<int>(info[1].As<Napi::Number>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_delete_cred_by_credid(uuid, credid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_delete_own_cred_by_credid(const Napi::CallbackInfo& info) {
  int credid = static_cast<int>(info[0].As<Napi::Number>());
  return Napi::Number::New(info.Env(), oc_obt_delete_own_cred_by_credid(credid));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_device_hard_reset(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_device_hard_reset(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_all_resources(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_discover_all_resources(uuid, handler, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_owned_devices(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_unowned_devices(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_free_ace(const Napi::CallbackInfo& info) {
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_ace(ace);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_free_acl(const Napi::CallbackInfo& info) {
  OCSecurityAcl& acl = *OCSecurityAcl::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_acl(acl);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_free_creds(const Napi::CallbackInfo& info) {
  OCCreds& creds = *OCCreds::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_creds(creds);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_free_roleid(const Napi::CallbackInfo& info) {
  OCRole& roles = *OCRole::Unwrap(info[0].As<Napi::Object>());
  (void)oc_obt_free_roleid(roles);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_init(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_obt_init());
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_new_ace_for_connection(const Napi::CallbackInfo& info) {
  oc_ace_connection_type_t conn = static_cast<oc_ace_connection_type_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_connection(conn));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_new_ace_for_role(const Napi::CallbackInfo& info) {
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
Napi::Value N_oc_obt_new_ace_for_subject(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_subject(uuid));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_perform_cert_otm(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_perform_cert_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_perform_just_works_otm(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_perform_just_works_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_perform_random_pin_otm(const Napi::CallbackInfo& info) {
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
Napi::Value N_oc_obt_provision_ace(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  OCSecurityAce& ace = *OCSecurityAce::Unwrap(info[1].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_ace(subject, ace, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_auth_wildcard_ace(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_provision_auth_wildcard_ace(subject, cb, data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_provision_identity_certificate(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_provision_identity_certificate(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_pairwise_credentials(const Napi::CallbackInfo& info) {
  OCUuid& uuid1 = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  OCUuid& uuid2 = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_pairwise_credentials(uuid1, uuid2, cb, data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_provision_role_certificate(const Napi::CallbackInfo& info) {
  OCRole& roles = *OCRole::Unwrap(info[0].As<Napi::Object>());
  OCUuid& uuid = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_role_certificate(roles, uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_role_wildcard_ace(const Napi::CallbackInfo& info) {
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
Napi::Value N_oc_obt_request_random_pin(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_request_random_pin(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_retrieve_acl(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_acl_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_retrieve_acl(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_retrieve_creds(const Napi::CallbackInfo& info) {
  OCUuid& subject = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  oc_obt_creds_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_retrieve_creds(subject, cb, data));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_retrieve_own_creds(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_sec_creds_t> sp(oc_obt_retrieve_own_creds());
  auto args = Napi::External<std::shared_ptr<oc_sec_creds_t>>::New(info.Env(), &sp);
  return OCCreds::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_set_sd_info(const Napi::CallbackInfo& info) {
  char* name = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  bool priv = info[1].As<Napi::Boolean>().Value();
  (void)oc_obt_set_sd_info(name, priv);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_obt_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_obt_shutdown();
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_mfg_cert(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  const unsigned char* key = info[3].As<Napi::Buffer<const uint8_t>>().Data();
  size_t key_size = static_cast<size_t>(info[4].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_cert(device, cert, cert_size, key, key_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_mfg_intermediate_cert(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  int credid = static_cast<int>(info[1].As<Napi::Number>());
  const unsigned char* cert = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_intermediate_cert(device, credid, cert, cert_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_mfg_trust_anchor(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_trust_anchor(device, cert, cert_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_trust_anchor(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_trust_anchor(device, cert, cert_size));
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_pki_set_security_profile(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_sp_types_t supported_profiles = static_cast<oc_sp_types_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_sp_types_t current_profile = static_cast<oc_sp_types_t>(info[2].As<Napi::Number>().Uint32Value());
  int mfg_credid = static_cast<int>(info[3].As<Napi::Number>());
  (void)oc_pki_set_security_profile(device, supported_profiles, current_profile, mfg_credid);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_random_destroy(const Napi::CallbackInfo& info) {
  (void)oc_random_destroy();
  return info.Env().Undefined();
}

Napi::Value N_oc_random_init(const Napi::CallbackInfo& info) {
  (void)oc_random_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_random_value(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_random_value());
}

Napi::Value N_oc_free_rep(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  (void)oc_free_rep(rep);
  return info.Env().Undefined();
}

Napi::Value N_oc_parse_rep(const Napi::CallbackInfo& info) {
  const uint8_t* payload = info[0].As<Napi::Buffer<const uint8_t>>().Data();
  int payload_size = static_cast<int>(info[1].As<Napi::Number>());
// 2 value_list, oc_rep_t**
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_bool(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, bool*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_bool_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, bool**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_byte_string(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_byte_string_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  OCMmem& value = *OCMmem::Unwrap(info[2].As<Napi::Object>());
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), oc_rep_get_byte_string_array(rep, key, value, size));
}

Napi::Value N_oc_rep_get_cbor_errno(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_rep_get_cbor_errno());
}

Napi::Value N_oc_rep_get_double(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, double*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_double_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, double**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_encoded_payload_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_rep_get_encoded_payload_size());
}

Napi::Value N_oc_rep_get_encoder_buf(const Napi::CallbackInfo& info) {
return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(oc_rep_get_encoder_buf()), oc_rep_get_encoded_payload_size() );
}

Napi::Value N_oc_rep_get_int(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, int64_t*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_int_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, int64_t**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_object(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, oc_rep_t**
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_object_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, oc_rep_t**
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_string(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_string_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  OCMmem& value = *OCMmem::Unwrap(info[2].As<Napi::Object>());
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), oc_rep_get_string_array(rep, key, value, size));
}

Napi::Value N_oc_rep_new(const Napi::CallbackInfo& info) {
  uint8_t* payload = info[0].As<Napi::Buffer<uint8_t>>().Data();
  int size = static_cast<int>(info[1].As<Napi::Number>());
  (void)oc_rep_new(payload, size);
  return info.Env().Undefined();
}

Napi::Value N_oc_rep_set_pool(const Napi::CallbackInfo& info) {
  OCMemb& rep_objects_pool = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  (void)oc_rep_set_pool(rep_objects_pool);
  return info.Env().Undefined();
}

Napi::Value N_oc_rep_to_json(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  char* buf = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  size_t buf_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  bool pretty_print = info[3].As<Napi::Boolean>().Value();
  return Napi::Number::New(info.Env(), oc_rep_to_json(rep, buf, buf_size, pretty_print));
}

#if defined(OC_SERVER)
Napi::Value N_oc_ri_add_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_add_resource(resource));
}
#endif

Napi::Value N_oc_ri_add_timed_event_callback_ticks(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t event_callback = nullptr;
  Napi::Function event_callback_ = info[1].As<Napi::Function>();
  oc_clock_time_t ticks = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
  (void)oc_ri_add_timed_event_callback_ticks(cb_data, event_callback, ticks);
  return info.Env().Undefined();
}

#if defined(OC_SERVER)
Napi::Value N_oc_ri_alloc_resource(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_ri_alloc_resource());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}
#endif

#if defined(OC_SERVER)
Napi::Value N_oc_ri_delete_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_delete_resource(resource));
}
#endif

Napi::Value N_oc_ri_free_resource_properties(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_ri_free_resource_properties(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_get_app_resource_by_uri(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  size_t uri_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_ri_get_app_resource_by_uri(uri, uri_len, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_ri_get_app_resources(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_ri_get_app_resources());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_ri_get_interface_mask(const Napi::CallbackInfo& info) {
  char* iface = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  size_t if_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_ri_get_interface_mask(iface, if_len));
}

Napi::Value N_oc_ri_get_query_nth_key_value(const Napi::CallbackInfo& info) {
  std::string query_ = info[0].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
// 2 key, char**
  size_t* key_len = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
// 4 value, char**
  size_t* value_len = reinterpret_cast<size_t*>(info[5].As<Napi::Uint32Array>().Data());
  size_t n = static_cast<size_t>(info[6].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_ri_get_query_value(const Napi::CallbackInfo& info) {
  std::string query_ = info[0].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::string key_ = info[2].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 3 value, char**
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_ri_init(const Napi::CallbackInfo& info) {
  (void)oc_ri_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_is_app_resource_valid(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_is_app_resource_valid(resource));
}

Napi::Value N_oc_ri_remove_timed_event_callback(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t event_callback = nullptr;
  Napi::Function event_callback_ = info[1].As<Napi::Function>();
  (void)oc_ri_remove_timed_event_callback(cb_data, event_callback);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_ri_shutdown();
  return info.Env().Undefined();
}

Napi::Value N_oc_status_code(const Napi::CallbackInfo& info) {
  oc_status_t key = static_cast<oc_status_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_status_code(key));
}

#if defined(OC_TCP)
Napi::Value N_oc_session_end_event(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_session_end_event(endpoint);
  return info.Env().Undefined();
}
#endif

#if defined(OC_TCP)
Napi::Value N_oc_session_events_set_event_delay(const Napi::CallbackInfo& info) {
  int secs = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_session_events_set_event_delay(secs);
  return info.Env().Undefined();
}
#endif

#if defined(OC_TCP)
Napi::Value N_oc_session_start_event(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_session_start_event(endpoint);
  return info.Env().Undefined();
}
#endif

Napi::Value N__oc_signal_event_loop(const Napi::CallbackInfo& info) {
  (void)_oc_signal_event_loop();
  return info.Env().Undefined();
}

Napi::Value N_oc_storage_config(const Napi::CallbackInfo& info) {
  std::string store_ = info[0].As<Napi::String>().Utf8Value();
  const char* store = store_.c_str();
  return Napi::Number::New(info.Env(), oc_storage_config(store));
}

Napi::Value N_oc_storage_read(const Napi::CallbackInfo& info) {
  std::string store_ = info[0].As<Napi::String>().Utf8Value();
  const char* store = store_.c_str();
  uint8_t* buf = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_storage_read(store, buf, size));
}

Napi::Value N_oc_storage_write(const Napi::CallbackInfo& info) {
  std::string store_ = info[0].As<Napi::String>().Utf8Value();
  const char* store = store_.c_str();
  uint8_t* buf = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_storage_write(store, buf, size));
}

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_done(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_done(device, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_downloaded(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string version_ = info[1].As<Napi::String>().Utf8Value();
  const char* version = version_.c_str();
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_downloaded(device, version, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_new_version_available(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::string version_ = info[1].As<Napi::String>().Utf8Value();
  const char* version = version_.c_str();
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_new_version_available(device, version, result);
  return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_upgrading(const Napi::CallbackInfo& info) {
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
Napi::Value N_oc_swupdate_set_impl(const Napi::CallbackInfo& info) {
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

Napi::Value N_oc_gen_uuid(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  (void)oc_gen_uuid(uuid);
  return info.Env().Undefined();
}

Napi::Value N_oc_str_to_uuid(const Napi::CallbackInfo& info) {
  std::string str_ = info[0].As<Napi::String>().Utf8Value();
  const char* str = str_.c_str();
  OCUuid& uuid = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  (void)oc_str_to_uuid(str, uuid);
  return info.Env().Undefined();
}

Napi::Value N_oc_uuid_to_str(const Napi::CallbackInfo& info) {
  OCUuid& uuid = *OCUuid::Unwrap(info[0].As<Napi::Object>());
  char* buffer = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  int buflen = static_cast<int>(info[2].As<Napi::Number>());
  (void)oc_uuid_to_str(uuid, buffer, buflen);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_double(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  double value = info[2].As<Napi::Number>().DoubleValue();
  (void)helper_rep_set_double(object, key, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_long(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  int64_t value = static_cast<int64_t>(info[2].As<Napi::Number>());
  (void)helper_rep_set_long(object, key, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_uint(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, unsigned int
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_boolean(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  bool value = info[2].As<Napi::Boolean>().Value();
  (void)helper_rep_set_boolean(object, key, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_text_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::string value_ = info[2].As<Napi::String>().Utf8Value();
  const char* value = value_.c_str();
  (void)helper_rep_set_text_string(object, key, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_byte_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  const unsigned char* value = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  size_t length = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)helper_rep_set_byte_string(object, key, value, length);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_start_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<CborEncoder> sp(helper_rep_start_array(parent));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_end_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_end_array(parent, arrayObject);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_start_links_array(const Napi::CallbackInfo& info) {
  std::shared_ptr<CborEncoder> sp(helper_rep_start_links_array());
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_end_links_array(const Napi::CallbackInfo& info) {
  (void)helper_rep_end_links_array();
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_start_root_object(const Napi::CallbackInfo& info) {
  std::shared_ptr<CborEncoder> sp(helper_rep_start_root_object());
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_end_root_object(const Napi::CallbackInfo& info) {
  (void)helper_rep_end_root_object();
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_add_byte_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  const unsigned char* value = info[1].As<Napi::Buffer<const uint8_t>>().Data();
// 2 length, const size_t
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_add_text_string(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string value_ = info[1].As<Napi::String>().Utf8Value();
  const char* value = value_.c_str();
  (void)helper_rep_add_text_string(arrayObject, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_add_double(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
// 1 value, const double
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_add_int(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  const int64_t value = static_cast<const int64_t>(info[1].As<Napi::Number>());
  (void)helper_rep_add_int(arrayObject, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_add_boolean(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
// 1 value, const bool
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_key(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  (void)helper_rep_set_key(parent, key);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::shared_ptr<CborEncoder> sp(helper_rep_set_array(parent, key));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_open_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::shared_ptr<CborEncoder> sp(helper_rep_open_array(parent, key));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_close_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_close_array(object, arrayObject);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_start_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<CborEncoder> sp(helper_rep_start_object(parent));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_end_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_end_object(parent, object);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_object_array_start_item(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<CborEncoder> sp(helper_rep_object_array_start_item(arrayObject));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_object_array_end_item(const Napi::CallbackInfo& info) {
  OCCborEncoder& parentArrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_object_array_end_item(parentArrayObject, arrayObject);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_open_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::shared_ptr<CborEncoder> sp(helper_rep_open_object(parent, key));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_close_object(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[1].As<Napi::Object>());
  (void)helper_rep_close_object(parent, object);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_long_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, int64_t*
  int length = static_cast<int>(info[3].As<Napi::Number>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_bool_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, bool*
  int length = static_cast<int>(info[3].As<Napi::Number>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_double_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, double*
  int length = static_cast<int>(info[3].As<Napi::Number>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_rep_set_string_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& object = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 values, oc_string_array_t
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_get_rep_from_root_object(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_rep_t> sp(helper_rep_get_rep_from_root_object());
  auto args = Napi::External<std::shared_ptr<oc_rep_t>>::New(info.Env(), &sp);
  return OCRep::constructor.New({args});
}

Napi::Value N_helper_rep_get_cbor_errno(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), helper_rep_get_cbor_errno());
}

Napi::Value N_helper_rep_clear_cbor_errno(const Napi::CallbackInfo& info) {
  (void)helper_rep_clear_cbor_errno();
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_delete_buffer(const Napi::CallbackInfo& info) {
  (void)helper_rep_delete_buffer();
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_new_buffer(const Napi::CallbackInfo& info) {
  int size = static_cast<int>(info[0].As<Napi::Number>());
  (void)helper_rep_new_buffer(size);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_oc_array_to_int_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
      return Napi::Buffer<int64_t>::New(info.Env(), oc_int_array(*static_cast<oc_array_t*>(array)), oc_int_array_size(*(oc_array_t*)array));
}

Napi::Value N_helper_rep_oc_array_to_bool_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
      return Napi::Buffer<bool>::New(info.Env(), oc_bool_array(*static_cast<oc_array_t*>(array)), oc_bool_array_size(*(oc_array_t*)array));
}

Napi::Value N_helper_rep_oc_array_to_double_array(const Napi::CallbackInfo& info) {
  OCArray& array = *OCArray::Unwrap(info[0].As<Napi::Object>());
      return Napi::Buffer<double>::New(info.Env(), oc_double_array(*static_cast<oc_array_t*>(array)), oc_double_array_size(*(oc_array_t*)array));
}

Napi::Value N_helper_rep_oc_array_to_string_array(const Napi::CallbackInfo& info) {
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

Napi::Value N_helper_oc_do_ip_discovery(const Napi::CallbackInfo& info) {
  std::string di_ = info[0].As<Napi::String>().Utf8Value();
  const char* di = di_.c_str();
  std::string uri_ = info[1].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
// 2 types, oc_string_array_t
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[3].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[4].As<Napi::Object>());
  oc_resource_properties_t bm = static_cast<oc_resource_properties_t>(info[5].As<Napi::Number>().Uint32Value());
  void* user_data = info[6];
  return Napi::Number::New(info.Env(), 0);
}

