#include "functions.h"
Napi::Value N_oc_assert_all_roles(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  (void)oc_assert_all_roles(endpoint, handler, user_data);
  return info.Env().Undefined();
}

Napi::Value N_oc_assert_role(const Napi::CallbackInfo& info) {
  const char* role = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* authority = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[2]);
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  void* user_data = info[4];
  return Napi::Boolean::New(info.Env(), oc_assert_role(role, authority, endpoint, handler, user_data));
}

Napi::Value N_oc_auto_assert_roles(const Napi::CallbackInfo& info) {
  bool auto_assert = info[0].As<Napi::Boolean>().Value();
  (void)oc_auto_assert_roles(auto_assert);
  return info.Env().Undefined();
}

Napi::Value N_oc_get_all_roles(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_role_t> sp(oc_get_all_roles());
  auto args = Napi::External<std::shared_ptr<oc_role_t>>::New(info.Env(), &sp);
  return OCRole::constructor.New({args});
}

Napi::Value N_oc_close_session(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_close_session(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_do_delete(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  const char* query = info[2].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_do_delete(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_do_get(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  const char* query = info[2].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_do_get(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_do_ip_discovery(const Napi::CallbackInfo& info) {
  const char* rt = info[0].As<Napi::String>().Utf8Value().c_str();
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
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  void* user_data = info[2];
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_all_at_endpoint(handler, endpoint, user_data));
}

Napi::Value N_oc_do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info) {
  const char* rt = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_discovery_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[2]);
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, user_data));
}

Napi::Value N_oc_do_ip_multicast(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* query = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_ip_multicast(uri, query, handler, user_data));
}

Napi::Value N_oc_do_observe(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  const char* query = info[2].As<Napi::String>().Utf8Value().c_str();
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
  const char* rt = info[0].As<Napi::String>().Utf8Value().c_str();
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
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* query = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_realm_local_ipv6_multicast(uri, query, handler, user_data));
}

Napi::Value N_oc_do_site_local_ipv6_discovery(const Napi::CallbackInfo& info) {
  const char* rt = info[0].As<Napi::String>().Utf8Value().c_str();
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
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* query = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  return Napi::Boolean::New(info.Env(), oc_do_site_local_ipv6_multicast(uri, query, handler, user_data));
}

Napi::Value N_oc_free_server_endpoints(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_free_server_endpoints(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_init_post(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  const char* query = info[2].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_init_post(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_init_put(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  const char* query = info[2].As<Napi::String>().Utf8Value().c_str();
  oc_response_handler_t handler = nullptr;
  Napi::Function handler_ = info[3].As<Napi::Function>();
  oc_qos_t qos = static_cast<oc_qos_t>(info[4].As<Napi::Number>().Uint32Value());
  void* user_data = info[5];
  return Napi::Boolean::New(info.Env(), oc_init_put(uri, endpoint, query, handler, qos, user_data));
}

Napi::Value N_oc_stop_multicast(const Napi::CallbackInfo& info) {
  oc_client_response_t* response;// = dynamic_cast<OCClientResponse>(info[0]);
  (void)oc_stop_multicast(response);
  return info.Env().Undefined();
}

Napi::Value N_oc_stop_observe(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  return Napi::Boolean::New(info.Env(), oc_stop_observe(uri, endpoint));
}

Napi::Value N_oc_add_collection(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  (void)oc_add_collection(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_add_link(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  oc_link_s* link;// = dynamic_cast<OCLink>(info[1]);
  (void)oc_collection_add_link(collection, link);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_add_mandatory_rt(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  const char* rt = info[1].As<Napi::String>().Utf8Value().c_str();
  return Napi::Boolean::New(info.Env(), oc_collection_add_mandatory_rt(collection, rt));
}

Napi::Value N_oc_collection_add_supported_rt(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  const char* rt = info[1].As<Napi::String>().Utf8Value().c_str();
  return Napi::Boolean::New(info.Env(), oc_collection_add_supported_rt(collection, rt));
}

Napi::Value N_oc_collection_get_collections(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_collection_get_collections());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_collection_get_links(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  std::shared_ptr<oc_link_t> sp(oc_collection_get_links(collection));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value N_oc_collection_remove_link(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  oc_link_s* link;// = dynamic_cast<OCLink>(info[1]);
  (void)oc_collection_remove_link(collection, link);
  return info.Env().Undefined();
}

Napi::Value N_oc_delete_collection(const Napi::CallbackInfo& info) {
  oc_resource_s* collection;// = dynamic_cast<OCResource>(info[0]);
  (void)oc_delete_collection(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_delete_link(const Napi::CallbackInfo& info) {
  oc_link_s* link;// = dynamic_cast<OCLink>(info[0]);
  (void)oc_delete_link(link);
  return info.Env().Undefined();
}

Napi::Value N_oc_link_add_link_param(const Napi::CallbackInfo& info) {
  oc_link_s* link;// = dynamic_cast<OCLink>(info[0]);
  const char* key = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* value = info[2].As<Napi::String>().Utf8Value().c_str();
  (void)oc_link_add_link_param(link, key, value);
  return info.Env().Undefined();
}

Napi::Value N_oc_link_add_rel(const Napi::CallbackInfo& info) {
  oc_link_s* link;// = dynamic_cast<OCLink>(info[0]);
  const char* rel = info[1].As<Napi::String>().Utf8Value().c_str();
  (void)oc_link_add_rel(link, rel);
  return info.Env().Undefined();
}

Napi::Value N_oc_new_collection(const Napi::CallbackInfo& info) {
  const char* name = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* uri = info[1].As<Napi::String>().Utf8Value().c_str();
  uint8_t num_resource_types = static_cast<uint8_t>(info[2].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_new_collection(name, uri, num_resource_types, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_new_link(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
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
  oc_uuid_t* piid;// = dynamic_cast<OCUuid>(info[1]);
  (void)oc_set_immutable_device_identifier(device, piid);
  return info.Env().Undefined();
}

Napi::Value N_oc_add_resource(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  return Napi::Boolean::New(info.Env(), oc_add_resource(resource));
}

Napi::Value N_oc_delete_resource(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  return Napi::Boolean::New(info.Env(), oc_delete_resource(resource));
}

Napi::Value N_oc_device_bind_resource_type(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const char* type = info[1].As<Napi::String>().Utf8Value().c_str();
  (void)oc_device_bind_resource_type(device, type);
  return info.Env().Undefined();
}

Napi::Value N_oc_ignore_request(const Napi::CallbackInfo& info) {
  oc_request_t* request;// = dynamic_cast<OCRequest>(info[0]);
  (void)oc_ignore_request(request);
  return info.Env().Undefined();
}

Napi::Value N_oc_init_query_iterator(const Napi::CallbackInfo& info) {
  (void)oc_init_query_iterator();
  return info.Env().Undefined();
}

Napi::Value N_oc_new_resource(const Napi::CallbackInfo& info) {
  const char* name = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* uri = info[1].As<Napi::String>().Utf8Value().c_str();
  uint8_t num_resource_types = static_cast<uint8_t>(info[2].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_new_resource(name, uri, num_resource_types, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_notify_observers(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  return Napi::Number::New(info.Env(), oc_notify_observers(resource));
}

Napi::Value N_oc_process_baseline_interface(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  (void)oc_process_baseline_interface(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_bind_resource_interface(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_bind_resource_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_bind_resource_type(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  const char* type = info[1].As<Napi::String>().Utf8Value().c_str();
  (void)oc_resource_bind_resource_type(resource, type);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_make_public(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  (void)oc_resource_make_public(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_default_interface(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_default_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_discoverable(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_discoverable(resource, state);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_observable(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_observable(resource, state);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_periodic_observable(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  uint16_t seconds = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_periodic_observable(resource, seconds);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_properties_cbs(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_get_properties_cb_t get_properties = nullptr;
  Napi::Function get_properties_ = info[1].As<Napi::Function>();
  void* get_propr_user_data = info[2];
  oc_set_properties_cb_t set_properties = nullptr;
  Napi::Function set_properties_ = info[3].As<Napi::Function>();
  void* set_props_user_data = info[4];
  (void)oc_resource_set_properties_cbs(resource, get_properties, get_propr_user_data, set_properties, set_props_user_data);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_set_request_handler(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_method_t method = static_cast<oc_method_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_request_callback_t callback = nullptr;
  Napi::Function callback_ = info[2].As<Napi::Function>();
  void* user_data = info[3];
  (void)oc_resource_set_request_handler(resource, method, callback, user_data);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_func_desc(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_enum_t func = static_cast<oc_enum_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_func_desc(resource, func);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_pos_desc(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_pos_desc(resource, pos);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_pos_rel(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  double x = info[1].As<Napi::Number>().DoubleValue();
  double y = info[2].As<Napi::Number>().DoubleValue();
  double z = info[3].As<Napi::Number>().DoubleValue();
  (void)oc_resource_tag_pos_rel(resource, x, y, z);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_diagnostic_message(const Napi::CallbackInfo& info) {
  oc_request_t* request;// = dynamic_cast<OCRequest>(info[0]);
  const char* msg = info[1].As<Napi::String>().Utf8Value().c_str();
  size_t msg_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_status_t response_code = static_cast<oc_status_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)oc_send_diagnostic_message(request, msg, msg_len, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_response(const Napi::CallbackInfo& info) {
  oc_request_t* request;// = dynamic_cast<OCRequest>(info[0]);
  oc_status_t response_code = static_cast<oc_status_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_send_response(request, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_response_raw(const Napi::CallbackInfo& info) {
  oc_request_t* request;// = dynamic_cast<OCRequest>(info[0]);
  const uint8_t* payload = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_content_format_t content_format = static_cast<oc_content_format_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_status_t response_code = static_cast<oc_status_t>(info[4].As<Napi::Number>().Uint32Value());
  (void)oc_send_response_raw(request, payload, size, content_format, response_code);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_con_write_cb(const Napi::CallbackInfo& info) {
  oc_con_write_cb_t callback = nullptr;
  Napi::Function callback_ = info[0].As<Napi::Function>();
  (void)oc_set_con_write_cb(callback);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_expired(const Napi::CallbackInfo& info) {
  oc_timer* t;// = dynamic_cast<OCTimer>(info[0]);
  return Napi::Number::New(info.Env(), oc_timer_expired(t));
}

Napi::Value N_oc_timer_remaining(const Napi::CallbackInfo& info) {
  oc_timer* t;// = dynamic_cast<OCTimer>(info[0]);
  return Napi::Number::New(info.Env(), oc_timer_remaining(t));
}

Napi::Value N_oc_timer_reset(const Napi::CallbackInfo& info) {
  oc_timer* t;// = dynamic_cast<OCTimer>(info[0]);
  (void)oc_timer_reset(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_restart(const Napi::CallbackInfo& info) {
  oc_timer* t;// = dynamic_cast<OCTimer>(info[0]);
  (void)oc_timer_restart(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_set(const Napi::CallbackInfo& info) {
  oc_timer* t;// = dynamic_cast<OCTimer>(info[0]);
  oc_clock_time_t interval = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
  (void)oc_timer_set(t, interval);
  return info.Env().Undefined();
}

Napi::Value N_oc_add_device(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* rt = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* name = info[2].As<Napi::String>().Utf8Value().c_str();
  const char* spec_version = info[3].As<Napi::String>().Utf8Value().c_str();
  const char* data_model_version = info[4].As<Napi::String>().Utf8Value().c_str();
  oc_add_device_cb_t add_device_cb = nullptr;
  Napi::Function add_device_cb_ = info[5].As<Napi::Function>();
  void* data = info[6];
  return Napi::Number::New(info.Env(), oc_add_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data));
}

Napi::Value N_oc_add_ownership_status_cb(const Napi::CallbackInfo& info) {
  oc_ownership_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  (void)oc_add_ownership_status_cb(cb, user_data);
  return info.Env().Undefined();
}

Napi::Value N_oc_get_con_res_announced(const Napi::CallbackInfo& info) {
  return Napi::Boolean::New(info.Env(), oc_get_con_res_announced());
}

Napi::Value N_oc_init_platform(const Napi::CallbackInfo& info) {
  const char* mfg_name = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_init_platform_cb_t init_platform_cb = nullptr;
  Napi::Function init_platform_cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_init_platform(mfg_name, init_platform_cb, data));
}

Napi::Value N_oc_is_owned_device(const Napi::CallbackInfo& info) {
  size_t device_index = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_is_owned_device(device_index));
}

Napi::Value N_oc_main_init(const Napi::CallbackInfo& info) {
  oc_handler_t* handler;// = dynamic_cast<OCHandler>(info[0]);
  return Napi::Number::New(info.Env(), oc_main_init(handler));
}

Napi::Value N_oc_main_poll(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_main_poll());
}

Napi::Value N_oc_main_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_main_shutdown();
  return info.Env().Undefined();
}

Napi::Value N_oc_remove_ownership_status_cb(const Napi::CallbackInfo& info) {
  oc_ownership_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* user_data = info[1];
  (void)oc_remove_ownership_status_cb(cb, user_data);
  return info.Env().Undefined();
}

Napi::Value N_oc_reset(const Napi::CallbackInfo& info) {
  (void)oc_reset();
  return info.Env().Undefined();
}

Napi::Value N_oc_reset_device(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_reset_device(device);
  return info.Env().Undefined();
}

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

Napi::Value N_oc_set_random_pin_callback(const Napi::CallbackInfo& info) {
  oc_random_pin_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  (void)oc_set_random_pin_callback(cb, data);
  return info.Env().Undefined();
}

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
  const char* msg = info[0].As<Napi::String>().Utf8Value().c_str();
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
  const char* href = info[0].As<Napi::String>().Utf8Value().c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[2]);
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[4].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_alloc_request_buffer(href, href_len, endpoint, method, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_alloc_response_buffer(const Napi::CallbackInfo& info) {
  const char* href = info[0].As<Napi::String>().Utf8Value().c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[2]);
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[4].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_alloc_response_buffer(href, href_len, endpoint, method, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer(const Napi::CallbackInfo& info) {
  const char* href = info[0].As<Napi::String>().Utf8Value().c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[2]);
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  const char* query = info[4].As<Napi::String>().Utf8Value().c_str();
  size_t query_len = static_cast<size_t>(info[5].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[6].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer(href, href_len, endpoint, method, query, query_len, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_client_cb(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
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
  const char* href = info[0].As<Napi::String>().Utf8Value().c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[2]);
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  const char* query = info[4].As<Napi::String>().Utf8Value().c_str();
  size_t query_len = static_cast<size_t>(info[5].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[6].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer(href, href_len, endpoint, method, query, query_len, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_client_cb(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
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
  oc_blockwise_state_s* buffer;// = dynamic_cast<OCBlockwiseState>(info[0]);
  (void)oc_blockwise_free_request_buffer(buffer);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_free_response_buffer(const Napi::CallbackInfo& info) {
  oc_blockwise_state_s* buffer;// = dynamic_cast<OCBlockwiseState>(info[0]);
  (void)oc_blockwise_free_response_buffer(buffer);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_handle_block(const Napi::CallbackInfo& info) {
  oc_blockwise_state_s* buffer;// = dynamic_cast<OCBlockwiseState>(info[0]);
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
  oc_memb* pool;// = dynamic_cast<OCMemb>(info[0]);
  std::shared_ptr<oc_message_t> sp(oc_allocate_message_from_pool(pool));
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

Napi::Value N_oc_close_all_tls_sessions(const Napi::CallbackInfo& info) {
  (void)oc_close_all_tls_sessions();
  return info.Env().Undefined();
}

Napi::Value N_oc_close_all_tls_sessions_for_device(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_close_all_tls_sessions_for_device(device);
  return info.Env().Undefined();
}

Napi::Value N_oc_internal_allocate_outgoing_message(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_message_t> sp(oc_internal_allocate_outgoing_message());
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

Napi::Value N_oc_message_add_ref(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
  (void)oc_message_add_ref(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_message_unref(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
  (void)oc_message_unref(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_recv_message(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
  (void)oc_recv_message(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_message(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
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
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_ri_free_client_cbs_by_endpoint(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_free_client_cbs_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_ri_free_client_cbs_by_mid(mid);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_get_client_cb(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  oc_method_t method = static_cast<oc_method_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_get_client_cb(uri, endpoint, method));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_is_client_cb_valid(const Napi::CallbackInfo& info) {
  oc_client_cb_t* client_cb;// = dynamic_cast<OCClientCallback>(info[0]);
  return Napi::Boolean::New(info.Env(), oc_ri_is_client_cb_valid(client_cb));
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
  const char* in_buf = info[0].As<Napi::String>().Utf8Value().c_str();
  size_t in_buf_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_parse_time_rfc3339(in_buf, in_buf_len));
}

Napi::Value N_oc_clock_time_rfc3339(const Napi::CallbackInfo& info) {
  char* out_buf = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  size_t out_buf_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_time_rfc3339(out_buf, out_buf_len));
}

Napi::Value N_oc_cloud_add_resource(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  return Napi::Number::New(info.Env(), oc_cloud_add_resource(resource));
}

Napi::Value N_oc_cloud_delete_resource(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  (void)oc_cloud_delete_resource(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_cloud_deregister(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_deregister(ctx, cb, data));
}

Napi::Value N_oc_cloud_discover_resources(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* user_data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_discover_resources(ctx, handler, user_data));
}

Napi::Value N_oc_cloud_get_context(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_cloud_context_t> sp(oc_cloud_get_context(device));
  auto args = Napi::External<std::shared_ptr<oc_cloud_context_t>>::New(info.Env(), &sp);
  return OCCloudContext::constructor.New({args});
}

Napi::Value N_oc_cloud_get_token_expiry(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  return Napi::Number::New(info.Env(), oc_cloud_get_token_expiry(ctx));
}

Napi::Value N_oc_cloud_login(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_login(ctx, cb, data));
}

Napi::Value N_oc_cloud_logout(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_logout(ctx, cb, data));
}

Napi::Value N_oc_cloud_manager_start(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_manager_start(ctx, cb, data));
}

Napi::Value N_oc_cloud_manager_stop(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  return Napi::Number::New(info.Env(), oc_cloud_manager_stop(ctx));
}

Napi::Value N_oc_cloud_provision_conf_resource(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  const char* server = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* access_token = info[2].As<Napi::String>().Utf8Value().c_str();
  const char* server_id = info[3].As<Napi::String>().Utf8Value().c_str();
  const char* auth_provider = info[4].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), oc_cloud_provision_conf_resource(ctx, server, access_token, server_id, auth_provider));
}

Napi::Value N_oc_cloud_publish_resources(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_cloud_publish_resources(device));
}

Napi::Value N_oc_cloud_refresh_token(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_refresh_token(ctx, cb, data));
}

Napi::Value N_oc_cloud_register(const Napi::CallbackInfo& info) {
  oc_cloud_context_t* ctx;// = dynamic_cast<OCCloudContext>(info[0]);
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_register(ctx, cb, data));
}

Napi::Value N_oc_check_if_collection(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  return Napi::Boolean::New(info.Env(), oc_check_if_collection(resource));
}

Napi::Value N_oc_collection_add(const Napi::CallbackInfo& info) {
  oc_collection_s* collection;// = dynamic_cast<OCCollection>(info[0]);
  (void)oc_collection_add(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_alloc(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_collection_t> sp(oc_collection_alloc());
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_collection_free(const Napi::CallbackInfo& info) {
  oc_collection_s* collection;// = dynamic_cast<OCCollection>(info[0]);
  (void)oc_collection_free(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_get_all(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_collection_t> sp(oc_collection_get_all());
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_get_collection_by_uri(const Napi::CallbackInfo& info) {
  const char* uri_path = info[0].As<Napi::String>().Utf8Value().c_str();
  size_t uri_path_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_collection_t> sp(oc_get_collection_by_uri(uri_path, uri_path_len, device));
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_get_link_by_uri(const Napi::CallbackInfo& info) {
  oc_collection_s* collection;// = dynamic_cast<OCCollection>(info[0]);
  const char* uri_path = info[1].As<Napi::String>().Utf8Value().c_str();
  int uri_path_len = static_cast<int>(info[2].As<Napi::Number>());
  std::shared_ptr<oc_link_t> sp(oc_get_link_by_uri(collection, uri_path, uri_path_len));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value N_oc_get_next_collection_with_link(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_collection_s* start;// = dynamic_cast<OCCollection>(info[1]);
  std::shared_ptr<oc_collection_t> sp(oc_get_next_collection_with_link(resource, start));
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_handle_collection_request(const Napi::CallbackInfo& info) {
  oc_method_t method = static_cast<oc_method_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_request_t* request;// = dynamic_cast<OCRequest>(info[1]);
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_resource_s* notify_resource;// = dynamic_cast<OCResource>(info[3]);
  return Napi::Boolean::New(info.Env(), oc_handle_collection_request(method, request, iface_mask, notify_resource));
}

Napi::Value N_oc_link_set_interfaces(const Napi::CallbackInfo& info) {
  oc_link_s* link;// = dynamic_cast<OCLink>(info[0]);
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
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_session_state_t state = static_cast<oc_session_state_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)handle_session_event_callback(endpoint, state);
  return info.Env().Undefined();
}

Napi::Value N_oc_connectivity_end_session(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_connectivity_end_session(endpoint);
  return info.Env().Undefined();
}

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

Napi::Value N_oc_send_buffer(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
  return Napi::Number::New(info.Env(), oc_send_buffer(message));
}

Napi::Value N_oc_send_discovery_request(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
  (void)oc_send_discovery_request(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_core_add_new_device(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* rt = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* name = info[2].As<Napi::String>().Utf8Value().c_str();
  const char* spec_version = info[3].As<Napi::String>().Utf8Value().c_str();
  const char* data_model_version = info[4].As<Napi::String>().Utf8Value().c_str();
  oc_core_add_device_cb_t add_device_cb = nullptr;
  Napi::Function add_device_cb_ = info[5].As<Napi::Function>();
  void* data = info[6];
  std::shared_ptr<oc_device_info_t> sp(oc_core_add_new_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data));
  auto args = Napi::External<std::shared_ptr<oc_device_info_t>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({args});
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
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
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
  const char* mfg_name = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_core_init_platform_cb_t init_cb = nullptr;
  Napi::Function init_cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  std::shared_ptr<oc_platform_info_t> sp(oc_core_init_platform(mfg_name, init_cb, data));
  auto args = Napi::External<std::shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({args});
}

Napi::Value N_oc_core_is_DCR(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_core_is_DCR(resource, device));
}

Napi::Value N_oc_core_populate_resource(const Napi::CallbackInfo& info) {
  int core_resource = static_cast<int>(info[0].As<Napi::Number>());
  size_t device_index = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  const char* uri = info[2].As<Napi::String>().Utf8Value().c_str();
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
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  oc_request_t* request;// = dynamic_cast<OCRequest>(info[1]);
  return Napi::Boolean::New(info.Env(), oc_filter_resource_by_rt(resource, request));
}

Napi::Value N_oc_store_uri(const Napi::CallbackInfo& info) {
  const char* s_uri = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_mmem* d_uri;// = dynamic_cast<OCMmem>(info[1]);
  (void)oc_store_uri(s_uri, d_uri);
  return info.Env().Undefined();
}

Napi::Value N_oc_cred_credtype_string(const Napi::CallbackInfo& info) {
  oc_sec_credtype_t credtype = static_cast<oc_sec_credtype_t>(info[0].As<Napi::Number>().Uint32Value());
}

Napi::Value N_oc_cred_parse_credusage(const Napi::CallbackInfo& info) {
  oc_mmem* credusage_string;// = dynamic_cast<OCMmem>(info[0]);
}

Napi::Value N_oc_cred_parse_encoding(const Napi::CallbackInfo& info) {
  oc_mmem* encoding_string;// = dynamic_cast<OCMmem>(info[0]);
}

Napi::Value N_oc_cred_read_credusage(const Napi::CallbackInfo& info) {
  oc_sec_credusage_t credusage = static_cast<oc_sec_credusage_t>(info[0].As<Napi::Number>().Uint32Value());
}

Napi::Value N_oc_cred_read_encoding(const Napi::CallbackInfo& info) {
  oc_sec_encoding_t encoding = static_cast<oc_sec_encoding_t>(info[0].As<Napi::Number>().Uint32Value());
}

Napi::Value N_oc_create_discovery_resource(const Napi::CallbackInfo& info) {
  int resource_idx = static_cast<int>(info[0].As<Napi::Number>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_create_discovery_resource(resource_idx, device);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_compare(const Napi::CallbackInfo& info) {
  oc_endpoint_t* ep1;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_endpoint_t* ep2;// = dynamic_cast<OCEndpoint>(info[1]);
  return Napi::Number::New(info.Env(), oc_endpoint_compare(ep1, ep2));
}

Napi::Value N_oc_endpoint_compare_address(const Napi::CallbackInfo& info) {
  oc_endpoint_t* ep1;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_endpoint_t* ep2;// = dynamic_cast<OCEndpoint>(info[1]);
  return Napi::Number::New(info.Env(), oc_endpoint_compare_address(ep1, ep2));
}

Napi::Value N_oc_endpoint_copy(const Napi::CallbackInfo& info) {
  oc_endpoint_t* dst;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_endpoint_t* src;// = dynamic_cast<OCEndpoint>(info[1]);
  (void)oc_endpoint_copy(dst, src);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_set_di(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_uuid_t* di;// = dynamic_cast<OCUuid>(info[1]);
  (void)oc_endpoint_set_di(endpoint, di);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_set_local_address(const Napi::CallbackInfo& info) {
  oc_endpoint_t* ep;// = dynamic_cast<OCEndpoint>(info[0]);
  int interface_index = static_cast<int>(info[1].As<Napi::Number>());
  (void)oc_endpoint_set_local_address(ep, interface_index);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_string_parse_path(const Napi::CallbackInfo& info) {
  oc_mmem* endpoint_str;// = dynamic_cast<OCMmem>(info[0]);
  oc_mmem* path;// = dynamic_cast<OCMmem>(info[1]);
  return Napi::Number::New(info.Env(), oc_endpoint_string_parse_path(endpoint_str, path));
}

Napi::Value N_oc_endpoint_to_string(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  oc_mmem* endpoint_str;// = dynamic_cast<OCMmem>(info[1]);
  return Napi::Number::New(info.Env(), oc_endpoint_to_string(endpoint, endpoint_str));
}

Napi::Value N_oc_free_endpoint(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_free_endpoint(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_ipv6_endpoint_is_link_local(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  return Napi::Number::New(info.Env(), oc_ipv6_endpoint_is_link_local(endpoint));
}

Napi::Value N_oc_new_endpoint(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_endpoint_t> sp(oc_new_endpoint());
  auto args = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({args});
}

Napi::Value N_oc_string_to_endpoint(const Napi::CallbackInfo& info) {
  oc_mmem* endpoint_str;// = dynamic_cast<OCMmem>(info[0]);
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[1]);
  oc_mmem* uri;// = dynamic_cast<OCMmem>(info[2]);
  return Napi::Number::New(info.Env(), oc_string_to_endpoint(endpoint_str, endpoint, uri));
}

Napi::Value N_oc_enum_pos_desc_to_str(const Napi::CallbackInfo& info) {
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[0].As<Napi::Number>().Uint32Value());
}

Napi::Value N_oc_enum_to_str(const Napi::CallbackInfo& info) {
  oc_enum_t val = static_cast<oc_enum_t>(info[0].As<Napi::Number>().Uint32Value());
}

Napi::Value N__oc_alloc_string(const Napi::CallbackInfo& info) {
  oc_mmem* ocstring;// = dynamic_cast<OCMmem>(info[0]);
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_alloc_string(ocstring, size);
  return info.Env().Undefined();
}

Napi::Value N__oc_alloc_string_array(const Napi::CallbackInfo& info) {
  oc_mmem* ocstringarray;// = dynamic_cast<OCMmem>(info[0]);
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_alloc_string_array(ocstringarray, size);
  return info.Env().Undefined();
}

Napi::Value N__oc_free_array(const Napi::CallbackInfo& info) {
  oc_mmem* ocarray;// = dynamic_cast<OCMmem>(info[0]);
  pool type = static_cast<pool>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_free_array(ocarray, type);
  return info.Env().Undefined();
}

Napi::Value N__oc_free_string(const Napi::CallbackInfo& info) {
  oc_mmem* ocstring;// = dynamic_cast<OCMmem>(info[0]);
  (void)_oc_free_string(ocstring);
  return info.Env().Undefined();
}

Napi::Value N__oc_new_array(const Napi::CallbackInfo& info) {
  oc_mmem* ocarray;// = dynamic_cast<OCMmem>(info[0]);
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  pool type = static_cast<pool>(info[2].As<Napi::Number>().Uint32Value());
  (void)_oc_new_array(ocarray, size, type);
  return info.Env().Undefined();
}

Napi::Value N__oc_new_string(const Napi::CallbackInfo& info) {
  oc_mmem* ocstring;// = dynamic_cast<OCMmem>(info[0]);
  const char* str = info[1].As<Napi::String>().Utf8Value().c_str();
  size_t str_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)_oc_new_string(ocstring, str, str_len);
  return info.Env().Undefined();
}

Napi::Value N_oc_concat_strings(const Napi::CallbackInfo& info) {
  oc_mmem* concat;// = dynamic_cast<OCMmem>(info[0]);
  const char* str1 = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* str2 = info[2].As<Napi::String>().Utf8Value().c_str();
  (void)oc_concat_strings(concat, str1, str2);
  return info.Env().Undefined();
}

Napi::Value N_oc_join_string_array(const Napi::CallbackInfo& info) {
  oc_mmem* ocstringarray;// = dynamic_cast<OCMmem>(info[0]);
  oc_mmem* ocstring;// = dynamic_cast<OCMmem>(info[1]);
  (void)oc_join_string_array(ocstringarray, ocstring);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_introspection_data(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  uint8_t* IDD = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t IDD_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_set_introspection_data(device, IDD, IDD_size);
  return info.Env().Undefined();
}

Napi::Value N__oc_memb_alloc(const Napi::CallbackInfo& info) {
  oc_memb* m;// = dynamic_cast<OCMemb>(info[0]);
}

Napi::Value N__oc_memb_free(const Napi::CallbackInfo& info) {
  oc_memb* m;// = dynamic_cast<OCMemb>(info[0]);
  void* ptr = info[1];
}

Napi::Value N_oc_memb_init(const Napi::CallbackInfo& info) {
  oc_memb* m;// = dynamic_cast<OCMemb>(info[0]);
  (void)oc_memb_init(m);
  return info.Env().Undefined();
}

Napi::Value N_oc_memb_inmemb(const Napi::CallbackInfo& info) {
  oc_memb* m;// = dynamic_cast<OCMemb>(info[0]);
  void* ptr = info[1];
  return Napi::Number::New(info.Env(), oc_memb_inmemb(m, ptr));
}

Napi::Value N_oc_memb_numfree(const Napi::CallbackInfo& info) {
  oc_memb* m;// = dynamic_cast<OCMemb>(info[0]);
  return Napi::Number::New(info.Env(), oc_memb_numfree(m));
}

Napi::Value N_oc_memb_set_buffers_avail_cb(const Napi::CallbackInfo& info) {
  oc_memb* m;// = dynamic_cast<OCMemb>(info[0]);
  oc_memb_buffers_avail_callback_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  (void)oc_memb_set_buffers_avail_cb(m, cb);
  return info.Env().Undefined();
}

Napi::Value N_oc_mem_trace_add_pace(const Napi::CallbackInfo& info) {
  const char* func = info[0].As<Napi::String>().Utf8Value().c_str();
  int size = static_cast<int>(info[1].As<Napi::Number>());
  int type = static_cast<int>(info[2].As<Napi::Number>());
  void* address = info[3];
  (void)oc_mem_trace_add_pace(func, size, type, address);
  return info.Env().Undefined();
}

Napi::Value N_oc_mem_trace_init(const Napi::CallbackInfo& info) {
  (void)oc_mem_trace_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_mem_trace_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_mem_trace_shutdown();
  return info.Env().Undefined();
}

Napi::Value N__oc_mmem_alloc(const Napi::CallbackInfo& info) {
  oc_mmem* m;// = dynamic_cast<OCMmem>(info[0]);
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  pool pool_type = static_cast<pool>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), _oc_mmem_alloc(m, size, pool_type));
}

Napi::Value N__oc_mmem_free(const Napi::CallbackInfo& info) {
  oc_mmem* m;// = dynamic_cast<OCMmem>(info[0]);
  pool pool_type = static_cast<pool>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_mmem_free(m, pool_type);
  return info.Env().Undefined();
}

Napi::Value N_oc_mmem_init(const Napi::CallbackInfo& info) {
  (void)oc_mmem_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event(const Napi::CallbackInfo& info) {
  oc_message_s* message;// = dynamic_cast<OCMessage>(info[0]);
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

Napi::Value N_oc_obt_ace_add_permission(const Napi::CallbackInfo& info) {
  oc_sec_ace_t* ace;// = dynamic_cast<OCSecurityAce>(info[0]);
  oc_ace_permissions_t permission = static_cast<oc_ace_permissions_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_obt_ace_add_permission(ace, permission);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_ace_new_resource(const Napi::CallbackInfo& info) {
  oc_sec_ace_t* ace;// = dynamic_cast<OCSecurityAce>(info[0]);
  std::shared_ptr<oc_ace_res_t> sp(oc_obt_ace_new_resource(ace));
  auto args = Napi::External<std::shared_ptr<oc_ace_res_t>>::New(info.Env(), &sp);
  return OCAceResource::constructor.New({args});
}

Napi::Value N_oc_obt_ace_resource_set_href(const Napi::CallbackInfo& info) {
  oc_ace_res_t* resource;// = dynamic_cast<OCAceResource>(info[0]);
  const char* href = info[1].As<Napi::String>().Utf8Value().c_str();
  (void)oc_obt_ace_resource_set_href(resource, href);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_ace_resource_set_wc(const Napi::CallbackInfo& info) {
  oc_ace_res_t* resource;// = dynamic_cast<OCAceResource>(info[0]);
  oc_ace_wildcard_t wc = static_cast<oc_ace_wildcard_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_obt_ace_resource_set_wc(resource, wc);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_add_roleid(const Napi::CallbackInfo& info) {
  oc_role_t* roles;// = dynamic_cast<OCRole>(info[0]);
  const char* role = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* authority = info[2].As<Napi::String>().Utf8Value().c_str();
  std::shared_ptr<oc_role_t> sp(oc_obt_add_roleid(roles, role, authority));
  auto args = Napi::External<std::shared_ptr<oc_role_t>>::New(info.Env(), &sp);
  return OCRole::constructor.New({args});
}

Napi::Value N_oc_obt_delete_ace_by_aceid(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  int aceid = static_cast<int>(info[1].As<Napi::Number>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_delete_ace_by_aceid(uuid, aceid, cb, data));
}

Napi::Value N_oc_obt_delete_cred_by_credid(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  int credid = static_cast<int>(info[1].As<Napi::Number>());
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_delete_cred_by_credid(uuid, credid, cb, data));
}

Napi::Value N_oc_obt_delete_own_cred_by_credid(const Napi::CallbackInfo& info) {
  int credid = static_cast<int>(info[0].As<Napi::Number>());
  return Napi::Number::New(info.Env(), oc_obt_delete_own_cred_by_credid(credid));
}

Napi::Value N_oc_obt_device_hard_reset(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_device_hard_reset(uuid, cb, data));
}

Napi::Value N_oc_obt_discover_all_resources(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_discovery_all_handler_t handler = nullptr;
  Napi::Function handler_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_discover_all_resources(uuid, handler, data));
}

Napi::Value N_oc_obt_discover_owned_devices(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices(cb, data));
}

Napi::Value N_oc_obt_discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices_realm_local_ipv6(cb, data));
}

Napi::Value N_oc_obt_discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_owned_devices_site_local_ipv6(cb, data));
}

Napi::Value N_oc_obt_discover_unowned_devices(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices(cb, data));
}

Napi::Value N_oc_obt_discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices_realm_local_ipv6(cb, data));
}

Napi::Value N_oc_obt_discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo& info) {
  oc_obt_discovery_cb_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  void* data = info[1];
  return Napi::Number::New(info.Env(), oc_obt_discover_unowned_devices_site_local_ipv6(cb, data));
}

Napi::Value N_oc_obt_free_ace(const Napi::CallbackInfo& info) {
  oc_sec_ace_t* ace;// = dynamic_cast<OCSecurityAce>(info[0]);
  (void)oc_obt_free_ace(ace);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_free_acl(const Napi::CallbackInfo& info) {
  oc_sec_acl_s* acl;// = dynamic_cast<OCSecurityAcl>(info[0]);
  (void)oc_obt_free_acl(acl);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_free_creds(const Napi::CallbackInfo& info) {
  oc_sec_creds_t* creds;// = dynamic_cast<OCCreds>(info[0]);
  (void)oc_obt_free_creds(creds);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_free_roleid(const Napi::CallbackInfo& info) {
  oc_role_t* roles;// = dynamic_cast<OCRole>(info[0]);
  (void)oc_obt_free_roleid(roles);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_init(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_obt_init());
}

Napi::Value N_oc_obt_new_ace_for_connection(const Napi::CallbackInfo& info) {
  oc_ace_connection_type_t conn = static_cast<oc_ace_connection_type_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_connection(conn));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}

Napi::Value N_oc_obt_new_ace_for_role(const Napi::CallbackInfo& info) {
  const char* role = info[0].As<Napi::String>().Utf8Value().c_str();
  const char* authority = info[1].As<Napi::String>().Utf8Value().c_str();
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_role(role, authority));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}

Napi::Value N_oc_obt_new_ace_for_subject(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  std::shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_subject(uuid));
  auto args = Napi::External<std::shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
  return OCSecurityAce::constructor.New({args});
}

Napi::Value N_oc_obt_perform_cert_otm(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_perform_cert_otm(uuid, cb, data));
}

Napi::Value N_oc_obt_perform_just_works_otm(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_perform_just_works_otm(uuid, cb, data));
}

Napi::Value N_oc_obt_perform_random_pin_otm(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  const unsigned char* pin = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t pin_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[3].As<Napi::Function>();
  void* data = info[4];
  return Napi::Number::New(info.Env(), oc_obt_perform_random_pin_otm(uuid, pin, pin_len, cb, data));
}

Napi::Value N_oc_obt_provision_ace(const Napi::CallbackInfo& info) {
  oc_uuid_t* subject;// = dynamic_cast<OCUuid>(info[0]);
  oc_sec_ace_t* ace;// = dynamic_cast<OCSecurityAce>(info[1]);
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_ace(subject, ace, cb, data));
}

Napi::Value N_oc_obt_provision_auth_wildcard_ace(const Napi::CallbackInfo& info) {
  oc_uuid_t* subject;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_provision_auth_wildcard_ace(subject, cb, data));
}

Napi::Value N_oc_obt_provision_identity_certificate(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_provision_identity_certificate(uuid, cb, data));
}

Napi::Value N_oc_obt_provision_pairwise_credentials(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid1;// = dynamic_cast<OCUuid>(info[0]);
  oc_uuid_t* uuid2;// = dynamic_cast<OCUuid>(info[1]);
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_pairwise_credentials(uuid1, uuid2, cb, data));
}

Napi::Value N_oc_obt_provision_role_certificate(const Napi::CallbackInfo& info) {
  oc_role_t* roles;// = dynamic_cast<OCRole>(info[0]);
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[1]);
  oc_obt_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[2].As<Napi::Function>();
  void* data = info[3];
  return Napi::Number::New(info.Env(), oc_obt_provision_role_certificate(roles, uuid, cb, data));
}

Napi::Value N_oc_obt_provision_role_wildcard_ace(const Napi::CallbackInfo& info) {
  oc_uuid_t* subject;// = dynamic_cast<OCUuid>(info[0]);
  const char* role = info[1].As<Napi::String>().Utf8Value().c_str();
  const char* authority = info[2].As<Napi::String>().Utf8Value().c_str();
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[3].As<Napi::Function>();
  void* data = info[4];
  return Napi::Number::New(info.Env(), oc_obt_provision_role_wildcard_ace(subject, role, authority, cb, data));
}

Napi::Value N_oc_obt_request_random_pin(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_device_status_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_request_random_pin(uuid, cb, data));
}

Napi::Value N_oc_obt_retrieve_acl(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_acl_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_retrieve_acl(uuid, cb, data));
}

Napi::Value N_oc_obt_retrieve_creds(const Napi::CallbackInfo& info) {
  oc_uuid_t* subject;// = dynamic_cast<OCUuid>(info[0]);
  oc_obt_creds_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_obt_retrieve_creds(subject, cb, data));
}

Napi::Value N_oc_obt_retrieve_own_creds(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_sec_creds_t> sp(oc_obt_retrieve_own_creds());
  auto args = Napi::External<std::shared_ptr<oc_sec_creds_t>>::New(info.Env(), &sp);
  return OCCreds::constructor.New({args});
}

Napi::Value N_oc_obt_set_sd_info(const Napi::CallbackInfo& info) {
  char* name = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  bool priv = info[1].As<Napi::Boolean>().Value();
  (void)oc_obt_set_sd_info(name, priv);
  return info.Env().Undefined();
}

Napi::Value N_oc_obt_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_obt_shutdown();
  return info.Env().Undefined();
}

Napi::Value N_oc_pki_add_mfg_cert(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  const unsigned char* key = info[3].As<Napi::Buffer<const uint8_t>>().Data();
  size_t key_size = static_cast<size_t>(info[4].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_cert(device, cert, cert_size, key, key_size));
}

Napi::Value N_oc_pki_add_mfg_intermediate_cert(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  int credid = static_cast<int>(info[1].As<Napi::Number>());
  const unsigned char* cert = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_intermediate_cert(device, credid, cert, cert_size));
}

Napi::Value N_oc_pki_add_mfg_trust_anchor(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_mfg_trust_anchor(device, cert, cert_size));
}

Napi::Value N_oc_pki_add_trust_anchor(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const unsigned char* cert = info[1].As<Napi::Buffer<const uint8_t>>().Data();
  size_t cert_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_pki_add_trust_anchor(device, cert, cert_size));
}

Napi::Value N_oc_pki_set_security_profile(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_sp_types_t supported_profiles = static_cast<oc_sp_types_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_sp_types_t current_profile = static_cast<oc_sp_types_t>(info[2].As<Napi::Number>().Uint32Value());
  int mfg_credid = static_cast<int>(info[3].As<Napi::Number>());
  (void)oc_pki_set_security_profile(device, supported_profiles, current_profile, mfg_credid);
  return info.Env().Undefined();
}

Napi::Value N_oc_random_destroy(const Napi::CallbackInfo& info) {
  (void)oc_random_destroy();
  return info.Env().Undefined();
}

Napi::Value N_oc_random_init(const Napi::CallbackInfo& info) {
  (void)oc_random_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_random_value(const Napi::CallbackInfo& info) {
}

Napi::Value N_oc_free_rep(const Napi::CallbackInfo& info) {
  oc_rep_s* rep;// = dynamic_cast<OCRep>(info[0]);
  (void)oc_free_rep(rep);
  return info.Env().Undefined();
}

Napi::Value N_oc_rep_get_byte_string_array(const Napi::CallbackInfo& info) {
  oc_rep_s* rep;// = dynamic_cast<OCRep>(info[0]);
  const char* key = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_mmem* value;// = dynamic_cast<OCMmem>(info[2]);
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), oc_rep_get_byte_string_array(rep, key, value, size));
}

Napi::Value N_oc_rep_get_cbor_errno(const Napi::CallbackInfo& info) {
}

Napi::Value N_oc_rep_get_encoded_payload_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_rep_get_encoded_payload_size());
}

Napi::Value N_oc_rep_get_encoder_buf(const Napi::CallbackInfo& info) {
}

Napi::Value N_oc_rep_get_string_array(const Napi::CallbackInfo& info) {
  oc_rep_s* rep;// = dynamic_cast<OCRep>(info[0]);
  const char* key = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_mmem* value;// = dynamic_cast<OCMmem>(info[2]);
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
  oc_memb* rep_objects_pool;// = dynamic_cast<OCMemb>(info[0]);
  (void)oc_rep_set_pool(rep_objects_pool);
  return info.Env().Undefined();
}

Napi::Value N_oc_rep_to_json(const Napi::CallbackInfo& info) {
  oc_rep_s* rep;// = dynamic_cast<OCRep>(info[0]);
  char* buf = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  size_t buf_size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  bool pretty_print = info[3].As<Napi::Boolean>().Value();
  return Napi::Number::New(info.Env(), oc_rep_to_json(rep, buf, buf_size, pretty_print));
}

Napi::Value N_oc_ri_add_timed_event_callback_ticks(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t event_callback = nullptr;
  Napi::Function event_callback_ = info[1].As<Napi::Function>();
  oc_clock_time_t ticks = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
  (void)oc_ri_add_timed_event_callback_ticks(cb_data, event_callback, ticks);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_free_resource_properties(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
  (void)oc_ri_free_resource_properties(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_get_app_resource_by_uri(const Napi::CallbackInfo& info) {
  const char* uri = info[0].As<Napi::String>().Utf8Value().c_str();
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
}

Napi::Value N_oc_ri_init(const Napi::CallbackInfo& info) {
  (void)oc_ri_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_is_app_resource_valid(const Napi::CallbackInfo& info) {
  oc_resource_s* resource;// = dynamic_cast<OCResource>(info[0]);
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

Napi::Value N_oc_session_end_event(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_session_end_event(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_session_events_set_event_delay(const Napi::CallbackInfo& info) {
  int secs = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_session_events_set_event_delay(secs);
  return info.Env().Undefined();
}

Napi::Value N_oc_session_start_event(const Napi::CallbackInfo& info) {
  oc_endpoint_t* endpoint;// = dynamic_cast<OCEndpoint>(info[0]);
  (void)oc_session_start_event(endpoint);
  return info.Env().Undefined();
}

Napi::Value N__oc_signal_event_loop(const Napi::CallbackInfo& info) {
  (void)_oc_signal_event_loop();
  return info.Env().Undefined();
}

Napi::Value N_oc_storage_config(const Napi::CallbackInfo& info) {
  const char* store = info[0].As<Napi::String>().Utf8Value().c_str();
  return Napi::Number::New(info.Env(), oc_storage_config(store));
}

Napi::Value N_oc_storage_read(const Napi::CallbackInfo& info) {
  const char* store = info[0].As<Napi::String>().Utf8Value().c_str();
  uint8_t* buf = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_storage_read(store, buf, size));
}

Napi::Value N_oc_storage_write(const Napi::CallbackInfo& info) {
  const char* store = info[0].As<Napi::String>().Utf8Value().c_str();
  uint8_t* buf = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_storage_write(store, buf, size));
}

Napi::Value N_oc_swupdate_notify_done(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_done(device, result);
  return info.Env().Undefined();
}

Napi::Value N_oc_swupdate_notify_downloaded(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const char* version = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_downloaded(device, version, result);
  return info.Env().Undefined();
}

Napi::Value N_oc_swupdate_notify_new_version_available(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const char* version = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_new_version_available(device, version, result);
  return info.Env().Undefined();
}

Napi::Value N_oc_swupdate_notify_upgrading(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  const char* version = info[1].As<Napi::String>().Utf8Value().c_str();
  oc_clock_time_t timestamp = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
  oc_swupdate_result_t result = static_cast<oc_swupdate_result_t>(info[3].As<Napi::Number>().Uint32Value());
  (void)oc_swupdate_notify_upgrading(device, version, timestamp, result);
  return info.Env().Undefined();
}

Napi::Value N_oc_swupdate_set_impl(const Napi::CallbackInfo& info) {
  oc_swupdate_cb_t* swupdate_impl;// = dynamic_cast<OCSoftwareUpdateHandler>(info[0]);
  (void)oc_swupdate_set_impl(swupdate_impl);
  return info.Env().Undefined();
}

Napi::Value N_oc_gen_uuid(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  (void)oc_gen_uuid(uuid);
  return info.Env().Undefined();
}

Napi::Value N_oc_str_to_uuid(const Napi::CallbackInfo& info) {
  const char* str = info[0].As<Napi::String>().Utf8Value().c_str();
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[1]);
  (void)oc_str_to_uuid(str, uuid);
  return info.Env().Undefined();
}

Napi::Value N_oc_uuid_to_str(const Napi::CallbackInfo& info) {
  oc_uuid_t* uuid;// = dynamic_cast<OCUuid>(info[0]);
  char* buffer = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  int buflen = static_cast<int>(info[2].As<Napi::Number>());
  (void)oc_uuid_to_str(uuid, buffer, buflen);
  return info.Env().Undefined();
}

