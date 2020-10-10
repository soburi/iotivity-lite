#pragma once
#include <napi.h>
#include <memory>
#include <oc_api.h>
#include <oc_base64.h>
#include <oc_blockwise.h>
#include <oc_buffer.h>
#include <oc_buffer_settings.h>
#include <oc_client_state.h>
#include <oc_clock_util.h>
#include <oc_cloud.h>
#include <oc_collection.h>
#include <oc_core_res.h>
#include <oc_cred.h>
#include <oc_discovery.h>
#include <oc_endpoint.h>
#include <oc_enums.h>
#include <oc_helpers.h>
#include <oc_introspection.h>
#include <oc_network_events.h>
#include <oc_network_monitor.h>
#include <oc_obt.h>
#include <oc_pki.h>
#include <oc_rep.h>
#include <oc_ri.h>
#include <oc_session_events.h>
#include <oc_signal_event_loop.h>
#include <oc_swupdate.h>
#include <oc_uuid.h>
#include <oc_connectivity.h>
#include <oc_assert.h>
#include <oc_mem_trace.h>
class OCAceResource : public Napi::ObjectWrap<OCAceResource>
{
public:
  OCAceResource(const Napi::CallbackInfo&);
  OCAceResource(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ace_res_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_href(const Napi::CallbackInfo&);
         void set_href(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_interfaces(const Napi::CallbackInfo&);
         void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_types(const Napi::CallbackInfo&);
         void set_types(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_wildcard(const Napi::CallbackInfo&);
         void set_wildcard(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ace_res_t> m_pvalue;
};




class OCClientCallback : public Napi::ObjectWrap<OCClientCallback>
{
public:
  OCClientCallback(const Napi::CallbackInfo&);
  OCClientCallback(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_client_cb_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_discovery(const Napi::CallbackInfo&);
         void set_discovery(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_handler(const Napi::CallbackInfo&);
         void set_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_method(const Napi::CallbackInfo&);
         void set_method(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_mid(const Napi::CallbackInfo&);
         void set_mid(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_multicast(const Napi::CallbackInfo&);
         void set_multicast(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_observe_seq(const Napi::CallbackInfo&);
         void set_observe_seq(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_qos(const Napi::CallbackInfo&);
         void set_qos(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_query(const Napi::CallbackInfo&);
         void set_query(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_ref_count(const Napi::CallbackInfo&);
         void set_ref_count(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_separate(const Napi::CallbackInfo&);
         void set_separate(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_stop_multicast_receive(const Napi::CallbackInfo&);
         void set_stop_multicast_receive(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_timestamp(const Napi::CallbackInfo&);
         void set_timestamp(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_token(const Napi::CallbackInfo&);
         void set_token(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_token_len(const Napi::CallbackInfo&);
         void set_token_len(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_uri(const Napi::CallbackInfo&);
         void set_uri(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_client_cb_t> m_pvalue;
};

class OCClientHandler : public Napi::ObjectWrap<OCClientHandler>
{
public:
  OCClientHandler(const Napi::CallbackInfo&);
  OCClientHandler(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_client_handler_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_discovery(const Napi::CallbackInfo&);
         void set_discovery(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value discovery_function; Napi::Value discovery_data;

  Napi::Value get_discovery_all(const Napi::CallbackInfo&);
         void set_discovery_all(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value discovery_all_function; Napi::Value discovery_all_data;

  Napi::Value get_response(const Napi::CallbackInfo&);
         void set_response(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value response_function; Napi::Value response_data;


  std::shared_ptr<oc_client_handler_t> m_pvalue;
};

class OCClientResponse : public Napi::ObjectWrap<OCClientResponse>
{
public:
  OCClientResponse(const Napi::CallbackInfo&);
  OCClientResponse(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_client_response_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_code(const Napi::CallbackInfo&);
         void set_code(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_content_format(const Napi::CallbackInfo&);
         void set_content_format(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_observe_option(const Napi::CallbackInfo&);
         void set_observe_option(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_client_response_t> m_pvalue;
};

class OCCloudContext : public Napi::ObjectWrap<OCCloudContext>
{
public:
  OCCloudContext(const Napi::CallbackInfo&);
  OCCloudContext(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_cloud_context_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_callback(const Napi::CallbackInfo&);
         void set_callback(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value callback_function; Napi::Value callback_data;

  Napi::Value get_cloud_manager(const Napi::CallbackInfo&);
         void set_cloud_manager(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_device(const Napi::CallbackInfo&);
         void set_device(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_expires_in(const Napi::CallbackInfo&);
         void set_expires_in(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_last_error(const Napi::CallbackInfo&);
         void set_last_error(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_rd_delete_all(const Napi::CallbackInfo&);
         void set_rd_delete_all(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_retry_count(const Napi::CallbackInfo&);
         void set_retry_count(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_retry_refresh_token_count(const Napi::CallbackInfo&);
         void set_retry_refresh_token_count(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_store(const Napi::CallbackInfo&);
         void set_store(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_user_data(const Napi::CallbackInfo&);
         void set_user_data(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_cloud_context_t> m_pvalue;
};

class OCCloudStore : public Napi::ObjectWrap<OCCloudStore>
{
public:
  OCCloudStore(const Napi::CallbackInfo&);
  OCCloudStore(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_cloud_store_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_access_token(const Napi::CallbackInfo&);
         void set_access_token(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_auth_provider(const Napi::CallbackInfo&);
         void set_auth_provider(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_ci_server(const Napi::CallbackInfo&);
         void set_ci_server(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_cps(const Napi::CallbackInfo&);
         void set_cps(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_device(const Napi::CallbackInfo&);
         void set_device(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_refresh_token(const Napi::CallbackInfo&);
         void set_refresh_token(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_sid(const Napi::CallbackInfo&);
         void set_sid(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_status(const Napi::CallbackInfo&);
         void set_status(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_uid(const Napi::CallbackInfo&);
         void set_uid(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_cloud_store_t> m_pvalue;
};

class OCCollection : public Napi::ObjectWrap<OCCollection>
{
public:
  OCCollection(const Napi::CallbackInfo&);
  OCCollection(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_collection_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_default_interface(const Napi::CallbackInfo&);
         void set_default_interface(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_delete_handler(const Napi::CallbackInfo&);
         void set_delete_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_device(const Napi::CallbackInfo&);
         void set_device(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_get_handler(const Napi::CallbackInfo&);
         void set_get_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_get_properties(const Napi::CallbackInfo&);
         void set_get_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_interfaces(const Napi::CallbackInfo&);
         void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_name(const Napi::CallbackInfo&);
         void set_name(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_num_links(const Napi::CallbackInfo&);
         void set_num_links(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_num_observers(const Napi::CallbackInfo&);
         void set_num_observers(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_post_handler(const Napi::CallbackInfo&);
         void set_post_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_properties(const Napi::CallbackInfo&);
         void set_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_put_handler(const Napi::CallbackInfo&);
         void set_put_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_set_properties(const Napi::CallbackInfo&);
         void set_set_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_desc(const Napi::CallbackInfo&);
         void set_tag_pos_desc(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_func(const Napi::CallbackInfo&);
         void set_tag_pos_func(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_rel(const Napi::CallbackInfo&);
         void set_tag_pos_rel(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_types(const Napi::CallbackInfo&);
         void set_types(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_uri(const Napi::CallbackInfo&);
         void set_uri(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_collection_s> m_pvalue;
};

class OCCredData : public Napi::ObjectWrap<OCCredData>
{
public:
  OCCredData(const Napi::CallbackInfo&);
  OCCredData(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_cred_data_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_data(const Napi::CallbackInfo&);
         void set_data(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_encoding(const Napi::CallbackInfo&);
         void set_encoding(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_cred_data_t> m_pvalue;
};

class OCDeviceInfo : public Napi::ObjectWrap<OCDeviceInfo>
{
public:
  OCDeviceInfo(const Napi::CallbackInfo&);
  OCDeviceInfo(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_device_info_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_add_device_cb(const Napi::CallbackInfo&);
         void set_add_device_cb(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value add_device_cb_function; Napi::Value add_device_cb_data;

  Napi::Value get_data(const Napi::CallbackInfo&);
         void set_data(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_di(const Napi::CallbackInfo&);
         void set_di(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_dmv(const Napi::CallbackInfo&);
         void set_dmv(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_icv(const Napi::CallbackInfo&);
         void set_icv(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_name(const Napi::CallbackInfo&);
         void set_name(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_piid(const Napi::CallbackInfo&);
         void set_piid(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_device_info_t> m_pvalue;
};

class OCEndpoint : public Napi::ObjectWrap<OCEndpoint>
{
public:
  OCEndpoint(const Napi::CallbackInfo&);
  OCEndpoint(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_endpoint_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_addr(const Napi::CallbackInfo&);
         void set_addr(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_addr_local(const Napi::CallbackInfo&);
         void set_addr_local(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_device(const Napi::CallbackInfo&);
         void set_device(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_di(const Napi::CallbackInfo&);
         void set_di(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_flags(const Napi::CallbackInfo&);
         void set_flags(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_interface_index(const Napi::CallbackInfo&);
         void set_interface_index(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_priority(const Napi::CallbackInfo&);
         void set_priority(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_version(const Napi::CallbackInfo&);
         void set_version(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_endpoint_t> m_pvalue;
};


class OCEventCallback : public Napi::ObjectWrap<OCEventCallback>
{
public:
  OCEventCallback(const Napi::CallbackInfo&);
  OCEventCallback(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_event_callback_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_callback(const Napi::CallbackInfo&);
         void set_callback(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value callback_function; Napi::Value callback_data;

  Napi::Value get_data(const Napi::CallbackInfo&);
         void set_data(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_timer(const Napi::CallbackInfo&);
         void set_timer(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_event_callback_s> m_pvalue;
};

class OCHandler : public Napi::ObjectWrap<OCHandler>
{
public:
  OCHandler(const Napi::CallbackInfo&);
  OCHandler(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_handler_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_init(const Napi::CallbackInfo&);
         void set_init(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value init_function; Napi::Value init_data;

  Napi::Value get_register_resources(const Napi::CallbackInfo&);
         void set_register_resources(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value register_resources_function; Napi::Value register_resources_data;

  Napi::Value get_requests_entry(const Napi::CallbackInfo&);
         void set_requests_entry(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value requests_entry_function; Napi::Value requests_entry_data;

  Napi::Value get_signal_event_loop(const Napi::CallbackInfo&);
         void set_signal_event_loop(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value signal_event_loop_function; Napi::Value signal_event_loop_data;


  std::shared_ptr<oc_handler_t> m_pvalue;
};

class OCIPv4Addr : public Napi::ObjectWrap<OCIPv4Addr>
{
public:
  OCIPv4Addr(const Napi::CallbackInfo&);
  OCIPv4Addr(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ipv4_addr_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_address(const Napi::CallbackInfo&);
         void set_address(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_port(const Napi::CallbackInfo&);
         void set_port(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ipv4_addr_t> m_pvalue;
};

class OCIPv6Addr : public Napi::ObjectWrap<OCIPv6Addr>
{
public:
  OCIPv6Addr(const Napi::CallbackInfo&);
  OCIPv6Addr(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ipv6_addr_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_address(const Napi::CallbackInfo&);
         void set_address(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_port(const Napi::CallbackInfo&);
         void set_port(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_scope(const Napi::CallbackInfo&);
         void set_scope(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ipv6_addr_t> m_pvalue;
};

class OCLEAddr : public Napi::ObjectWrap<OCLEAddr>
{
public:
  OCLEAddr(const Napi::CallbackInfo&);
  OCLEAddr(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_le_addr_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_address(const Napi::CallbackInfo&);
         void set_address(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_type(const Napi::CallbackInfo&);
         void set_type(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_le_addr_t> m_pvalue;
};

class OCLinkParams : public Napi::ObjectWrap<OCLinkParams>
{
public:
  OCLinkParams(const Napi::CallbackInfo&);
  OCLinkParams(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_link_params_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_key(const Napi::CallbackInfo&);
         void set_key(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_value(const Napi::CallbackInfo&);
         void set_value(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_link_params_t> m_pvalue;
};

class OCLink : public Napi::ObjectWrap<OCLink>
{
public:
  OCLink(const Napi::CallbackInfo&);
  OCLink(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_link_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_ins(const Napi::CallbackInfo&);
         void set_ins(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_interfaces(const Napi::CallbackInfo&);
         void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_rel(const Napi::CallbackInfo&);
         void set_rel(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_link_s> m_pvalue;
};



class OCMmem : public Napi::ObjectWrap<OCMmem>
{
public:
  OCMmem(const Napi::CallbackInfo&);
  OCMmem(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_mmem*() { return m_pvalue.get(); }
private:
  Napi::Value get_size(const Napi::CallbackInfo&);
         void set_size(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_mmem> m_pvalue;
};

class OCNetworkInterfaceCb : public Napi::ObjectWrap<OCNetworkInterfaceCb>
{
public:
  OCNetworkInterfaceCb(const Napi::CallbackInfo&);
  OCNetworkInterfaceCb(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_network_interface_cb*() { return m_pvalue.get(); }
private:

  std::shared_ptr<oc_network_interface_cb> m_pvalue;
};

class OCPlatformInfo : public Napi::ObjectWrap<OCPlatformInfo>
{
public:
  OCPlatformInfo(const Napi::CallbackInfo&);
  OCPlatformInfo(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_platform_info_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_data(const Napi::CallbackInfo&);
         void set_data(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_init_platform_cb(const Napi::CallbackInfo&);
         void set_init_platform_cb(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value init_platform_cb_function; Napi::Value init_platform_cb_data;

  Napi::Value get_mfg_name(const Napi::CallbackInfo&);
         void set_mfg_name(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_pi(const Napi::CallbackInfo&);
         void set_pi(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_platform_info_t> m_pvalue;
};

class OCProcess : public Napi::ObjectWrap<OCProcess>
{
public:
  OCProcess(const Napi::CallbackInfo&);
  OCProcess(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_process*() { return m_pvalue.get(); }
private:
  Napi::Value get_name(const Napi::CallbackInfo&);
         void set_name(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_needspoll(const Napi::CallbackInfo&);
         void set_needspoll(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_state(const Napi::CallbackInfo&);
         void set_state(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_process> m_pvalue;
};

class OCPropertiesCb : public Napi::ObjectWrap<OCPropertiesCb>
{
public:
  OCPropertiesCb(const Napi::CallbackInfo&);
  OCPropertiesCb(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_properties_cb_t*() { return m_pvalue.get(); }
private:

  std::shared_ptr<oc_properties_cb_t> m_pvalue;
};

class OCRep : public Napi::ObjectWrap<OCRep>
{
public:
  OCRep(const Napi::CallbackInfo&);
  OCRep(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_rep_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_name(const Napi::CallbackInfo&);
         void set_name(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_type(const Napi::CallbackInfo&);
         void set_type(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_rep_s> m_pvalue;
};

class OCRequestHandler : public Napi::ObjectWrap<OCRequestHandler>
{
public:
  OCRequestHandler(const Napi::CallbackInfo&);
  OCRequestHandler(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_request_handler_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_cb(const Napi::CallbackInfo&);
         void set_cb(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value cb_function; Napi::Value cb_data;

  Napi::Value get_user_data(const Napi::CallbackInfo&);
         void set_user_data(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_request_handler_s> m_pvalue;
};

class OCRequest : public Napi::ObjectWrap<OCRequest>
{
public:
  OCRequest(const Napi::CallbackInfo&);
  OCRequest(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_request_t*() { return m_pvalue.get(); }
private:
  Napi::Value get__payload(const Napi::CallbackInfo&);
         void set__payload(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get__payload_len(const Napi::CallbackInfo&);
         void set__payload_len(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_content_format(const Napi::CallbackInfo&);
         void set_content_format(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_query(const Napi::CallbackInfo&);
         void set_query(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_query_len(const Napi::CallbackInfo&);
         void set_query_len(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_request_t> m_pvalue;
};

class OCResource : public Napi::ObjectWrap<OCResource>
{
public:
  OCResource(const Napi::CallbackInfo&);
  OCResource(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_resource_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_default_interface(const Napi::CallbackInfo&);
         void set_default_interface(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_delete_handler(const Napi::CallbackInfo&);
         void set_delete_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_device(const Napi::CallbackInfo&);
         void set_device(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_get_handler(const Napi::CallbackInfo&);
         void set_get_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_get_properties(const Napi::CallbackInfo&);
         void set_get_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_interfaces(const Napi::CallbackInfo&);
         void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_name(const Napi::CallbackInfo&);
         void set_name(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_num_links(const Napi::CallbackInfo&);
         void set_num_links(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_num_observers(const Napi::CallbackInfo&);
         void set_num_observers(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_observe_period_seconds(const Napi::CallbackInfo&);
         void set_observe_period_seconds(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_post_handler(const Napi::CallbackInfo&);
         void set_post_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_properties(const Napi::CallbackInfo&);
         void set_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_put_handler(const Napi::CallbackInfo&);
         void set_put_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_set_properties(const Napi::CallbackInfo&);
         void set_set_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_func_desc(const Napi::CallbackInfo&);
         void set_tag_func_desc(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_desc(const Napi::CallbackInfo&);
         void set_tag_pos_desc(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_rel(const Napi::CallbackInfo&);
         void set_tag_pos_rel(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_types(const Napi::CallbackInfo&);
         void set_types(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_uri(const Napi::CallbackInfo&);
         void set_uri(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_resource_s> m_pvalue;
};

class OCResponse : public Napi::ObjectWrap<OCResponse>
{
public:
  OCResponse(const Napi::CallbackInfo&);
  OCResponse(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_response_t*() { return m_pvalue.get(); }
private:

  std::shared_ptr<oc_response_t> m_pvalue;
};

class OCRole : public Napi::ObjectWrap<OCRole>
{
public:
  OCRole(const Napi::CallbackInfo&);
  OCRole(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_role_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_authority(const Napi::CallbackInfo&);
         void set_authority(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_role(const Napi::CallbackInfo&);
         void set_role(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_role_t> m_pvalue;
};

class OCResourceType : public Napi::ObjectWrap<OCResourceType>
{
public:
  OCResourceType(const Napi::CallbackInfo&);
  OCResourceType(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_rt_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_rt(const Napi::CallbackInfo&);
         void set_rt(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_rt_t> m_pvalue;
};

class OCSecurityAce : public Napi::ObjectWrap<OCSecurityAce>
{
public:
  OCSecurityAce(const Napi::CallbackInfo&);
  OCSecurityAce(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_ace_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_aceid(const Napi::CallbackInfo&);
         void set_aceid(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_permission(const Napi::CallbackInfo&);
         void set_permission(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_subject(const Napi::CallbackInfo&);
         void set_subject(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_subject_type(const Napi::CallbackInfo&);
         void set_subject_type(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_ace_t> m_pvalue;
};

class OCSecurityAcl : public Napi::ObjectWrap<OCSecurityAcl>
{
public:
  OCSecurityAcl(const Napi::CallbackInfo&);
  OCSecurityAcl(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_acl_s*() { return m_pvalue.get(); }
private:
  Napi::Value get_rowneruuid(const Napi::CallbackInfo&);
         void set_rowneruuid(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_acl_s> m_pvalue;
};

class OCCreds : public Napi::ObjectWrap<OCCreds>
{
public:
  OCCreds(const Napi::CallbackInfo&);
  OCCreds(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_creds_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_rowneruuid(const Napi::CallbackInfo&);
         void set_rowneruuid(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_creds_t> m_pvalue;
};

class OCCred : public Napi::ObjectWrap<OCCred>
{
public:
  OCCred(const Napi::CallbackInfo&);
  OCCred(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_cred_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_chain(const Napi::CallbackInfo&);
         void set_chain(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_child(const Napi::CallbackInfo&);
         void set_child(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_credid(const Napi::CallbackInfo&);
         void set_credid(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_credtype(const Napi::CallbackInfo&);
         void set_credtype(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_credusage(const Napi::CallbackInfo&);
         void set_credusage(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_owner_cred(const Napi::CallbackInfo&);
         void set_owner_cred(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_privatedata(const Napi::CallbackInfo&);
         void set_privatedata(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_publicdata(const Napi::CallbackInfo&);
         void set_publicdata(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_subjectuuid(const Napi::CallbackInfo&);
         void set_subjectuuid(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_cred_t> m_pvalue;
};

class OCSessionEventCb : public Napi::ObjectWrap<OCSessionEventCb>
{
public:
  OCSessionEventCb(const Napi::CallbackInfo&);
  OCSessionEventCb(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_session_event_cb*() { return m_pvalue.get(); }
private:

  std::shared_ptr<oc_session_event_cb> m_pvalue;
};

class OCSoftwareUpdateHandler : public Napi::ObjectWrap<OCSoftwareUpdateHandler>
{
public:
  OCSoftwareUpdateHandler(const Napi::CallbackInfo&);
  OCSoftwareUpdateHandler(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_swupdate_cb_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_check_new_version(const Napi::CallbackInfo&);
         void set_check_new_version(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value check_new_version_function; Napi::Value check_new_version_data;

  Napi::Value get_download_update(const Napi::CallbackInfo&);
         void set_download_update(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value download_update_function; Napi::Value download_update_data;

  Napi::Value get_perform_upgrade(const Napi::CallbackInfo&);
         void set_perform_upgrade(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value perform_upgrade_function; Napi::Value perform_upgrade_data;

  Napi::Value get_validate_purl(const Napi::CallbackInfo&);
         void set_validate_purl(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value validate_purl_function; Napi::Value validate_purl_data;


  std::shared_ptr<oc_swupdate_cb_t> m_pvalue;
};


class OCUuid : public Napi::ObjectWrap<OCUuid>
{
public:
  OCUuid(const Napi::CallbackInfo&);
  OCUuid(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_uuid_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_id(const Napi::CallbackInfo&);
         void set_id(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_uuid_t> m_pvalue;
};

class OCAceSubject : public Napi::ObjectWrap<OCAceSubject>
{
public:
  OCAceSubject(const Napi::CallbackInfo&);
  OCAceSubject(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ace_subject_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_conn(const Napi::CallbackInfo&);
         void set_conn(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_uuid(const Napi::CallbackInfo&);
         void set_uuid(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ace_subject_t> m_pvalue;
};

class DevAddr : public Napi::ObjectWrap<DevAddr>
{
public:
  DevAddr(const Napi::CallbackInfo&);
  DevAddr(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_endpoint_t::dev_addr*() { return m_pvalue.get(); }
private:
  Napi::Value get_bt(const Napi::CallbackInfo&);
         void set_bt(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_ipv4(const Napi::CallbackInfo&);
         void set_ipv4(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_ipv6(const Napi::CallbackInfo&);
         void set_ipv6(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_endpoint_t::dev_addr> m_pvalue;
};


class OCAceConnectionType : public Napi::ObjectWrap<OCAceConnectionType>
{
public:
  OCAceConnectionType(const Napi::CallbackInfo&);
  OCAceConnectionType(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ace_connection_type_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_CONN_AUTH_CRYPT(const Napi::CallbackInfo&);
         void set_OC_CONN_AUTH_CRYPT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CONN_ANON_CLEAR(const Napi::CallbackInfo&);
         void set_OC_CONN_ANON_CLEAR(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ace_connection_type_t> m_pvalue;
};

class OCAcePermissionsMask : public Napi::ObjectWrap<OCAcePermissionsMask>
{
public:
  OCAcePermissionsMask(const Napi::CallbackInfo&);
  OCAcePermissionsMask(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ace_permissions_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_PERM_NONE(const Napi::CallbackInfo&);
         void set_OC_PERM_NONE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PERM_CREATE(const Napi::CallbackInfo&);
         void set_OC_PERM_CREATE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PERM_RETRIEVE(const Napi::CallbackInfo&);
         void set_OC_PERM_RETRIEVE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PERM_UPDATE(const Napi::CallbackInfo&);
         void set_OC_PERM_UPDATE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PERM_DELETE(const Napi::CallbackInfo&);
         void set_OC_PERM_DELETE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PERM_NOTIFY(const Napi::CallbackInfo&);
         void set_OC_PERM_NOTIFY(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ace_permissions_t> m_pvalue;
};

class OCAceSubjectType : public Napi::ObjectWrap<OCAceSubjectType>
{
public:
  OCAceSubjectType(const Napi::CallbackInfo&);
  OCAceSubjectType(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ace_subject_type_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_SUBJECT_UUID(const Napi::CallbackInfo&);
         void set_OC_SUBJECT_UUID(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SUBJECT_ROLE(const Napi::CallbackInfo&);
         void set_OC_SUBJECT_ROLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SUBJECT_CONN(const Napi::CallbackInfo&);
         void set_OC_SUBJECT_CONN(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ace_subject_type_t> m_pvalue;
};

class OCAceWildcard : public Napi::ObjectWrap<OCAceWildcard>
{
public:
  OCAceWildcard(const Napi::CallbackInfo&);
  OCAceWildcard(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_ace_wildcard_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_ACE_NO_WC(const Napi::CallbackInfo&);
         void set_OC_ACE_NO_WC(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ACE_WC_ALL(const Napi::CallbackInfo&);
         void set_OC_ACE_WC_ALL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ACE_WC_ALL_SECURED(const Napi::CallbackInfo&);
         void set_OC_ACE_WC_ALL_SECURED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ACE_WC_ALL_PUBLIC(const Napi::CallbackInfo&);
         void set_OC_ACE_WC_ALL_PUBLIC(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_ace_wildcard_t> m_pvalue;
};


class OCDiscoveryFlags : public Napi::ObjectWrap<OCDiscoveryFlags>
{
public:
  OCDiscoveryFlags(const Napi::CallbackInfo&);
  OCDiscoveryFlags(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_discovery_flags_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_STOP_DISCOVERY(const Napi::CallbackInfo&);
         void set_OC_STOP_DISCOVERY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CONTINUE_DISCOVERY(const Napi::CallbackInfo&);
         void set_OC_CONTINUE_DISCOVERY(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_discovery_flags_t> m_pvalue;
};

class OCQos : public Napi::ObjectWrap<OCQos>
{
public:
  OCQos(const Napi::CallbackInfo&);
  OCQos(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_qos_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_HIGH_QOS(const Napi::CallbackInfo&);
         void set_HIGH_QOS(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_LOW_QOS(const Napi::CallbackInfo&);
         void set_LOW_QOS(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_qos_t> m_pvalue;
};

class OCCloudError : public Napi::ObjectWrap<OCCloudError>
{
public:
  OCCloudError(const Napi::CallbackInfo&);
  OCCloudError(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_cloud_error_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_CLOUD_OK(const Napi::CallbackInfo&);
         void set_CLOUD_OK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_CLOUD_ERROR_RESPONSE(const Napi::CallbackInfo&);
         void set_CLOUD_ERROR_RESPONSE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_CLOUD_ERROR_CONNECT(const Napi::CallbackInfo&);
         void set_CLOUD_ERROR_CONNECT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN(const Napi::CallbackInfo&);
         void set_CLOUD_ERROR_REFRESH_ACCESS_TOKEN(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_cloud_error_t> m_pvalue;
};

class OCCloudStatusMask : public Napi::ObjectWrap<OCCloudStatusMask>
{
public:
  OCCloudStatusMask(const Napi::CallbackInfo&);
  OCCloudStatusMask(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_cloud_status_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo&);
         void set_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_REGISTERED(const Napi::CallbackInfo&);
         void set_OC_CLOUD_REGISTERED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo&);
         void set_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo&);
         void set_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo&);
         void set_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo&);
         void set_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_FAILURE(const Napi::CallbackInfo&);
         void set_OC_CLOUD_FAILURE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo&);
         void set_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_cloud_status_t> m_pvalue;
};

class OCCloudPrivisoningStatus : public Napi::ObjectWrap<OCCloudPrivisoningStatus>
{
public:
  OCCloudPrivisoningStatus(const Napi::CallbackInfo&);
  OCCloudPrivisoningStatus(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_cps_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo&);
         void set_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo&);
         void set_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CPS_REGISTERING(const Napi::CallbackInfo&);
         void set_OC_CPS_REGISTERING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CPS_REGISTERED(const Napi::CallbackInfo&);
         void set_OC_CPS_REGISTERED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CPS_FAILED(const Napi::CallbackInfo&);
         void set_OC_CPS_FAILED(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_cps_t> m_pvalue;
};

#ifdef OC_TCP
class tcpCsmState : public Napi::ObjectWrap<tcpCsmState>
{
public:
  tcpCsmState(const Napi::CallbackInfo&);
  tcpCsmState(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator tcp_csm_state_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_CSM_NONE(const Napi::CallbackInfo&);
         void set_CSM_NONE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_CSM_SENT(const Napi::CallbackInfo&);
         void set_CSM_SENT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_CSM_DONE(const Napi::CallbackInfo&);
         void set_CSM_DONE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_CSM_ERROR(const Napi::CallbackInfo&);
         void set_CSM_ERROR(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<tcp_csm_state_t> m_pvalue;
};
#endif

class OCCredType : public Napi::ObjectWrap<OCCredType>
{
public:
  OCCredType(const Napi::CallbackInfo&);
  OCCredType(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_credtype_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_CREDTYPE_NULL(const Napi::CallbackInfo&);
         void set_OC_CREDTYPE_NULL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDTYPE_PSK(const Napi::CallbackInfo&);
         void set_OC_CREDTYPE_PSK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDTYPE_CERT(const Napi::CallbackInfo&);
         void set_OC_CREDTYPE_CERT(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_credtype_t> m_pvalue;
};

class OCCredUsage : public Napi::ObjectWrap<OCCredUsage>
{
public:
  OCCredUsage(const Napi::CallbackInfo&);
  OCCredUsage(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_credusage_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_CREDUSAGE_NULL(const Napi::CallbackInfo&);
         void set_OC_CREDUSAGE_NULL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo&);
         void set_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo&);
         void set_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo&);
         void set_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo&);
         void set_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo&);
         void set_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_credusage_t> m_pvalue;
};

class OCEncoding : public Napi::ObjectWrap<OCEncoding>
{
public:
  OCEncoding(const Napi::CallbackInfo&);
  OCEncoding(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sec_encoding_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo&);
         void set_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENCODING_BASE64(const Napi::CallbackInfo&);
         void set_OC_ENCODING_BASE64(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENCODING_RAW(const Napi::CallbackInfo&);
         void set_OC_ENCODING_RAW(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENCODING_PEM(const Napi::CallbackInfo&);
         void set_OC_ENCODING_PEM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENCODING_HANDLE(const Napi::CallbackInfo&);
         void set_OC_ENCODING_HANDLE(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sec_encoding_t> m_pvalue;
};

class OCFVersion : public Napi::ObjectWrap<OCFVersion>
{
public:
  OCFVersion(const Napi::CallbackInfo&);
  OCFVersion(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator ocf_version_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OCF_VER_1_0_0(const Napi::CallbackInfo&);
         void set_OCF_VER_1_0_0(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OIC_VER_1_1_0(const Napi::CallbackInfo&);
         void set_OIC_VER_1_1_0(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<ocf_version_t> m_pvalue;
};

class transportFlags : public Napi::ObjectWrap<transportFlags>
{
public:
  transportFlags(const Napi::CallbackInfo&);
  transportFlags(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator transport_flags*() { return m_pvalue.get(); }
private:
  Napi::Value get_DISCOVERY(const Napi::CallbackInfo&);
         void set_DISCOVERY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_SECURED(const Napi::CallbackInfo&);
         void set_SECURED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_IPV4(const Napi::CallbackInfo&);
         void set_IPV4(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_IPV6(const Napi::CallbackInfo&);
         void set_IPV6(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_TCP(const Napi::CallbackInfo&);
         void set_TCP(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_GATT(const Napi::CallbackInfo&);
         void set_GATT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_MULTICAST(const Napi::CallbackInfo&);
         void set_MULTICAST(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<transport_flags> m_pvalue;
};

class OCEnum : public Napi::ObjectWrap<OCEnum>
{
public:
  OCEnum(const Napi::CallbackInfo&);
  OCEnum(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_enum_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_ENUM_ABORTED(const Napi::CallbackInfo&);
         void set_OC_ENUM_ABORTED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ACTIVE(const Napi::CallbackInfo&);
         void set_OC_ENUM_ACTIVE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_AIRDRY(const Napi::CallbackInfo&);
         void set_OC_ENUM_AIRDRY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ARMEDAWAY(const Napi::CallbackInfo&);
         void set_OC_ENUM_ARMEDAWAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ARMEDINSTANT(const Napi::CallbackInfo&);
         void set_OC_ENUM_ARMEDINSTANT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ARMEDMAXIMUM(const Napi::CallbackInfo&);
         void set_OC_ENUM_ARMEDMAXIMUM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ARMEDNIGHTSTAY(const Napi::CallbackInfo&);
         void set_OC_ENUM_ARMEDNIGHTSTAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ARMEDSTAY(const Napi::CallbackInfo&);
         void set_OC_ENUM_ARMEDSTAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_AROMA(const Napi::CallbackInfo&);
         void set_OC_ENUM_AROMA(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_AI(const Napi::CallbackInfo&);
         void set_OC_ENUM_AI(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_AUTO(const Napi::CallbackInfo&);
         void set_OC_ENUM_AUTO(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_BOILING(const Napi::CallbackInfo&);
         void set_OC_ENUM_BOILING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_BREWING(const Napi::CallbackInfo&);
         void set_OC_ENUM_BREWING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_CANCELLED(const Napi::CallbackInfo&);
         void set_OC_ENUM_CANCELLED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_CIRCULATING(const Napi::CallbackInfo&);
         void set_OC_ENUM_CIRCULATING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_CLEANING(const Napi::CallbackInfo&);
         void set_OC_ENUM_CLEANING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_CLOTHES(const Napi::CallbackInfo&);
         void set_OC_ENUM_CLOTHES(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_COMPLETED(const Napi::CallbackInfo&);
         void set_OC_ENUM_COMPLETED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_COOL(const Napi::CallbackInfo&);
         void set_OC_ENUM_COOL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_DELICATE(const Napi::CallbackInfo&);
         void set_OC_ENUM_DELICATE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_DISABLED(const Napi::CallbackInfo&);
         void set_OC_ENUM_DISABLED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_DOWN(const Napi::CallbackInfo&);
         void set_OC_ENUM_DOWN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_DUAL(const Napi::CallbackInfo&);
         void set_OC_ENUM_DUAL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_DRY(const Napi::CallbackInfo&);
         void set_OC_ENUM_DRY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ENABLED(const Napi::CallbackInfo&);
         void set_OC_ENUM_ENABLED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_EXTENDED(const Napi::CallbackInfo&);
         void set_OC_ENUM_EXTENDED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_FAN(const Napi::CallbackInfo&);
         void set_OC_ENUM_FAN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_FAST(const Napi::CallbackInfo&);
         void set_OC_ENUM_FAST(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_FILTERMATERIAL(const Napi::CallbackInfo&);
         void set_OC_ENUM_FILTERMATERIAL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_FOCUSED(const Napi::CallbackInfo&);
         void set_OC_ENUM_FOCUSED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_GRINDING(const Napi::CallbackInfo&);
         void set_OC_ENUM_GRINDING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_HEATING(const Napi::CallbackInfo&);
         void set_OC_ENUM_HEATING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_HEAVY(const Napi::CallbackInfo&);
         void set_OC_ENUM_HEAVY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_IDLE(const Napi::CallbackInfo&);
         void set_OC_ENUM_IDLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_INK(const Napi::CallbackInfo&);
         void set_OC_ENUM_INK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_INKBLACK(const Napi::CallbackInfo&);
         void set_OC_ENUM_INKBLACK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_INKCYAN(const Napi::CallbackInfo&);
         void set_OC_ENUM_INKCYAN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_INKMAGENTA(const Napi::CallbackInfo&);
         void set_OC_ENUM_INKMAGENTA(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_INKTRICOLOUR(const Napi::CallbackInfo&);
         void set_OC_ENUM_INKTRICOLOUR(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_INKYELLOW(const Napi::CallbackInfo&);
         void set_OC_ENUM_INKYELLOW(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_KEEPWARM(const Napi::CallbackInfo&);
         void set_OC_ENUM_KEEPWARM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_NORMAL(const Napi::CallbackInfo&);
         void set_OC_ENUM_NORMAL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_NOTSUPPORTED(const Napi::CallbackInfo&);
         void set_OC_ENUM_NOTSUPPORTED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PAUSE(const Napi::CallbackInfo&);
         void set_OC_ENUM_PAUSE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PENDING(const Napi::CallbackInfo&);
         void set_OC_ENUM_PENDING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PENDINGHELD(const Napi::CallbackInfo&);
         void set_OC_ENUM_PENDINGHELD(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PERMAPRESS(const Napi::CallbackInfo&);
         void set_OC_ENUM_PERMAPRESS(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PREWASH(const Napi::CallbackInfo&);
         void set_OC_ENUM_PREWASH(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PROCESSING(const Napi::CallbackInfo&);
         void set_OC_ENUM_PROCESSING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_PURE(const Napi::CallbackInfo&);
         void set_OC_ENUM_PURE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_QUICK(const Napi::CallbackInfo&);
         void set_OC_ENUM_QUICK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_QUIET(const Napi::CallbackInfo&);
         void set_OC_ENUM_QUIET(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_RINSE(const Napi::CallbackInfo&);
         void set_OC_ENUM_RINSE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_SECTORED(const Napi::CallbackInfo&);
         void set_OC_ENUM_SECTORED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_SILENT(const Napi::CallbackInfo&);
         void set_OC_ENUM_SILENT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_SLEEP(const Napi::CallbackInfo&);
         void set_OC_ENUM_SLEEP(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_SMART(const Napi::CallbackInfo&);
         void set_OC_ENUM_SMART(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_SPOT(const Napi::CallbackInfo&);
         void set_OC_ENUM_SPOT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_STEAM(const Napi::CallbackInfo&);
         void set_OC_ENUM_STEAM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_STOPPED(const Napi::CallbackInfo&);
         void set_OC_ENUM_STOPPED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_SPIN(const Napi::CallbackInfo&);
         void set_OC_ENUM_SPIN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_TESTING(const Napi::CallbackInfo&);
         void set_OC_ENUM_TESTING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_TONER(const Napi::CallbackInfo&);
         void set_OC_ENUM_TONER(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_TONERBLACK(const Napi::CallbackInfo&);
         void set_OC_ENUM_TONERBLACK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_TONERCYAN(const Napi::CallbackInfo&);
         void set_OC_ENUM_TONERCYAN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_TONERMAGENTA(const Napi::CallbackInfo&);
         void set_OC_ENUM_TONERMAGENTA(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_TONERYELLOW(const Napi::CallbackInfo&);
         void set_OC_ENUM_TONERYELLOW(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_WARM(const Napi::CallbackInfo&);
         void set_OC_ENUM_WARM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_WASH(const Napi::CallbackInfo&);
         void set_OC_ENUM_WASH(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_WET(const Napi::CallbackInfo&);
         void set_OC_ENUM_WET(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_WIND(const Napi::CallbackInfo&);
         void set_OC_ENUM_WIND(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_WRINKLEPREVENT(const Napi::CallbackInfo&);
         void set_OC_ENUM_WRINKLEPREVENT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_ENUM_ZIGZAG(const Napi::CallbackInfo&);
         void set_OC_ENUM_ZIGZAG(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_enum_t> m_pvalue;
};

class OCPositionDescription : public Napi::ObjectWrap<OCPositionDescription>
{
public:
  OCPositionDescription(const Napi::CallbackInfo&);
  OCPositionDescription(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_pos_description_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_POS_UNKNOWN(const Napi::CallbackInfo&);
         void set_OC_POS_UNKNOWN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_TOP(const Napi::CallbackInfo&);
         void set_OC_POS_TOP(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_BOTTOM(const Napi::CallbackInfo&);
         void set_OC_POS_BOTTOM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_LEFT(const Napi::CallbackInfo&);
         void set_OC_POS_LEFT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_RIGHT(const Napi::CallbackInfo&);
         void set_OC_POS_RIGHT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_CENTRE(const Napi::CallbackInfo&);
         void set_OC_POS_CENTRE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_TOPLEFT(const Napi::CallbackInfo&);
         void set_OC_POS_TOPLEFT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo&);
         void set_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_CENTRELEFT(const Napi::CallbackInfo&);
         void set_OC_POS_CENTRELEFT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_CENTRERIGHT(const Napi::CallbackInfo&);
         void set_OC_POS_CENTRERIGHT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo&);
         void set_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_TOPRIGHT(const Napi::CallbackInfo&);
         void set_OC_POS_TOPRIGHT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_TOPCENTRE(const Napi::CallbackInfo&);
         void set_OC_POS_TOPCENTRE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo&);
         void set_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_pos_description_t> m_pvalue;
};


class OCInterfaceEvent : public Napi::ObjectWrap<OCInterfaceEvent>
{
public:
  OCInterfaceEvent(const Napi::CallbackInfo&);
  OCInterfaceEvent(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_interface_event_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_NETWORK_INTERFACE_DOWN(const Napi::CallbackInfo&);
         void set_NETWORK_INTERFACE_DOWN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_NETWORK_INTERFACE_UP(const Napi::CallbackInfo&);
         void set_NETWORK_INTERFACE_UP(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_interface_event_t> m_pvalue;
};

class OCSpTypesMask : public Napi::ObjectWrap<OCSpTypesMask>
{
public:
  OCSpTypesMask(const Napi::CallbackInfo&);
  OCSpTypesMask(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_sp_types_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_SP_BASELINE(const Napi::CallbackInfo&);
         void set_OC_SP_BASELINE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SP_BLACK(const Napi::CallbackInfo&);
         void set_OC_SP_BLACK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SP_BLUE(const Napi::CallbackInfo&);
         void set_OC_SP_BLUE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SP_PURPLE(const Napi::CallbackInfo&);
         void set_OC_SP_PURPLE(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_sp_types_t> m_pvalue;
};

class OCRepValueType : public Napi::ObjectWrap<OCRepValueType>
{
public:
  OCRepValueType(const Napi::CallbackInfo&);
  OCRepValueType(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_rep_value_type_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_REP_NIL(const Napi::CallbackInfo&);
         void set_OC_REP_NIL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_INT(const Napi::CallbackInfo&);
         void set_OC_REP_INT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_DOUBLE(const Napi::CallbackInfo&);
         void set_OC_REP_DOUBLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_BOOL(const Napi::CallbackInfo&);
         void set_OC_REP_BOOL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_BYTE_STRING(const Napi::CallbackInfo&);
         void set_OC_REP_BYTE_STRING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_STRING(const Napi::CallbackInfo&);
         void set_OC_REP_STRING(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_OBJECT(const Napi::CallbackInfo&);
         void set_OC_REP_OBJECT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_INT_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_INT_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_DOUBLE_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_DOUBLE_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_BOOL_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_BOOL_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_BYTE_STRING_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_BYTE_STRING_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_STRING_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_STRING_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_REP_OBJECT_ARRAY(const Napi::CallbackInfo&);
         void set_OC_REP_OBJECT_ARRAY(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_rep_value_type_t> m_pvalue;
};

class OCContentFormat : public Napi::ObjectWrap<OCContentFormat>
{
public:
  OCContentFormat(const Napi::CallbackInfo&);
  OCContentFormat(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_content_format_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_TEXT_PLAIN(const Napi::CallbackInfo&);
         void set_TEXT_PLAIN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_TEXT_XML(const Napi::CallbackInfo&);
         void set_TEXT_XML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_TEXT_CSV(const Napi::CallbackInfo&);
         void set_TEXT_CSV(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_TEXT_HTML(const Napi::CallbackInfo&);
         void set_TEXT_HTML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_IMAGE_GIF(const Napi::CallbackInfo&);
         void set_IMAGE_GIF(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_IMAGE_JPEG(const Napi::CallbackInfo&);
         void set_IMAGE_JPEG(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_IMAGE_PNG(const Napi::CallbackInfo&);
         void set_IMAGE_PNG(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_IMAGE_TIFF(const Napi::CallbackInfo&);
         void set_IMAGE_TIFF(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_AUDIO_RAW(const Napi::CallbackInfo&);
         void set_AUDIO_RAW(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_VIDEO_RAW(const Napi::CallbackInfo&);
         void set_VIDEO_RAW(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_LINK_FORMAT(const Napi::CallbackInfo&);
         void set_APPLICATION_LINK_FORMAT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_XML(const Napi::CallbackInfo&);
         void set_APPLICATION_XML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_OCTET_STREAM(const Napi::CallbackInfo&);
         void set_APPLICATION_OCTET_STREAM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_RDF_XML(const Napi::CallbackInfo&);
         void set_APPLICATION_RDF_XML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_SOAP_XML(const Napi::CallbackInfo&);
         void set_APPLICATION_SOAP_XML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_ATOM_XML(const Napi::CallbackInfo&);
         void set_APPLICATION_ATOM_XML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_XMPP_XML(const Napi::CallbackInfo&);
         void set_APPLICATION_XMPP_XML(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_EXI(const Napi::CallbackInfo&);
         void set_APPLICATION_EXI(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_FASTINFOSET(const Napi::CallbackInfo&);
         void set_APPLICATION_FASTINFOSET(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_SOAP_FASTINFOSET(const Napi::CallbackInfo&);
         void set_APPLICATION_SOAP_FASTINFOSET(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_JSON(const Napi::CallbackInfo&);
         void set_APPLICATION_JSON(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_X_OBIX_BINARY(const Napi::CallbackInfo&);
         void set_APPLICATION_X_OBIX_BINARY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_CBOR(const Napi::CallbackInfo&);
         void set_APPLICATION_CBOR(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_APPLICATION_VND_OCF_CBOR(const Napi::CallbackInfo&);
         void set_APPLICATION_VND_OCF_CBOR(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_content_format_t> m_pvalue;
};

class OCCoreRes : public Napi::ObjectWrap<OCCoreRes>
{
public:
  OCCoreRes(const Napi::CallbackInfo&);
  OCCoreRes(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_core_resource_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OCF_P(const Napi::CallbackInfo&);
         void set_OCF_P(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_CON(const Napi::CallbackInfo&);
         void set_OCF_CON(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_INTROSPECTION_WK(const Napi::CallbackInfo&);
         void set_OCF_INTROSPECTION_WK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_INTROSPECTION_DATA(const Napi::CallbackInfo&);
         void set_OCF_INTROSPECTION_DATA(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_RES(const Napi::CallbackInfo&);
         void set_OCF_RES(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_MNT(const Napi::CallbackInfo&);
         void set_OCF_MNT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_COAPCLOUDCONF(const Napi::CallbackInfo&);
         void set_OCF_COAPCLOUDCONF(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SW_UPDATE(const Napi::CallbackInfo&);
         void set_OCF_SW_UPDATE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_DOXM(const Napi::CallbackInfo&);
         void set_OCF_SEC_DOXM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_PSTAT(const Napi::CallbackInfo&);
         void set_OCF_SEC_PSTAT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_ACL(const Napi::CallbackInfo&);
         void set_OCF_SEC_ACL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_AEL(const Napi::CallbackInfo&);
         void set_OCF_SEC_AEL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_CRED(const Napi::CallbackInfo&);
         void set_OCF_SEC_CRED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_SDI(const Napi::CallbackInfo&);
         void set_OCF_SEC_SDI(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_SP(const Napi::CallbackInfo&);
         void set_OCF_SEC_SP(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_CSR(const Napi::CallbackInfo&);
         void set_OCF_SEC_CSR(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_SEC_ROLES(const Napi::CallbackInfo&);
         void set_OCF_SEC_ROLES(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OCF_D(const Napi::CallbackInfo&);
         void set_OCF_D(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_core_resource_t> m_pvalue;
};

class OCEventCallbackResult : public Napi::ObjectWrap<OCEventCallbackResult>
{
public:
  OCEventCallbackResult(const Napi::CallbackInfo&);
  OCEventCallbackResult(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_event_callback_retval_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_EVENT_DONE(const Napi::CallbackInfo&);
         void set_OC_EVENT_DONE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_EVENT_CONTINUE(const Napi::CallbackInfo&);
         void set_OC_EVENT_CONTINUE(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_event_callback_retval_t> m_pvalue;
};

class OCInterfaceMask : public Napi::ObjectWrap<OCInterfaceMask>
{
public:
  OCInterfaceMask(const Napi::CallbackInfo&);
  OCInterfaceMask(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_interface_mask_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_IF_BASELINE(const Napi::CallbackInfo&);
         void set_OC_IF_BASELINE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_LL(const Napi::CallbackInfo&);
         void set_OC_IF_LL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_B(const Napi::CallbackInfo&);
         void set_OC_IF_B(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_R(const Napi::CallbackInfo&);
         void set_OC_IF_R(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_RW(const Napi::CallbackInfo&);
         void set_OC_IF_RW(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_A(const Napi::CallbackInfo&);
         void set_OC_IF_A(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_S(const Napi::CallbackInfo&);
         void set_OC_IF_S(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IF_CREATE(const Napi::CallbackInfo&);
         void set_OC_IF_CREATE(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_interface_mask_t> m_pvalue;
};

class OCMethod : public Napi::ObjectWrap<OCMethod>
{
public:
  OCMethod(const Napi::CallbackInfo&);
  OCMethod(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_method_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_GET(const Napi::CallbackInfo&);
         void set_OC_GET(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_POST(const Napi::CallbackInfo&);
         void set_OC_POST(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PUT(const Napi::CallbackInfo&);
         void set_OC_PUT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_DELETE(const Napi::CallbackInfo&);
         void set_OC_DELETE(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_method_t> m_pvalue;
};

class OCResourcePropertiesMask : public Napi::ObjectWrap<OCResourcePropertiesMask>
{
public:
  OCResourcePropertiesMask(const Napi::CallbackInfo&);
  OCResourcePropertiesMask(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_resource_properties_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_DISCOVERABLE(const Napi::CallbackInfo&);
         void set_OC_DISCOVERABLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_OBSERVABLE(const Napi::CallbackInfo&);
         void set_OC_OBSERVABLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SECURE(const Napi::CallbackInfo&);
         void set_OC_SECURE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PERIODIC(const Napi::CallbackInfo&);
         void set_OC_PERIODIC(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_resource_properties_t> m_pvalue;
};

class OCStatus : public Napi::ObjectWrap<OCStatus>
{
public:
  OCStatus(const Napi::CallbackInfo&);
  OCStatus(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_status_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_STATUS_OK(const Napi::CallbackInfo&);
         void set_OC_STATUS_OK(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_CREATED(const Napi::CallbackInfo&);
         void set_OC_STATUS_CREATED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_CHANGED(const Napi::CallbackInfo&);
         void set_OC_STATUS_CHANGED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_DELETED(const Napi::CallbackInfo&);
         void set_OC_STATUS_DELETED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_NOT_MODIFIED(const Napi::CallbackInfo&);
         void set_OC_STATUS_NOT_MODIFIED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_BAD_REQUEST(const Napi::CallbackInfo&);
         void set_OC_STATUS_BAD_REQUEST(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_UNAUTHORIZED(const Napi::CallbackInfo&);
         void set_OC_STATUS_UNAUTHORIZED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_BAD_OPTION(const Napi::CallbackInfo&);
         void set_OC_STATUS_BAD_OPTION(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_FORBIDDEN(const Napi::CallbackInfo&);
         void set_OC_STATUS_FORBIDDEN(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_NOT_FOUND(const Napi::CallbackInfo&);
         void set_OC_STATUS_NOT_FOUND(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_METHOD_NOT_ALLOWED(const Napi::CallbackInfo&);
         void set_OC_STATUS_METHOD_NOT_ALLOWED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_NOT_ACCEPTABLE(const Napi::CallbackInfo&);
         void set_OC_STATUS_NOT_ACCEPTABLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE(const Napi::CallbackInfo&);
         void set_OC_STATUS_REQUEST_ENTITY_TOO_LARGE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE(const Napi::CallbackInfo&);
         void set_OC_STATUS_UNSUPPORTED_MEDIA_TYPE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_INTERNAL_SERVER_ERROR(const Napi::CallbackInfo&);
         void set_OC_STATUS_INTERNAL_SERVER_ERROR(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_NOT_IMPLEMENTED(const Napi::CallbackInfo&);
         void set_OC_STATUS_NOT_IMPLEMENTED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_BAD_GATEWAY(const Napi::CallbackInfo&);
         void set_OC_STATUS_BAD_GATEWAY(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_SERVICE_UNAVAILABLE(const Napi::CallbackInfo&);
         void set_OC_STATUS_SERVICE_UNAVAILABLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_GATEWAY_TIMEOUT(const Napi::CallbackInfo&);
         void set_OC_STATUS_GATEWAY_TIMEOUT(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_STATUS_PROXYING_NOT_SUPPORTED(const Napi::CallbackInfo&);
         void set_OC_STATUS_PROXYING_NOT_SUPPORTED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get___NUM_OC_STATUS_CODES__(const Napi::CallbackInfo&);
         void set___NUM_OC_STATUS_CODES__(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_IGNORE(const Napi::CallbackInfo&);
         void set_OC_IGNORE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_PING_TIMEOUT(const Napi::CallbackInfo&);
         void set_OC_PING_TIMEOUT(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_status_t> m_pvalue;
};

class OCSessionState : public Napi::ObjectWrap<OCSessionState>
{
public:
  OCSessionState(const Napi::CallbackInfo&);
  OCSessionState(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_session_state_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_SESSION_CONNECTED(const Napi::CallbackInfo&);
         void set_OC_SESSION_CONNECTED(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SESSION_DISCONNECTED(const Napi::CallbackInfo&);
         void set_OC_SESSION_DISCONNECTED(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_session_state_t> m_pvalue;
};

class OCSoftwareUpdateResult : public Napi::ObjectWrap<OCSoftwareUpdateResult>
{
public:
  OCSoftwareUpdateResult(const Napi::CallbackInfo&);
  OCSoftwareUpdateResult(const napi_env&, const napi_value&); //TODO
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_swupdate_result_t*() { return m_pvalue.get(); }
private:
  Napi::Value get_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo&);
         void set_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_swupdate_result_t> m_pvalue;
};

