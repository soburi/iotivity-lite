#pragma once
#include <napi.h>
#include <memory>
extern "C" {
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
#include <coap.h>
#include <coap_signal.h>
#include <constants.h>
#include <engine.h>
#include <observe.h>
#include <oc_coap.h>
#include <separate.h>
#include <transactions.h>
}
#include "extra.h"




class OCAceResource : public Napi::ObjectWrap<OCAceResource>
{
public:
    OCAceResource(const Napi::CallbackInfo&);
    virtual ~OCAceResource();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ace_res_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_href(const Napi::CallbackInfo&);
    void set_href(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_interfaces(const Napi::CallbackInfo&);
    void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_types(const Napi::CallbackInfo&);
    void set_types(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_wildcard(const Napi::CallbackInfo&);
    void set_wildcard(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_ace_res_t> m_pvalue;
};

class OCBlockwiseRequestState : public Napi::ObjectWrap<OCBlockwiseRequestState>
{
public:
    OCBlockwiseRequestState(const Napi::CallbackInfo&);
    virtual ~OCBlockwiseRequestState();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_blockwise_request_state_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_base(const Napi::CallbackInfo&);
    void set_base(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_blockwise_request_state_s> m_pvalue;
};

class OCBlockwiseResponseState : public Napi::ObjectWrap<OCBlockwiseResponseState>
{
public:
    OCBlockwiseResponseState(const Napi::CallbackInfo&);
    virtual ~OCBlockwiseResponseState();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_blockwise_response_state_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_base(const Napi::CallbackInfo&);
    void set_base(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_etag(const Napi::CallbackInfo&);
    void set_etag(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_CLIENT)
    Napi::Value get_observe_seq(const Napi::CallbackInfo&);
    void set_observe_seq(const Napi::CallbackInfo&, const Napi::Value&);
#endif



    std::shared_ptr<oc_blockwise_response_state_s> m_pvalue;
};

class OCBlockwiseState : public Napi::ObjectWrap<OCBlockwiseState>
{
public:
    OCBlockwiseState(const Napi::CallbackInfo&);
    virtual ~OCBlockwiseState();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_blockwise_state_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_buffer(const Napi::CallbackInfo&);
    void set_buffer(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_CLEINT)
    Napi::Value get_client_cb(const Napi::CallbackInfo&);
    void set_client_cb(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_endpoint(const Napi::CallbackInfo&);
    void set_endpoint(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_href(const Napi::CallbackInfo&);
    void set_href(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_method(const Napi::CallbackInfo&);
    void set_method(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_CLIENT)
    Napi::Value get_mid(const Napi::CallbackInfo&);
    void set_mid(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_next_block_offset(const Napi::CallbackInfo&);
    void set_next_block_offset(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_payload_size(const Napi::CallbackInfo&);
    void set_payload_size(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_ref_count(const Napi::CallbackInfo&);
    void set_ref_count(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_role(const Napi::CallbackInfo&);
    void set_role(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_CLIENT)
    Napi::Value get_token(const Napi::CallbackInfo&);
    void set_token(const Napi::CallbackInfo&, const Napi::Value&);
#endif
#if defined(OC_CLIENT)
    Napi::Value get_token_len(const Napi::CallbackInfo&);
    void set_token_len(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_uri_query(const Napi::CallbackInfo&);
    void set_uri_query(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_blockwise_state_s> m_pvalue;
};

class OCClientCallback : public Napi::ObjectWrap<OCClientCallback>
{
public:
    OCClientCallback(const Napi::CallbackInfo&);
    virtual ~OCClientCallback();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_client_cb_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_discovery(const Napi::CallbackInfo&);
    void set_discovery(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_endpoint(const Napi::CallbackInfo&);
    void set_endpoint(const Napi::CallbackInfo&, const Napi::Value&);
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
    virtual ~OCClientHandler();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_client_handler_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_discovery(const Napi::CallbackInfo&);
    void set_discovery(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value discovery_function;
    Napi::Value discovery_data;

    Napi::Value get_discovery_all(const Napi::CallbackInfo&);
    void set_discovery_all(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value discovery_all_function;
    Napi::Value discovery_all_data;

    Napi::Value get_response(const Napi::CallbackInfo&);
    void set_response(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value response_function;
    Napi::Value response_data;




    std::shared_ptr<oc_client_handler_t> m_pvalue;
};

class OCClientResponse : public Napi::ObjectWrap<OCClientResponse>
{
public:
    OCClientResponse(const Napi::CallbackInfo&);
    virtual ~OCClientResponse();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_client_response_t*() {
        return m_pvalue.get();
    }
    Napi::Value get__payload(const Napi::CallbackInfo&);
    void set__payload(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get__payload_len(const Napi::CallbackInfo&);
    void set__payload_len(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_code(const Napi::CallbackInfo&);
    void set_code(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_content_format(const Napi::CallbackInfo&);
    void set_content_format(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_endpoint(const Napi::CallbackInfo&);
    void set_endpoint(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_observe_option(const Napi::CallbackInfo&);
    void set_observe_option(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_payload(const Napi::CallbackInfo&);
    void set_payload(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_client_response_t> m_pvalue;
};

class OCCloudContext : public Napi::ObjectWrap<OCCloudContext>
{
public:
    OCCloudContext(const Napi::CallbackInfo&);
    virtual ~OCCloudContext();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_cloud_context_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_callback(const Napi::CallbackInfo&);
    void set_callback(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value callback_function;
    Napi::Value callback_data;

    Napi::Value get_cloud_conf(const Napi::CallbackInfo&);
    void set_cloud_conf(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_cloud_ep(const Napi::CallbackInfo&);
    void set_cloud_ep(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_cloud_ep_state(const Napi::CallbackInfo&);
    void set_cloud_ep_state(const Napi::CallbackInfo&, const Napi::Value&);
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
    Napi::Value get_rd_delete_resources(const Napi::CallbackInfo&);
    void set_rd_delete_resources(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_rd_publish_resources(const Napi::CallbackInfo&);
    void set_rd_publish_resources(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_rd_published_resources(const Napi::CallbackInfo&);
    void set_rd_published_resources(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_retry_count(const Napi::CallbackInfo&);
    void set_retry_count(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_retry_refresh_token_count(const Napi::CallbackInfo&);
    void set_retry_refresh_token_count(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_store(const Napi::CallbackInfo&);
    void set_store(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_user_data(const Napi::CallbackInfo&);
    void set_user_data(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_cloud_context_t> m_pvalue;
};

class OCCloudStore : public Napi::ObjectWrap<OCCloudStore>
{
public:
    OCCloudStore(const Napi::CallbackInfo&);
    virtual ~OCCloudStore();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_cloud_store_t*() {
        return m_pvalue.get();
    }
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
    virtual ~OCCollection();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_collection_s*() {
        return m_pvalue.get();
    }
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

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_collection_s> m_pvalue;
};

class OCCredData : public Napi::ObjectWrap<OCCredData>
{
public:
    OCCredData(const Napi::CallbackInfo&);
    virtual ~OCCredData();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_cred_data_t*() {
        return m_pvalue.get();
    }
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
    virtual ~OCDeviceInfo();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_device_info_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_add_device_cb(const Napi::CallbackInfo&);
    void set_add_device_cb(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value add_device_cb_function;
    Napi::Value add_device_cb_data;

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
    virtual ~OCEndpoint();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_endpoint_t*() {
        return m_pvalue.get();
    }
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

    Napi::Value get_iterator(const Napi::CallbackInfo& info);

    Napi::Value to_string(const Napi::CallbackInfo& info);
    Napi::Value compare(const Napi::CallbackInfo& info);
    Napi::Value copy(const Napi::CallbackInfo& info);
    static Napi::Value string_to_endpoint(const Napi::CallbackInfo& info);
    Napi::Value endpoint_string_parse_path(const Napi::CallbackInfo& info);
    Napi::Value ipv6_endpoint_is_link_local(const Napi::CallbackInfo& info);
    Napi::Value compare_address(const Napi::CallbackInfo& info);
    Napi::Value set_local_address(const Napi::CallbackInfo& info);

    std::shared_ptr<oc_endpoint_t> m_pvalue;
};

class OCEtimer : public Napi::ObjectWrap<OCEtimer>
{
public:
    OCEtimer(const Napi::CallbackInfo&);
    virtual ~OCEtimer();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_etimer*() {
        return m_pvalue.get();
    }
    Napi::Value get_p(const Napi::CallbackInfo&);
    void set_p(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_timer(const Napi::CallbackInfo&);
    void set_timer(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_etimer> m_pvalue;
};

class OCEventCallback : public Napi::ObjectWrap<OCEventCallback>
{
public:
    OCEventCallback(const Napi::CallbackInfo&);
    virtual ~OCEventCallback();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_event_callback_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_callback(const Napi::CallbackInfo&);
    void set_callback(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value callback_function;
    Napi::Value callback_data;

    Napi::Value get_data(const Napi::CallbackInfo&);
    void set_data(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_timer(const Napi::CallbackInfo&);
    void set_timer(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_event_callback_s> m_pvalue;
};

class OCHandler : public Napi::ObjectWrap<OCHandler>
{
public:
    OCHandler(const Napi::CallbackInfo&);
    virtual ~OCHandler();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_handler_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_init(const Napi::CallbackInfo&);
    void set_init(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value init_function;
    Napi::Value init_data;

#if defined(OC_SERVER)
    Napi::Value get_register_resources(const Napi::CallbackInfo&);
    void set_register_resources(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value register_resources_function;
    Napi::Value register_resources_data;

#endif
#if defined(OC_CLIENT)
    Napi::Value get_requests_entry(const Napi::CallbackInfo&);
    void set_requests_entry(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value requests_entry_function;
    Napi::Value requests_entry_data;

#endif

    Napi::FunctionReference init;
#if defined(OC_SERVER)
    Napi::FunctionReference register_resources;
#endif
#if defined(OC_CLIENT)
    Napi::FunctionReference requests_entry;
#endif


    std::shared_ptr<oc_handler_t> m_pvalue;
};

class OCIPv4Addr : public Napi::ObjectWrap<OCIPv4Addr>
{
public:
    OCIPv4Addr(const Napi::CallbackInfo&);
    virtual ~OCIPv4Addr();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ipv4_addr_t*() {
        return m_pvalue.get();
    }
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
    virtual ~OCIPv6Addr();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ipv6_addr_t*() {
        return m_pvalue.get();
    }
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
    virtual ~OCLEAddr();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_le_addr_t*() {
        return m_pvalue.get();
    }
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
    virtual ~OCLinkParams();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_link_params_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_key(const Napi::CallbackInfo&);
    void set_key(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_value(const Napi::CallbackInfo&);
    void set_value(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_link_params_t> m_pvalue;
};

class OCLink : public Napi::ObjectWrap<OCLink>
{
public:
    OCLink(const Napi::CallbackInfo&);
    virtual ~OCLink();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_link_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_ins(const Napi::CallbackInfo&);
    void set_ins(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_interfaces(const Napi::CallbackInfo&);
    void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_rel(const Napi::CallbackInfo&);
    void set_rel(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_resource(const Napi::CallbackInfo&);
    void set_resource(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_link_s> m_pvalue;
};

class OCMemb : public Napi::ObjectWrap<OCMemb>
{
public:
    OCMemb(const Napi::CallbackInfo&);
    virtual ~OCMemb();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_memb*() {
        return m_pvalue.get();
    }
    Napi::Value get_count(const Napi::CallbackInfo&);
    void set_count(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_num(const Napi::CallbackInfo&);
    void set_num(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_size(const Napi::CallbackInfo&);
    void set_size(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_memb> m_pvalue;
};

class OCMessage : public Napi::ObjectWrap<OCMessage>
{
public:
    OCMessage(const Napi::CallbackInfo&);
    virtual ~OCMessage();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_message_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_data(const Napi::CallbackInfo&);
    void set_data(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_SECURITY)
    Napi::Value get_encrypted(const Napi::CallbackInfo&);
    void set_encrypted(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_endpoint(const Napi::CallbackInfo&);
    void set_endpoint(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_length(const Napi::CallbackInfo&);
    void set_length(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_pool(const Napi::CallbackInfo&);
    void set_pool(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_TCP)
    Napi::Value get_read_offset(const Napi::CallbackInfo&);
    void set_read_offset(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_ref_count(const Napi::CallbackInfo&);
    void set_ref_count(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_message_s> m_pvalue;
};

class OCMmem : public Napi::ObjectWrap<OCMmem>
{
public:
    OCMmem(const Napi::CallbackInfo&);
    virtual ~OCMmem();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_mmem*() {
        return m_pvalue.get();
    }
    Napi::Value get_size(const Napi::CallbackInfo&);
    void set_size(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_mmem> m_pvalue;
};

class OCNetworkInterfaceCb : public Napi::ObjectWrap<OCNetworkInterfaceCb>
{
public:
    OCNetworkInterfaceCb(const Napi::CallbackInfo&);
    virtual ~OCNetworkInterfaceCb();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_network_interface_cb*() {
        return m_pvalue.get();
    }
    Napi::Value get_handler(const Napi::CallbackInfo&);
    void set_handler(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value handler_function;
    Napi::Value handler_data;




    std::shared_ptr<oc_network_interface_cb> m_pvalue;
};

class OCPlatformInfo : public Napi::ObjectWrap<OCPlatformInfo>
{
public:
    OCPlatformInfo(const Napi::CallbackInfo&);
    virtual ~OCPlatformInfo();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_platform_info_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_data(const Napi::CallbackInfo&);
    void set_data(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_init_platform_cb(const Napi::CallbackInfo&);
    void set_init_platform_cb(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value init_platform_cb_function;
    Napi::Value init_platform_cb_data;

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
    virtual ~OCProcess();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_process*() {
        return m_pvalue.get();
    }
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
    virtual ~OCPropertiesCb();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_properties_cb_t*() {
        return m_pvalue.get();
    }



    std::shared_ptr<oc_properties_cb_t> m_pvalue;
};

class OCRepresentation : public Napi::ObjectWrap<OCRepresentation>
{
public:
    OCRepresentation(const Napi::CallbackInfo&);
    virtual ~OCRepresentation();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_rep_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_name(const Napi::CallbackInfo&);
    void set_name(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_type(const Napi::CallbackInfo&);
    void set_type(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_value(const Napi::CallbackInfo&);
    void set_value(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);

    Napi::Value get_bool(const Napi::CallbackInfo& info);
    Napi::Value get_bool_array(const Napi::CallbackInfo& info);
    Napi::Value get_byte_string(const Napi::CallbackInfo& info);
    Napi::Value get_byte_string_array(const Napi::CallbackInfo& info);
    Napi::Value get_cbor_errno(const Napi::CallbackInfo& info);
    Napi::Value get_double(const Napi::CallbackInfo& info);
    Napi::Value get_double_array(const Napi::CallbackInfo& info);
    Napi::Value get_object(const Napi::CallbackInfo& info);
    Napi::Value get_object_array(const Napi::CallbackInfo& info);
    Napi::Value get_string(const Napi::CallbackInfo& info);
    Napi::Value get_string_array(const Napi::CallbackInfo& info);
    Napi::Value get_int(const Napi::CallbackInfo& info);
    Napi::Value get_int_array(const Napi::CallbackInfo& info);
    Napi::Value to_json(const Napi::CallbackInfo& info);
    static Napi::Value parse(const Napi::CallbackInfo& info);
    static Napi::Value set_pool(const Napi::CallbackInfo& info);
    static Napi::Value get_encoded_payload_size(const Napi::CallbackInfo& info);
    static Napi::Value get_encoder_buf(const Napi::CallbackInfo& info);
    static Napi::Value add_boolean(const Napi::CallbackInfo& info);
    static Napi::Value add_byte_string(const Napi::CallbackInfo& info);
    static Napi::Value add_double(const Napi::CallbackInfo& info);
    static Napi::Value add_text_string(const Napi::CallbackInfo& info);
    static Napi::Value clear_cbor_errno(const Napi::CallbackInfo& info);
    static Napi::Value close_array(const Napi::CallbackInfo& info);
    static Napi::Value close_object(const Napi::CallbackInfo& info);
    static Napi::Value delete_buffer(const Napi::CallbackInfo& info);
    static Napi::Value end_array(const Napi::CallbackInfo& info);
    static Napi::Value end_links_array(const Napi::CallbackInfo& info);
    static Napi::Value end_object(const Napi::CallbackInfo& info);
    static Napi::Value end_root_object(const Napi::CallbackInfo& info);
    static Napi::Value get_rep_from_root_object(const Napi::CallbackInfo& info);
    static Napi::Value new_buffer(const Napi::CallbackInfo& info);
    static Napi::Value object_array_start_item(const Napi::CallbackInfo& info);
    static Napi::Value object_array_end_item(const Napi::CallbackInfo& info);
    static Napi::Value oc_array_to_bool_array(const Napi::CallbackInfo& info);
    static Napi::Value oc_array_to_double_array(const Napi::CallbackInfo& info);
    static Napi::Value oc_array_to_int_array(const Napi::CallbackInfo& info);
    static Napi::Value oc_array_to_string_array(const Napi::CallbackInfo& info);
    static Napi::Value open_array(const Napi::CallbackInfo& info);
    static Napi::Value open_object(const Napi::CallbackInfo& info);
    static Napi::Value set_boolean(const Napi::CallbackInfo& info);
    static Napi::Value set_bool_array(const Napi::CallbackInfo& info);
    static Napi::Value set_byte_string(const Napi::CallbackInfo& info);
    static Napi::Value set_double(const Napi::CallbackInfo& info);
    static Napi::Value set_double_array(const Napi::CallbackInfo& info);
    static Napi::Value set_key(const Napi::CallbackInfo& info);
    static Napi::Value set_long(const Napi::CallbackInfo& info);
    static Napi::Value set_long_array(const Napi::CallbackInfo& info);
    static Napi::Value set_string_array(const Napi::CallbackInfo& info);
    static Napi::Value set_text_string(const Napi::CallbackInfo& info);
    static Napi::Value set_uint(const Napi::CallbackInfo& info);
    static Napi::Value start_array(const Napi::CallbackInfo& info);
    static Napi::Value start_links_array(const Napi::CallbackInfo& info);
    static Napi::Value start_object(const Napi::CallbackInfo& info);
    static Napi::Value start_root_object(const Napi::CallbackInfo& info);

    std::shared_ptr<oc_rep_s> m_pvalue;
};

class OCRequestHandler : public Napi::ObjectWrap<OCRequestHandler>
{
public:
    OCRequestHandler(const Napi::CallbackInfo&);
    virtual ~OCRequestHandler();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_request_handler_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_cb(const Napi::CallbackInfo&);
    void set_cb(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value cb_function;
    Napi::Value cb_data;

    Napi::Value get_user_data(const Napi::CallbackInfo&);
    void set_user_data(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_request_handler_s> m_pvalue;
};

class OCRequest : public Napi::ObjectWrap<OCRequest>
{
public:
    OCRequest(const Napi::CallbackInfo&);
    virtual ~OCRequest();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_request_t*() {
        return m_pvalue.get();
    }
    Napi::Value get__payload(const Napi::CallbackInfo&);
    void set__payload(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get__payload_len(const Napi::CallbackInfo&);
    void set__payload_len(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_content_format(const Napi::CallbackInfo&);
    void set_content_format(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_origin(const Napi::CallbackInfo&);
    void set_origin(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_query(const Napi::CallbackInfo&);
    void set_query(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_query_len(const Napi::CallbackInfo&);
    void set_query_len(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_request_payload(const Napi::CallbackInfo&);
    void set_request_payload(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_resource(const Napi::CallbackInfo&);
    void set_resource(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_response(const Napi::CallbackInfo&);
    void set_response(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_request_t> m_pvalue;
};

class OCResource : public Napi::ObjectWrap<OCResource>
{
public:
    OCResource(const Napi::CallbackInfo&);
    virtual ~OCResource();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_resource_s*() {
        return m_pvalue.get();
    }
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
#if defined(OC_COLLECTIONS)
    Napi::Value get_num_links(const Napi::CallbackInfo&);
    void set_num_links(const Napi::CallbackInfo&, const Napi::Value&);
#endif
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

    Napi::FunctionReference get_handler;
    Napi::FunctionReference post_handler;
    Napi::FunctionReference put_handler;
    Napi::Value get_value;
    Napi::Value post_value;
    Napi::Value put_value;


    Napi::Value bind_resource_interface(const Napi::CallbackInfo& info);
    Napi::Value bind_resource_type(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY)
    Napi::Value make_public(const Napi::CallbackInfo& info);
#endif
    Napi::Value set_default_interface(const Napi::CallbackInfo& info);
    Napi::Value set_discoverable(const Napi::CallbackInfo& info);
    Napi::Value set_observable(const Napi::CallbackInfo& info);
    Napi::Value set_periodic_observable(const Napi::CallbackInfo& info);
    Napi::Value set_properties_cbs(const Napi::CallbackInfo& info);
    Napi::Value set_request_handler(const Napi::CallbackInfo& info);
    Napi::Value process_baseline_interface(const Napi::CallbackInfo& info);
    Napi::Value notify_observers(const Napi::CallbackInfo& info);

    std::shared_ptr<oc_resource_s> m_pvalue;
};

class OCResponseBuffer : public Napi::ObjectWrap<OCResponseBuffer>
{
public:
    OCResponseBuffer(const Napi::CallbackInfo&);
    virtual ~OCResponseBuffer();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_response_buffer_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_buffer(const Napi::CallbackInfo&);
    void set_buffer(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_buffer_size(const Napi::CallbackInfo&);
    void set_buffer_size(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_code(const Napi::CallbackInfo&);
    void set_code(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_content_format(const Napi::CallbackInfo&);
    void set_content_format(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_response_length(const Napi::CallbackInfo&);
    void set_response_length(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_response_buffer_s> m_pvalue;
};

class OCResponse : public Napi::ObjectWrap<OCResponse>
{
public:
    OCResponse(const Napi::CallbackInfo&);
    virtual ~OCResponse();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_response_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_response_buffer(const Napi::CallbackInfo&);
    void set_response_buffer(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_separate_response(const Napi::CallbackInfo&);
    void set_separate_response(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_response_t> m_pvalue;
};

class OCRole : public Napi::ObjectWrap<OCRole>
{
public:
    OCRole(const Napi::CallbackInfo&);
    virtual ~OCRole();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_role_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_authority(const Napi::CallbackInfo&);
    void set_authority(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_role(const Napi::CallbackInfo&);
    void set_role(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_role_t> m_pvalue;
};

class OCResourceType : public Napi::ObjectWrap<OCResourceType>
{
public:
    OCResourceType(const Napi::CallbackInfo&);
    virtual ~OCResourceType();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_rt_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_rt(const Napi::CallbackInfo&);
    void set_rt(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_rt_t> m_pvalue;
};

class OCSecurityAce : public Napi::ObjectWrap<OCSecurityAce>
{
public:
    OCSecurityAce(const Napi::CallbackInfo&);
    virtual ~OCSecurityAce();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_ace_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_aceid(const Napi::CallbackInfo&);
    void set_aceid(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_permission(const Napi::CallbackInfo&);
    void set_permission(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_subject(const Napi::CallbackInfo&);
    void set_subject(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_subject_type(const Napi::CallbackInfo&);
    void set_subject_type(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_sec_ace_t> m_pvalue;
};

class OCSecurityAcl : public Napi::ObjectWrap<OCSecurityAcl>
{
public:
    OCSecurityAcl(const Napi::CallbackInfo&);
    virtual ~OCSecurityAcl();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_acl_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_rowneruuid(const Napi::CallbackInfo&);
    void set_rowneruuid(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_sec_acl_s> m_pvalue;
};

class OCCreds : public Napi::ObjectWrap<OCCreds>
{
public:
    OCCreds(const Napi::CallbackInfo&);
    virtual ~OCCreds();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_creds_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_rowneruuid(const Napi::CallbackInfo&);
    void set_rowneruuid(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_sec_creds_t> m_pvalue;
};

class OCCred : public Napi::ObjectWrap<OCCred>
{
public:
    OCCred(const Napi::CallbackInfo&);
    virtual ~OCCred();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_cred_t*() {
        return m_pvalue.get();
    }
#if defined(OC_PKI)
    Napi::Value get_chain(const Napi::CallbackInfo&);
    void set_chain(const Napi::CallbackInfo&, const Napi::Value&);
#endif
#if defined(OC_PKI)
    Napi::Value get_child(const Napi::CallbackInfo&);
    void set_child(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_credid(const Napi::CallbackInfo&);
    void set_credid(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_credtype(const Napi::CallbackInfo&);
    void set_credtype(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_PKI)
    Napi::Value get_credusage(const Napi::CallbackInfo&);
    void set_credusage(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_owner_cred(const Napi::CallbackInfo&);
    void set_owner_cred(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_privatedata(const Napi::CallbackInfo&);
    void set_privatedata(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_PKI)
    Napi::Value get_publicdata(const Napi::CallbackInfo&);
    void set_publicdata(const Napi::CallbackInfo&, const Napi::Value&);
#endif
    Napi::Value get_subjectuuid(const Napi::CallbackInfo&);
    void set_subjectuuid(const Napi::CallbackInfo&, const Napi::Value&);


#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value read_credusage(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value read_encoding(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value parse_credusage(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value parse_encoding(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value credtype_string(const Napi::CallbackInfo& info);
#endif

    std::shared_ptr<oc_sec_cred_t> m_pvalue;
};

class OCSeparateResponse : public Napi::ObjectWrap<OCSeparateResponse>
{
public:
    OCSeparateResponse(const Napi::CallbackInfo&);
    virtual ~OCSeparateResponse();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_separate_response_s*() {
        return m_pvalue.get();
    }
    Napi::Value get_active(const Napi::CallbackInfo&);
    void set_active(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_buffer(const Napi::CallbackInfo&);
    void set_buffer(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_separate_response_s> m_pvalue;
};

class OCSessionEventCb : public Napi::ObjectWrap<OCSessionEventCb>
{
public:
    OCSessionEventCb(const Napi::CallbackInfo&);
    virtual ~OCSessionEventCb();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_session_event_cb*() {
        return m_pvalue.get();
    }
    Napi::Value get_handler(const Napi::CallbackInfo&);
    void set_handler(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value handler_function;
    Napi::Value handler_data;


    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_session_event_cb> m_pvalue;
};

class OCSoftwareUpdateHandler : public Napi::ObjectWrap<OCSoftwareUpdateHandler>
{
public:
    OCSoftwareUpdateHandler(const Napi::CallbackInfo&);
    virtual ~OCSoftwareUpdateHandler();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_swupdate_cb_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_check_new_version(const Napi::CallbackInfo&);
    void set_check_new_version(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value check_new_version_function;
    Napi::Value check_new_version_data;

    Napi::Value get_download_update(const Napi::CallbackInfo&);
    void set_download_update(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value download_update_function;
    Napi::Value download_update_data;

    Napi::Value get_perform_upgrade(const Napi::CallbackInfo&);
    void set_perform_upgrade(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value perform_upgrade_function;
    Napi::Value perform_upgrade_data;

    Napi::Value get_validate_purl(const Napi::CallbackInfo&);
    void set_validate_purl(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value validate_purl_function;
    Napi::Value validate_purl_data;


    Napi::FunctionReference validate_purl;
    Napi::FunctionReference check_new_version;
    Napi::FunctionReference download_update;
    Napi::FunctionReference perform_upgrade;



    std::shared_ptr<oc_swupdate_cb_t> m_pvalue;
};

class OCTimer : public Napi::ObjectWrap<OCTimer>
{
public:
    OCTimer(const Napi::CallbackInfo&);
    virtual ~OCTimer();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_timer*() {
        return m_pvalue.get();
    }
    Napi::Value get_interval(const Napi::CallbackInfo&);
    void set_interval(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_start(const Napi::CallbackInfo&);
    void set_start(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_timer> m_pvalue;
};

class OCUuid : public Napi::ObjectWrap<OCUuid>
{
public:
    OCUuid(const Napi::CallbackInfo&);
    virtual ~OCUuid();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_uuid_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_id(const Napi::CallbackInfo&);
    void set_id(const Napi::CallbackInfo&, const Napi::Value&);


    static Napi::Value str_to_uuid(const Napi::CallbackInfo& info);
    static Napi::Value uuid_to_str(const Napi::CallbackInfo& info);
    static Napi::Value gen_uuid(const Napi::CallbackInfo& info);

    std::shared_ptr<oc_uuid_t> m_pvalue;
};

class OCAceSubject : public Napi::ObjectWrap<OCAceSubject>
{
public:
    OCAceSubject(const Napi::CallbackInfo&);
    virtual ~OCAceSubject();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ace_subject_t*() {
        return m_pvalue.get();
    }
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
    virtual ~DevAddr();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_endpoint_t::dev_addr*() {
        return m_pvalue.get();
    }
    Napi::Value get_bt(const Napi::CallbackInfo&);
    void set_bt(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_ipv4(const Napi::CallbackInfo&);
    void set_ipv4(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_ipv6(const Napi::CallbackInfo&);
    void set_ipv6(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_endpoint_t::dev_addr> m_pvalue;
};

class OCValue : public Napi::ObjectWrap<OCValue>
{
public:
    OCValue(const Napi::CallbackInfo&);
    virtual ~OCValue();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_rep_s::oc_rep_value*() {
        return m_pvalue.get();
    }
    Napi::Value get_array(const Napi::CallbackInfo&);
    void set_array(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_boolean(const Napi::CallbackInfo&);
    void set_boolean(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_double_p(const Napi::CallbackInfo&);
    void set_double_p(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_integer(const Napi::CallbackInfo&);
    void set_integer(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_object(const Napi::CallbackInfo&);
    void set_object(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_object_array(const Napi::CallbackInfo&);
    void set_object_array(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_string(const Napi::CallbackInfo&);
    void set_string(const Napi::CallbackInfo&, const Napi::Value&);



    std::shared_ptr<oc_rep_s::oc_rep_value> m_pvalue;
};

class OCArray : public Napi::ObjectWrap<OCArray>
{
public:
    OCArray(const Napi::CallbackInfo&);
    virtual ~OCArray();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_array_t*() {
        return m_pvalue.get();
    }



    std::shared_ptr<oc_array_t> m_pvalue;
};

class OCStringArrayIterator : public Napi::ObjectWrap<OCStringArrayIterator>
{
public:
    OCStringArrayIterator(const Napi::CallbackInfo&);
    virtual ~OCStringArrayIterator();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_string_array_iterator_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_value(const Napi::CallbackInfo&);
    void set_value(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_done(const Napi::CallbackInfo&);
    void set_done(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_next(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_string_array_iterator_t> m_pvalue;
};

class OCEndpointIterator : public Napi::ObjectWrap<OCEndpointIterator>
{
public:
    OCEndpointIterator(const Napi::CallbackInfo&);
    virtual ~OCEndpointIterator();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_endpoint_iterator_t*() {
        return m_pvalue.get();
    }
    Napi::Value get_value(const Napi::CallbackInfo&);
    void set_value(const Napi::CallbackInfo&, const Napi::Value&);
    Napi::Value get_done(const Napi::CallbackInfo&);
    void set_done(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value get_next(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_endpoint_iterator_t> m_pvalue;
};

class OCStringArray : public Napi::ObjectWrap<OCStringArray>
{
public:
    OCStringArray(const Napi::CallbackInfo&);
    virtual ~OCStringArray();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_string_array_t*() {
        return m_pvalue.get();
    }

    Napi::Value get_iterator(const Napi::CallbackInfo& info);


    std::shared_ptr<oc_string_array_t> m_pvalue;
};

class OCCborEncoder : public Napi::ObjectWrap<OCCborEncoder>
{
public:
    OCCborEncoder(const Napi::CallbackInfo&);
    virtual ~OCCborEncoder();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator CborEncoder*() {
        return m_pvalue.get();
    }



    std::shared_ptr<CborEncoder> m_pvalue;
};









class OCAceConnectionType : public Napi::ObjectWrap<OCAceConnectionType>
{
public:
    OCAceConnectionType(const Napi::CallbackInfo&);
    virtual ~OCAceConnectionType();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ace_connection_type_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_CONN_AUTH_CRYPT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CONN_ANON_CLEAR(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_ace_connection_type_t> m_pvalue;
};

class OCAcePermissionsMask : public Napi::ObjectWrap<OCAcePermissionsMask>
{
public:
    OCAcePermissionsMask(const Napi::CallbackInfo&);
    virtual ~OCAcePermissionsMask();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ace_permissions_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_PERM_NONE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PERM_CREATE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PERM_RETRIEVE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PERM_UPDATE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PERM_DELETE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PERM_NOTIFY(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_ace_permissions_t> m_pvalue;
};

class OCAceSubjectType : public Napi::ObjectWrap<OCAceSubjectType>
{
public:
    OCAceSubjectType(const Napi::CallbackInfo&);
    virtual ~OCAceSubjectType();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ace_subject_type_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_SUBJECT_UUID(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SUBJECT_ROLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SUBJECT_CONN(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_ace_subject_type_t> m_pvalue;
};

class OCAceWildcard : public Napi::ObjectWrap<OCAceWildcard>
{
public:
    OCAceWildcard(const Napi::CallbackInfo&);
    virtual ~OCAceWildcard();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_ace_wildcard_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_ACE_NO_WC(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ACE_WC_ALL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ACE_WC_ALL_SECURED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ACE_WC_ALL_PUBLIC(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_ace_wildcard_t> m_pvalue;
};

class OCBlockwiseRole : public Napi::ObjectWrap<OCBlockwiseRole>
{
public:
    OCBlockwiseRole(const Napi::CallbackInfo&);
    virtual ~OCBlockwiseRole();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_blockwise_role_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_BLOCKWISE_CLIENT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_BLOCKWISE_SERVER(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_blockwise_role_t> m_pvalue;
};

class OCDiscoveryFlags : public Napi::ObjectWrap<OCDiscoveryFlags>
{
public:
    OCDiscoveryFlags(const Napi::CallbackInfo&);
    virtual ~OCDiscoveryFlags();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_discovery_flags_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_STOP_DISCOVERY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CONTINUE_DISCOVERY(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_discovery_flags_t> m_pvalue;
};

class OCQos : public Napi::ObjectWrap<OCQos>
{
public:
    OCQos(const Napi::CallbackInfo&);
    virtual ~OCQos();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_qos_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_HIGH_QOS(const Napi::CallbackInfo&);
    static Napi::Value get_LOW_QOS(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_qos_t> m_pvalue;
};

class OCCloudError : public Napi::ObjectWrap<OCCloudError>
{
public:
    OCCloudError(const Napi::CallbackInfo&);
    virtual ~OCCloudError();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_cloud_error_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_CLOUD_OK(const Napi::CallbackInfo&);
    static Napi::Value get_CLOUD_ERROR_RESPONSE(const Napi::CallbackInfo&);
    static Napi::Value get_CLOUD_ERROR_CONNECT(const Napi::CallbackInfo&);
    static Napi::Value get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_cloud_error_t> m_pvalue;
};

class OCCloudStatusMask : public Napi::ObjectWrap<OCCloudStatusMask>
{
public:
    OCCloudStatusMask(const Napi::CallbackInfo&);
    virtual ~OCCloudStatusMask();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_cloud_status_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_REGISTERED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_FAILURE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_cloud_status_t> m_pvalue;
};

class OCCloudPrivisoningStatus : public Napi::ObjectWrap<OCCloudPrivisoningStatus>
{
public:
    OCCloudPrivisoningStatus(const Napi::CallbackInfo&);
    virtual ~OCCloudPrivisoningStatus();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_cps_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CPS_REGISTERING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CPS_REGISTERED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CPS_FAILED(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_cps_t> m_pvalue;
};

#if defined(OC_TCP)
class tcpCsmState : public Napi::ObjectWrap<tcpCsmState>
{
public:
    tcpCsmState(const Napi::CallbackInfo&);
    virtual ~tcpCsmState();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator tcp_csm_state_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_CSM_NONE(const Napi::CallbackInfo&);
    static Napi::Value get_CSM_SENT(const Napi::CallbackInfo&);
    static Napi::Value get_CSM_DONE(const Napi::CallbackInfo&);
    static Napi::Value get_CSM_ERROR(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<tcp_csm_state_t> m_pvalue;
};
#endif

class OCCredType : public Napi::ObjectWrap<OCCredType>
{
public:
    OCCredType(const Napi::CallbackInfo&);
    virtual ~OCCredType();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_credtype_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_CREDTYPE_NULL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDTYPE_PSK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDTYPE_CERT(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_sec_credtype_t> m_pvalue;
};

class OCCredUsage : public Napi::ObjectWrap<OCCredUsage>
{
public:
    OCCredUsage(const Napi::CallbackInfo&);
    virtual ~OCCredUsage();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_credusage_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_CREDUSAGE_NULL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo&);
    static Napi::Value get_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_sec_credusage_t> m_pvalue;
};

class OCEncoding : public Napi::ObjectWrap<OCEncoding>
{
public:
    OCEncoding(const Napi::CallbackInfo&);
    virtual ~OCEncoding();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sec_encoding_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENCODING_BASE64(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENCODING_RAW(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENCODING_PEM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENCODING_HANDLE(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_sec_encoding_t> m_pvalue;
};

class OCFVersion : public Napi::ObjectWrap<OCFVersion>
{
public:
    OCFVersion(const Napi::CallbackInfo&);
    virtual ~OCFVersion();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator ocf_version_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OCF_VER_1_0_0(const Napi::CallbackInfo&);
    static Napi::Value get_OIC_VER_1_1_0(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<ocf_version_t> m_pvalue;
};

class OCTransportFlags : public Napi::ObjectWrap<OCTransportFlags>
{
public:
    OCTransportFlags(const Napi::CallbackInfo&);
    virtual ~OCTransportFlags();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator transport_flags*() {
        return m_pvalue.get();
    }
    static Napi::Value get_DISCOVERY(const Napi::CallbackInfo&);
    static Napi::Value get_SECURED(const Napi::CallbackInfo&);
    static Napi::Value get_IPV4(const Napi::CallbackInfo&);
    static Napi::Value get_IPV6(const Napi::CallbackInfo&);
    static Napi::Value get_TCP(const Napi::CallbackInfo&);
    static Napi::Value get_GATT(const Napi::CallbackInfo&);
    static Napi::Value get_MULTICAST(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<transport_flags> m_pvalue;
};

class OCEnum : public Napi::ObjectWrap<OCEnum>
{
public:
    OCEnum(const Napi::CallbackInfo&);
    virtual ~OCEnum();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_enum_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_ENUM_ABORTED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ACTIVE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_AIRDRY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ARMEDAWAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ARMEDINSTANT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ARMEDMAXIMUM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ARMEDNIGHTSTAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ARMEDSTAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_AROMA(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_AI(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_AUTO(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_BOILING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_BREWING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_CANCELLED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_CIRCULATING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_CLEANING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_CLOTHES(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_COMPLETED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_COOL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_DELICATE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_DISABLED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_DOWN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_DUAL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_DRY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ENABLED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_EXTENDED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_FAN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_FAST(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_FILTERMATERIAL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_FOCUSED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_GRINDING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_HEATING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_HEAVY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_IDLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_INK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_INKBLACK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_INKCYAN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_INKMAGENTA(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_INKTRICOLOUR(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_INKYELLOW(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_KEEPWARM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_NORMAL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_NOTSUPPORTED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PAUSE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PENDING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PENDINGHELD(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PERMAPRESS(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PREWASH(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PROCESSING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_PURE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_QUICK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_QUIET(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_RINSE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_SECTORED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_SILENT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_SLEEP(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_SMART(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_SPOT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_STEAM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_STOPPED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_SPIN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_TESTING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_TONER(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_TONERBLACK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_TONERCYAN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_TONERMAGENTA(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_TONERYELLOW(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_WARM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_WASH(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_WET(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_WIND(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_WRINKLEPREVENT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_ENUM_ZIGZAG(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_enum_t> m_pvalue;
};

class OCPositionDescription : public Napi::ObjectWrap<OCPositionDescription>
{
public:
    OCPositionDescription(const Napi::CallbackInfo&);
    virtual ~OCPositionDescription();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_pos_description_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_POS_UNKNOWN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_TOP(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_BOTTOM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_LEFT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_RIGHT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_CENTRE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_TOPLEFT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_CENTRELEFT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_CENTRERIGHT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_TOPRIGHT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_TOPCENTRE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_pos_description_t> m_pvalue;
};


class OCInterfaceEvent : public Napi::ObjectWrap<OCInterfaceEvent>
{
public:
    OCInterfaceEvent(const Napi::CallbackInfo&);
    virtual ~OCInterfaceEvent();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_interface_event_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_NETWORK_INTERFACE_DOWN(const Napi::CallbackInfo&);
    static Napi::Value get_NETWORK_INTERFACE_UP(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_interface_event_t> m_pvalue;
};

class OCSpTypesMask : public Napi::ObjectWrap<OCSpTypesMask>
{
public:
    OCSpTypesMask(const Napi::CallbackInfo&);
    virtual ~OCSpTypesMask();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_sp_types_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_SP_BASELINE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SP_BLACK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SP_BLUE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SP_PURPLE(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_sp_types_t> m_pvalue;
};

class OCRepValueType : public Napi::ObjectWrap<OCRepValueType>
{
public:
    OCRepValueType(const Napi::CallbackInfo&);
    virtual ~OCRepValueType();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_rep_value_type_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_REP_NIL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_INT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_DOUBLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_BOOL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_BYTE_STRING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_STRING(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_OBJECT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_ARRAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_INT_ARRAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_DOUBLE_ARRAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_BOOL_ARRAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_BYTE_STRING_ARRAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_STRING_ARRAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_REP_OBJECT_ARRAY(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_rep_value_type_t> m_pvalue;
};

class OCContentFormat : public Napi::ObjectWrap<OCContentFormat>
{
public:
    OCContentFormat(const Napi::CallbackInfo&);
    virtual ~OCContentFormat();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_content_format_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_TEXT_PLAIN(const Napi::CallbackInfo&);
    static Napi::Value get_TEXT_XML(const Napi::CallbackInfo&);
    static Napi::Value get_TEXT_CSV(const Napi::CallbackInfo&);
    static Napi::Value get_TEXT_HTML(const Napi::CallbackInfo&);
    static Napi::Value get_IMAGE_GIF(const Napi::CallbackInfo&);
    static Napi::Value get_IMAGE_JPEG(const Napi::CallbackInfo&);
    static Napi::Value get_IMAGE_PNG(const Napi::CallbackInfo&);
    static Napi::Value get_IMAGE_TIFF(const Napi::CallbackInfo&);
    static Napi::Value get_AUDIO_RAW(const Napi::CallbackInfo&);
    static Napi::Value get_VIDEO_RAW(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_LINK_FORMAT(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_XML(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_OCTET_STREAM(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_RDF_XML(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_SOAP_XML(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_ATOM_XML(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_XMPP_XML(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_EXI(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_FASTINFOSET(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_SOAP_FASTINFOSET(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_JSON(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_X_OBIX_BINARY(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_CBOR(const Napi::CallbackInfo&);
    static Napi::Value get_APPLICATION_VND_OCF_CBOR(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_content_format_t> m_pvalue;
};

class OCCoreResource : public Napi::ObjectWrap<OCCoreResource>
{
public:
    OCCoreResource(const Napi::CallbackInfo&);
    virtual ~OCCoreResource();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_core_resource_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OCF_P(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_CON(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_INTROSPECTION_WK(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_INTROSPECTION_DATA(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_RES(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_MNT(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_COAPCLOUDCONF(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SW_UPDATE(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_DOXM(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_PSTAT(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_ACL(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_AEL(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_CRED(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_SDI(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_SP(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_CSR(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_SEC_ROLES(const Napi::CallbackInfo&);
    static Napi::Value get_OCF_D(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_core_resource_t> m_pvalue;
};

class OCEventCallbackResult : public Napi::ObjectWrap<OCEventCallbackResult>
{
public:
    OCEventCallbackResult(const Napi::CallbackInfo&);
    virtual ~OCEventCallbackResult();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_event_callback_retval_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_EVENT_DONE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_EVENT_CONTINUE(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_event_callback_retval_t> m_pvalue;
};

class OCInterfaceMask : public Napi::ObjectWrap<OCInterfaceMask>
{
public:
    OCInterfaceMask(const Napi::CallbackInfo&);
    virtual ~OCInterfaceMask();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_interface_mask_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_IF_BASELINE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_LL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_B(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_R(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_RW(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_A(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_S(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IF_CREATE(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_interface_mask_t> m_pvalue;
};

class OCMethod : public Napi::ObjectWrap<OCMethod>
{
public:
    OCMethod(const Napi::CallbackInfo&);
    virtual ~OCMethod();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_method_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_GET(const Napi::CallbackInfo&);
    static Napi::Value get_OC_POST(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PUT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_DELETE(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_method_t> m_pvalue;
};

class OCResourcePropertiesMask : public Napi::ObjectWrap<OCResourcePropertiesMask>
{
public:
    OCResourcePropertiesMask(const Napi::CallbackInfo&);
    virtual ~OCResourcePropertiesMask();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_resource_properties_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_DISCOVERABLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_OBSERVABLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SECURE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PERIODIC(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_resource_properties_t> m_pvalue;
};

class OCStatus : public Napi::ObjectWrap<OCStatus>
{
public:
    OCStatus(const Napi::CallbackInfo&);
    virtual ~OCStatus();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_status_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_STATUS_OK(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_CREATED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_CHANGED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_DELETED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_NOT_MODIFIED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_BAD_REQUEST(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_UNAUTHORIZED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_BAD_OPTION(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_FORBIDDEN(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_NOT_FOUND(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_METHOD_NOT_ALLOWED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_NOT_ACCEPTABLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_INTERNAL_SERVER_ERROR(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_NOT_IMPLEMENTED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_BAD_GATEWAY(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_SERVICE_UNAVAILABLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_GATEWAY_TIMEOUT(const Napi::CallbackInfo&);
    static Napi::Value get_OC_STATUS_PROXYING_NOT_SUPPORTED(const Napi::CallbackInfo&);
    static Napi::Value get___NUM_OC_STATUS_CODES__(const Napi::CallbackInfo&);
    static Napi::Value get_OC_IGNORE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_PING_TIMEOUT(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_status_t> m_pvalue;
};

class OCSessionState : public Napi::ObjectWrap<OCSessionState>
{
public:
    OCSessionState(const Napi::CallbackInfo&);
    virtual ~OCSessionState();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_session_state_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_SESSION_CONNECTED(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SESSION_DISCONNECTED(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_session_state_t> m_pvalue;
};

class OCSoftwareUpdateResult : public Napi::ObjectWrap<OCSoftwareUpdateResult>
{
public:
    OCSoftwareUpdateResult(const Napi::CallbackInfo&);
    virtual ~OCSoftwareUpdateResult();
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    operator oc_swupdate_result_t*() {
        return m_pvalue.get();
    }
    static Napi::Value get_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo&);
    static Napi::Value get_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo&);


    /* apis */
    std::shared_ptr<oc_swupdate_result_t> m_pvalue;
};

