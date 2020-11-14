#include "functions.h"
#include "iotivity_lite.h"
#include "helper.h"
using namespace std;
using namespace Napi;
Value N_handle_coap_signal_message(const CallbackInfo& info) {
    void* packet = info[0];
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    return Number::New(info.Env(), handle_coap_signal_message(packet, endpoint));
}

Value N_handle_network_interface_event_callback(const CallbackInfo& info) {
    auto event = static_cast<oc_interface_event_t>(info[0].ToNumber().Uint32Value());
    (void)handle_network_interface_event_callback(event);
    return info.Env().Undefined();
}

Value N_handle_session_event_callback(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    auto state = static_cast<oc_session_state_t>(info[1].ToNumber().Uint32Value());
    (void)handle_session_event_callback(endpoint, state);
    return info.Env().Undefined();
}

Value N_oc_abort(const CallbackInfo& info) {
    auto msg_ = info[0].ToString().Utf8Value();
    auto msg = msg_.c_str();
    (void)oc_abort(msg);
    return info.Env().Undefined();
}

Value N_oc_allocate_message(const CallbackInfo& info) {
    shared_ptr<oc_message_t> sp(oc_allocate_message(), nop_deleter);
    auto args = External<shared_ptr<oc_message_t>>::New(info.Env(), &sp);
    return OCMessage::constructor.New({args});
}

Value N_oc_allocate_message_from_pool(const CallbackInfo& info) {
    auto& pool = *OCMemb::Unwrap(info[0].ToObject());
    shared_ptr<oc_message_t> sp(oc_allocate_message_from_pool(pool), nop_deleter);
    auto args = External<shared_ptr<oc_message_t>>::New(info.Env(), &sp);
    return OCMessage::constructor.New({args});
}

Value N_oc_check_if_collection(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    return Boolean::New(info.Env(), oc_check_if_collection(resource));
}

#if defined(OC_SECURITY)
Value N_oc_close_all_tls_sessions(const CallbackInfo& info) {
    (void)oc_close_all_tls_sessions();
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value N_oc_close_all_tls_sessions_for_device(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    (void)oc_close_all_tls_sessions_for_device(device);
    return info.Env().Undefined();
}
#endif

#if defined(OC_COLLECTIONS_IF_CREATE)
Value N_oc_collections_add_rt_factory(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
// 1 get_instance, oc_resource_get_instance_t
// 2 free_instance, oc_resource_free_instance_t
    return Boolean::New(info.Env(), 0);
}
#endif

#if defined(OC_COLLECTIONS_IF_CREATE)
Value N_oc_collections_free_rt_factories(const CallbackInfo& info) {
    (void)oc_collections_free_rt_factories();
    return info.Env().Undefined();
}
#endif

Value N_oc_concat_strings(const CallbackInfo& info) {
    auto& concat = *OCMmem::Unwrap(info[0].ToObject());
    auto str1_ = info[1].ToString().Utf8Value();
    auto str1 = str1_.c_str();
    auto str2_ = info[2].ToString().Utf8Value();
    auto str2 = str2_.c_str();
    (void)oc_concat_strings(concat, str1, str2);
    return info.Env().Undefined();
}

#if defined(OC_TCP)
Value N_oc_connectivity_end_session(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    (void)oc_connectivity_end_session(endpoint);
    return info.Env().Undefined();
}
#endif

Value N_oc_connectivity_get_endpoints(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    shared_ptr<oc_endpoint_t> sp(oc_connectivity_get_endpoints(device), nop_deleter);
    auto args = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({args});
}

Value N_oc_connectivity_init(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_connectivity_init(device));
}

Value N_oc_connectivity_shutdown(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    (void)oc_connectivity_shutdown(device);
    return info.Env().Undefined();
}

Value N_oc_create_discovery_resource(const CallbackInfo& info) {
    auto resource_idx = static_cast<int>(info[0].ToNumber());
    auto device = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    (void)oc_create_discovery_resource(resource_idx, device);
    return info.Env().Undefined();
}

Value N_oc_dns_lookup(const CallbackInfo& info) {
    auto domain_ = info[0].ToString().Utf8Value();
    auto domain = domain_.c_str();
    auto& addr = *OCMmem::Unwrap(info[1].ToObject());
    auto flags = static_cast<enum transport_flags>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_dns_lookup(domain, addr, flags));
}

Value N_oc_exit(const CallbackInfo& info) {
    auto status = static_cast<int>(info[0].ToNumber());
    (void)oc_exit(status);
    return info.Env().Undefined();
}

Value N_oc_get_collection_by_uri(const CallbackInfo& info) {
    auto uri_path_ = info[0].ToString().Utf8Value();
    auto uri_path = uri_path_.c_str();
    auto uri_path_len = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    auto device = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    shared_ptr<oc_collection_t> sp(oc_get_collection_by_uri(uri_path, uri_path_len, device), nop_deleter);
    auto args = External<shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({args});
}

Value N_oc_get_diagnostic_message(const CallbackInfo& info) {
    auto& response = *OCClientResponse::Unwrap(info[0].ToObject());
// 1 msg, const char**
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
    return Boolean::New(info.Env(), 0);
}

Value N_oc_get_link_by_uri(const CallbackInfo& info) {
    auto& collection = *OCCollection::Unwrap(info[0].ToObject());
    auto uri_path_ = info[1].ToString().Utf8Value();
    auto uri_path = uri_path_.c_str();
    auto uri_path_len = static_cast<int>(info[2].ToNumber());
    shared_ptr<oc_link_t> sp(oc_get_link_by_uri(collection, uri_path, uri_path_len), nop_deleter);
    auto args = External<shared_ptr<oc_link_t>>::New(info.Env(), &sp);
    return OCLink::constructor.New({args});
}

Value N_oc_get_next_collection_with_link(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    auto& start = *OCCollection::Unwrap(info[1].ToObject());
    shared_ptr<oc_collection_t> sp(oc_get_next_collection_with_link(resource, start), nop_deleter);
    auto args = External<shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({args});
}

Value N_oc_get_query_value(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 value, char**
    return Number::New(info.Env(), 0);
}

Value N_oc_get_request_payload_raw(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
// 1 payload, const uint8_t**
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
// 3 content_format, oc_content_format_t*
    return Boolean::New(info.Env(), 0);
}

Value N_oc_get_response_payload_raw(const CallbackInfo& info) {
    auto& response = *OCClientResponse::Unwrap(info[0].ToObject());
// 1 payload, const uint8_t**
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
// 3 content_format, oc_content_format_t*
    return Boolean::New(info.Env(), 0);
}

Value N_oc_handle_collection_request(const CallbackInfo& info) {
    auto method = static_cast<oc_method_t>(info[0].ToNumber().Uint32Value());
    auto& request = *OCRequest::Unwrap(info[1].ToObject());
    auto iface_mask = static_cast<oc_interface_mask_t>(info[2].ToNumber().Uint32Value());
    auto& notify_resource = *OCResource::Unwrap(info[3].ToObject());
    return Boolean::New(info.Env(), oc_handle_collection_request(method, request, iface_mask, notify_resource));
}

Value N_oc_init_query_iterator(const CallbackInfo& info) {
    (void)oc_init_query_iterator();
    return info.Env().Undefined();
}

Value N_oc_internal_allocate_outgoing_message(const CallbackInfo& info) {
    shared_ptr<oc_message_t> sp(oc_internal_allocate_outgoing_message(), nop_deleter);
    auto args = External<shared_ptr<oc_message_t>>::New(info.Env(), &sp);
    return OCMessage::constructor.New({args});
}

Value N_oc_iterate_query(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
// 1 key, char**
    auto key_len = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
// 3 value, char**
    auto value_len = reinterpret_cast<size_t*>(info[4].As<Uint32Array>().Data());
    return Number::New(info.Env(), 0);
}

Value N_oc_iterate_query_get_values(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 value, char**
// 3 value_len, int*
    return Boolean::New(info.Env(), 0);
}

Value N_oc_join_string_array(const CallbackInfo& info) {
    auto& ocstringarray = *OCStringArray::Unwrap(info[0].ToObject());
    auto& ocstring = *OCMmem::Unwrap(info[1].ToObject());
    (void)oc_join_string_array(ocstringarray, ocstring);
    return info.Env().Undefined();
}

Value N_oc_link_set_interfaces(const CallbackInfo& info) {
    auto& link = *OCLink::Unwrap(info[0].ToObject());
    auto new_interfaces = static_cast<oc_interface_mask_t>(info[1].ToNumber().Uint32Value());
    (void)oc_link_set_interfaces(link, new_interfaces);
    return info.Env().Undefined();
}

#if defined(OC_MEMORY_TRACE)
Value N_oc_mem_trace_add_pace(const CallbackInfo& info) {
    auto func_ = info[0].ToString().Utf8Value();
    auto func = func_.c_str();
    auto size = static_cast<int>(info[1].ToNumber());
    auto type = static_cast<int>(info[2].ToNumber());
    void* address = info[3];
    (void)oc_mem_trace_add_pace(func, size, type, address);
    return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Value N_oc_mem_trace_init(const CallbackInfo& info) {
    (void)oc_mem_trace_init();
    return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Value N_oc_mem_trace_shutdown(const CallbackInfo& info) {
    (void)oc_mem_trace_shutdown();
    return info.Env().Undefined();
}
#endif

Value N_oc_memb_init(const CallbackInfo& info) {
    auto& m = *OCMemb::Unwrap(info[0].ToObject());
    (void)oc_memb_init(m);
    return info.Env().Undefined();
}

Value N_oc_memb_inmemb(const CallbackInfo& info) {
    auto& m = *OCMemb::Unwrap(info[0].ToObject());
    void* ptr = info[1];
    return Number::New(info.Env(), oc_memb_inmemb(m, ptr));
}

Value N_oc_memb_numfree(const CallbackInfo& info) {
    auto& m = *OCMemb::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_memb_numfree(m));
}

Value N_oc_memb_set_buffers_avail_cb(const CallbackInfo& info) {
    auto& m = *OCMemb::Unwrap(info[0].ToObject());
    oc_memb_buffers_avail_callback_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    (void)oc_memb_set_buffers_avail_cb(m, cb);
    return info.Env().Undefined();
}

Value N_oc_message_add_ref(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    (void)oc_message_add_ref(message);
    return info.Env().Undefined();
}

Value N_oc_message_unref(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    (void)oc_message_unref(message);
    return info.Env().Undefined();
}

Value N_oc_mmem_init(const CallbackInfo& info) {
    (void)oc_mmem_init();
    return info.Env().Undefined();
}

Value N_oc_network_event(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    (void)oc_network_event(message);
    return info.Env().Undefined();
}

Value N_oc_network_event_handler_mutex_destroy(const CallbackInfo& info) {
    (void)oc_network_event_handler_mutex_destroy();
    return info.Env().Undefined();
}

Value N_oc_network_event_handler_mutex_init(const CallbackInfo& info) {
    (void)oc_network_event_handler_mutex_init();
    return info.Env().Undefined();
}

Value N_oc_network_event_handler_mutex_lock(const CallbackInfo& info) {
    (void)oc_network_event_handler_mutex_lock();
    return info.Env().Undefined();
}

Value N_oc_network_event_handler_mutex_unlock(const CallbackInfo& info) {
    (void)oc_network_event_handler_mutex_unlock();
    return info.Env().Undefined();
}

Value N_oc_network_interface_event(const CallbackInfo& info) {
    auto event = static_cast<oc_interface_event_t>(info[0].ToNumber().Uint32Value());
    (void)oc_network_interface_event(event);
    return info.Env().Undefined();
}

Value N_oc_recv_message(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    (void)oc_recv_message(message);
    return info.Env().Undefined();
}

Value N_oc_send_buffer(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_send_buffer(message));
}

Value N_oc_send_discovery_request(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    (void)oc_send_discovery_request(message);
    return info.Env().Undefined();
}

Value N_oc_send_message(const CallbackInfo& info) {
    auto& message = *OCMessage::Unwrap(info[0].ToObject());
    (void)oc_send_message(message);
    return info.Env().Undefined();
}

Value N_oc_set_buffers_avail_cb(const CallbackInfo& info) {
    oc_memb_buffers_avail_callback_t cb = nullptr;
    Function cb_ = info[0].As<Function>();
    (void)oc_set_buffers_avail_cb(cb);
    return info.Env().Undefined();
}

Value N_oc_set_immutable_device_identifier(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto& piid = *OCUuid::Unwrap(info[1].ToObject());
    (void)oc_set_immutable_device_identifier(device, piid);
    return info.Env().Undefined();
}

Value N_oc_status_code(const CallbackInfo& info) {
    auto key = static_cast<oc_status_t>(info[0].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_status_code(key));
}

Value N_oc_store_uri(const CallbackInfo& info) {
    auto s_uri_ = info[0].ToString().Utf8Value();
    auto s_uri = s_uri_.c_str();
    auto& d_uri = *OCMmem::Unwrap(info[1].ToObject());
    (void)oc_store_uri(s_uri, d_uri);
    return info.Env().Undefined();
}

