#include "helper.h"
Napi::Value N_handle_coap_signal_message(const Napi::CallbackInfo&);
Napi::Value N_handle_network_interface_event_callback(const Napi::CallbackInfo&);
Napi::Value N_handle_session_event_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_abort(const Napi::CallbackInfo&);
Napi::Value N_oc_allocate_message(const Napi::CallbackInfo&);
Napi::Value N_oc_allocate_message_from_pool(const Napi::CallbackInfo&);
Napi::Value N_oc_base64_decode(const Napi::CallbackInfo&);
Napi::Value N_oc_base64_encode(const Napi::CallbackInfo&);
Napi::Value N_oc_check_if_collection(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_encode_time_rfc3339(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_parse_time_rfc3339(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_time_rfc3339(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions_for_device(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_collection_add(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_alloc(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_free(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_get_all(const Napi::CallbackInfo&);
#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_add_rt_factory(const Napi::CallbackInfo&);
#endif
#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_free_rt_factories(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_concat_strings(const Napi::CallbackInfo&);
#if defined(OC_TCP)
Napi::Value N_oc_connectivity_end_session(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_connectivity_get_endpoints(const Napi::CallbackInfo&);
Napi::Value N_oc_connectivity_init(const Napi::CallbackInfo&);
Napi::Value N_oc_connectivity_shutdown(const Napi::CallbackInfo&);
Napi::Value N_oc_core_encode_interfaces_mask(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_resource_by_index(const Napi::CallbackInfo&);
Napi::Value N_oc_core_populate_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_create_discovery_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_dns_lookup(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_list_copy(const Napi::CallbackInfo&);
Napi::Value N_oc_exit(const Napi::CallbackInfo&);
Napi::Value N_oc_free_rep(const Napi::CallbackInfo&);
Napi::Value N_oc_get_collection_by_uri(const Napi::CallbackInfo&);
Napi::Value N_oc_get_diagnostic_message(const Napi::CallbackInfo&);
Napi::Value N_oc_get_link_by_uri(const Napi::CallbackInfo&);
Napi::Value N_oc_get_next_collection_with_link(const Napi::CallbackInfo&);
Napi::Value N_oc_get_query_value(const Napi::CallbackInfo&);
Napi::Value N_oc_get_request_payload_raw(const Napi::CallbackInfo&);
Napi::Value N_oc_get_response_payload_raw(const Napi::CallbackInfo&);
Napi::Value N_oc_handle_collection_request(const Napi::CallbackInfo&);
Napi::Value N_oc_init_query_iterator(const Napi::CallbackInfo&);
Napi::Value N_oc_internal_allocate_outgoing_message(const Napi::CallbackInfo&);
Napi::Value N_oc_iterate_query(const Napi::CallbackInfo&);
Napi::Value N_oc_iterate_query_get_values(const Napi::CallbackInfo&);
Napi::Value N_oc_join_string_array(const Napi::CallbackInfo&);
Napi::Value N_oc_link_set_interfaces(const Napi::CallbackInfo&);
Napi::Value N_oc_main_poll(const Napi::CallbackInfo&);
#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_add_pace(const Napi::CallbackInfo&);
#endif
#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_init(const Napi::CallbackInfo&);
#endif
#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_shutdown(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_memb_init(const Napi::CallbackInfo&);
Napi::Value N_oc_memb_inmemb(const Napi::CallbackInfo&);
Napi::Value N_oc_memb_numfree(const Napi::CallbackInfo&);
Napi::Value N_oc_memb_set_buffers_avail_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_message_add_ref(const Napi::CallbackInfo&);
Napi::Value N_oc_message_unref(const Napi::CallbackInfo&);
Napi::Value N_oc_mmem_init(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_destroy(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_init(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_lock(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_unlock(const Napi::CallbackInfo&);
Napi::Value N_oc_network_interface_event(const Napi::CallbackInfo&);
Napi::Value N_oc_parse_rep(const Napi::CallbackInfo&);
Napi::Value N_oc_recv_message(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_encoded_payload_size(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_encoder_buf(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_int(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_int_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_new(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_set_pool(const Napi::CallbackInfo&);
Napi::Value N_oc_send_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_send_discovery_request(const Napi::CallbackInfo&);
Napi::Value N_oc_send_message(const Napi::CallbackInfo&);
Napi::Value N_oc_set_buffers_avail_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_set_immutable_device_identifier(const Napi::CallbackInfo&);
Napi::Value N_oc_status_code(const Napi::CallbackInfo&);
Napi::Value N_oc_store_uri(const Napi::CallbackInfo&);
