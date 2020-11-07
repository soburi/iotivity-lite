#include "structs.h"
#include "functions.h"
Napi::Object module_init(Napi::Env env, Napi::Object exports) {
  exports.Set("coapObserver", coapObserver::GetClass(env));
  exports.Set("coapPacket", coapPacket::GetClass(env));
  exports.Set("coapSeparate", coapSeparate::GetClass(env));
  exports.Set("coapTransaction", coapTransaction::GetClass(env));
  exports.Set("OCAceResource", OCAceResource::GetClass(env));
  exports.Set("OCBlockwiseRequestState", OCBlockwiseRequestState::GetClass(env));
  exports.Set("OCBlockwiseResponseState", OCBlockwiseResponseState::GetClass(env));
  exports.Set("OCBlockwiseState", OCBlockwiseState::GetClass(env));
  exports.Set("OCClientCallback", OCClientCallback::GetClass(env));
  exports.Set("OCClientHandler", OCClientHandler::GetClass(env));
  exports.Set("OCClientResponse", OCClientResponse::GetClass(env));
  exports.Set("OCCloudContext", OCCloudContext::GetClass(env));
  exports.Set("OCCloudStore", OCCloudStore::GetClass(env));
  exports.Set("OCCollection", OCCollection::GetClass(env));
  exports.Set("OCCredData", OCCredData::GetClass(env));
  exports.Set("OCDeviceInfo", OCDeviceInfo::GetClass(env));
  exports.Set("OCEndpoint", OCEndpoint::GetClass(env));
  exports.Set("OCEtimer", OCEtimer::GetClass(env));
  exports.Set("OCEventCallback", OCEventCallback::GetClass(env));
  exports.Set("OCHandler", OCHandler::GetClass(env));
  exports.Set("OCIPv4Addr", OCIPv4Addr::GetClass(env));
  exports.Set("OCIPv6Addr", OCIPv6Addr::GetClass(env));
  exports.Set("OCLEAddr", OCLEAddr::GetClass(env));
  exports.Set("OCLinkParams", OCLinkParams::GetClass(env));
  exports.Set("OCLink", OCLink::GetClass(env));
  exports.Set("OCMemb", OCMemb::GetClass(env));
  exports.Set("OCMessage", OCMessage::GetClass(env));
  exports.Set("OCMmem", OCMmem::GetClass(env));
  exports.Set("OCNetworkInterfaceCb", OCNetworkInterfaceCb::GetClass(env));
  exports.Set("OCPlatformInfo", OCPlatformInfo::GetClass(env));
  exports.Set("OCProcess", OCProcess::GetClass(env));
  exports.Set("OCPropertiesCb", OCPropertiesCb::GetClass(env));
  exports.Set("OCRepresentation", OCRepresentation::GetClass(env));
  exports.Set("OCRequestHandler", OCRequestHandler::GetClass(env));
  exports.Set("OCRequest", OCRequest::GetClass(env));
  exports.Set("OCResource", OCResource::GetClass(env));
  exports.Set("OCResponseBuffer", OCResponseBuffer::GetClass(env));
  exports.Set("OCResponse", OCResponse::GetClass(env));
  exports.Set("OCRole", OCRole::GetClass(env));
  exports.Set("OCResourceType", OCResourceType::GetClass(env));
  exports.Set("OCSecurityAce", OCSecurityAce::GetClass(env));
  exports.Set("OCSecurityAcl", OCSecurityAcl::GetClass(env));
  exports.Set("OCCreds", OCCreds::GetClass(env));
  exports.Set("OCCred", OCCred::GetClass(env));
  exports.Set("OCSeparateResponse", OCSeparateResponse::GetClass(env));
  exports.Set("OCSessionEventCb", OCSessionEventCb::GetClass(env));
  exports.Set("OCSoftwareUpdateHandler", OCSoftwareUpdateHandler::GetClass(env));
  exports.Set("OCTimer", OCTimer::GetClass(env));
  exports.Set("OCUuid", OCUuid::GetClass(env));
  exports.Set("OCAceSubject", OCAceSubject::GetClass(env));
  exports.Set("DevAddr", DevAddr::GetClass(env));
  exports.Set("OCValue", OCValue::GetClass(env));
  exports.Set("OCArray", OCArray::GetClass(env));
  exports.Set("OCStringArrayIterator", OCStringArrayIterator::GetClass(env));
  exports.Set("OCStringArray", OCStringArray::GetClass(env));
  exports.Set("OCCborEncoder", OCCborEncoder::GetClass(env));
  exports.Set("coapTransportType", coapTransportType::GetClass(env));
  exports.Set("coapSignalCode", coapSignalCode::GetClass(env));
  exports.Set("coapSignalOption", coapSignalOption::GetClass(env));
  exports.Set("coapMessageType", coapMessageType::GetClass(env));
  exports.Set("coapMethod", coapMethod::GetClass(env));
  exports.Set("coapOption", coapOption::GetClass(env));
  exports.Set("coapStatus", coapStatus::GetClass(env));
  exports.Set("OCAceConnectionType", OCAceConnectionType::GetClass(env));
  exports.Set("OCAcePermissionsMask", OCAcePermissionsMask::GetClass(env));
  exports.Set("OCAceSubjectType", OCAceSubjectType::GetClass(env));
  exports.Set("OCAceWildcard", OCAceWildcard::GetClass(env));
  exports.Set("OCBlockwiseRole", OCBlockwiseRole::GetClass(env));
  exports.Set("OCDiscoveryFlags", OCDiscoveryFlags::GetClass(env));
  exports.Set("OCQos", OCQos::GetClass(env));
  exports.Set("OCCloudError", OCCloudError::GetClass(env));
  exports.Set("OCCloudStatusMask", OCCloudStatusMask::GetClass(env));
  exports.Set("OCCloudPrivisoningStatus", OCCloudPrivisoningStatus::GetClass(env));
#if defined(OC_TCP)
  exports.Set("tcpCsmState", tcpCsmState::GetClass(env));
#endif
  exports.Set("OCCredType", OCCredType::GetClass(env));
  exports.Set("OCCredUsage", OCCredUsage::GetClass(env));
  exports.Set("OCEncoding", OCEncoding::GetClass(env));
  exports.Set("OCFVersion", OCFVersion::GetClass(env));
  exports.Set("OCTransportFlags", OCTransportFlags::GetClass(env));
  exports.Set("OCEnum", OCEnum::GetClass(env));
  exports.Set("OCPositionDescription", OCPositionDescription::GetClass(env));
  exports.Set("OCInterfaceEvent", OCInterfaceEvent::GetClass(env));
  exports.Set("OCSpTypesMask", OCSpTypesMask::GetClass(env));
  exports.Set("OCRepValueType", OCRepValueType::GetClass(env));
  exports.Set("OCContentFormat", OCContentFormat::GetClass(env));
  exports.Set("OCCoreResource", OCCoreResource::GetClass(env));
  exports.Set("OCEventCallbackResult", OCEventCallbackResult::GetClass(env));
  exports.Set("OCInterfaceMask", OCInterfaceMask::GetClass(env));
  exports.Set("OCMethod", OCMethod::GetClass(env));
  exports.Set("OCResourcePropertiesMask", OCResourcePropertiesMask::GetClass(env));
  exports.Set("OCStatus", OCStatus::GetClass(env));
  exports.Set("OCSessionState", OCSessionState::GetClass(env));
  exports.Set("OCSoftwareUpdateResult", OCSoftwareUpdateResult::GetClass(env));
  exports.Set("handle_coap_signal_message", Napi::Function::New(env, N_handle_coap_signal_message));
#if defined(OC_COLLECTIONS_IF_CREATE)
  exports.Set("oc_collections_add_rt_factory", Napi::Function::New(env, N_oc_collections_add_rt_factory));
#endif
  exports.Set("oc_set_immutable_device_identifier", Napi::Function::New(env, N_oc_set_immutable_device_identifier));
  exports.Set("oc_get_diagnostic_message", Napi::Function::New(env, N_oc_get_diagnostic_message));
  exports.Set("oc_get_query_value", Napi::Function::New(env, N_oc_get_query_value));
  exports.Set("oc_get_request_payload_raw", Napi::Function::New(env, N_oc_get_request_payload_raw));
  exports.Set("oc_get_response_payload_raw", Napi::Function::New(env, N_oc_get_response_payload_raw));
  exports.Set("oc_init_query_iterator", Napi::Function::New(env, N_oc_init_query_iterator));
  exports.Set("oc_iterate_query", Napi::Function::New(env, N_oc_iterate_query));
  exports.Set("oc_iterate_query_get_values", Napi::Function::New(env, N_oc_iterate_query_get_values));
  exports.Set("oc_resource_tag_func_desc", Napi::Function::New(env, N_oc_resource_tag_func_desc));
  exports.Set("oc_resource_tag_pos_desc", Napi::Function::New(env, N_oc_resource_tag_pos_desc));
  exports.Set("oc_resource_tag_pos_rel", Napi::Function::New(env, N_oc_resource_tag_pos_rel));
  exports.Set("oc_timer_expired", Napi::Function::New(env, N_oc_timer_expired));
  exports.Set("oc_timer_remaining", Napi::Function::New(env, N_oc_timer_remaining));
  exports.Set("oc_timer_reset", Napi::Function::New(env, N_oc_timer_reset));
  exports.Set("oc_timer_restart", Napi::Function::New(env, N_oc_timer_restart));
  exports.Set("oc_timer_set", Napi::Function::New(env, N_oc_timer_set));
  exports.Set("oc_main_poll", Napi::Function::New(env, N_oc_main_poll));
  exports.Set("abort_impl", Napi::Function::New(env, N_abort_impl));
  exports.Set("exit_impl", Napi::Function::New(env, N_exit_impl));
  exports.Set("oc_abort", Napi::Function::New(env, N_oc_abort));
  exports.Set("oc_exit", Napi::Function::New(env, N_oc_exit));
  exports.Set("oc_base64_decode", Napi::Function::New(env, N_oc_base64_decode));
  exports.Set("oc_base64_encode", Napi::Function::New(env, N_oc_base64_encode));
  exports.Set("oc_blockwise_alloc_request_buffer", Napi::Function::New(env, N_oc_blockwise_alloc_request_buffer));
  exports.Set("oc_blockwise_alloc_response_buffer", Napi::Function::New(env, N_oc_blockwise_alloc_response_buffer));
#if defined(XXX)
  exports.Set("oc_blockwise_dispatch_block", Napi::Function::New(env, N_oc_blockwise_dispatch_block));
#endif
  exports.Set("oc_blockwise_find_request_buffer", Napi::Function::New(env, N_oc_blockwise_find_request_buffer));
  exports.Set("oc_blockwise_find_request_buffer_by_client_cb", Napi::Function::New(env, N_oc_blockwise_find_request_buffer_by_client_cb));
  exports.Set("oc_blockwise_find_request_buffer_by_mid", Napi::Function::New(env, N_oc_blockwise_find_request_buffer_by_mid));
  exports.Set("oc_blockwise_find_request_buffer_by_token", Napi::Function::New(env, N_oc_blockwise_find_request_buffer_by_token));
  exports.Set("oc_blockwise_find_response_buffer", Napi::Function::New(env, N_oc_blockwise_find_response_buffer));
  exports.Set("oc_blockwise_find_response_buffer_by_client_cb", Napi::Function::New(env, N_oc_blockwise_find_response_buffer_by_client_cb));
  exports.Set("oc_blockwise_find_response_buffer_by_mid", Napi::Function::New(env, N_oc_blockwise_find_response_buffer_by_mid));
  exports.Set("oc_blockwise_find_response_buffer_by_token", Napi::Function::New(env, N_oc_blockwise_find_response_buffer_by_token));
  exports.Set("oc_blockwise_free_request_buffer", Napi::Function::New(env, N_oc_blockwise_free_request_buffer));
  exports.Set("oc_blockwise_free_response_buffer", Napi::Function::New(env, N_oc_blockwise_free_response_buffer));
  exports.Set("oc_blockwise_handle_block", Napi::Function::New(env, N_oc_blockwise_handle_block));
  exports.Set("oc_blockwise_scrub_buffers", Napi::Function::New(env, N_oc_blockwise_scrub_buffers));
  exports.Set("oc_blockwise_scrub_buffers_for_client_cb", Napi::Function::New(env, N_oc_blockwise_scrub_buffers_for_client_cb));
  exports.Set("oc_allocate_message", Napi::Function::New(env, N_oc_allocate_message));
  exports.Set("oc_allocate_message_from_pool", Napi::Function::New(env, N_oc_allocate_message_from_pool));
#if defined(OC_SECURITY)
  exports.Set("oc_close_all_tls_sessions", Napi::Function::New(env, N_oc_close_all_tls_sessions));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_close_all_tls_sessions_for_device", Napi::Function::New(env, N_oc_close_all_tls_sessions_for_device));
#endif
  exports.Set("oc_internal_allocate_outgoing_message", Napi::Function::New(env, N_oc_internal_allocate_outgoing_message));
  exports.Set("oc_message_add_ref", Napi::Function::New(env, N_oc_message_add_ref));
  exports.Set("oc_message_unref", Napi::Function::New(env, N_oc_message_unref));
  exports.Set("oc_recv_message", Napi::Function::New(env, N_oc_recv_message));
  exports.Set("oc_send_message", Napi::Function::New(env, N_oc_send_message));
  exports.Set("oc_set_buffers_avail_cb", Napi::Function::New(env, N_oc_set_buffers_avail_cb));
  exports.Set("oc_ri_alloc_client_cb", Napi::Function::New(env, N_oc_ri_alloc_client_cb));
  exports.Set("oc_ri_find_client_cb_by_mid", Napi::Function::New(env, N_oc_ri_find_client_cb_by_mid));
  exports.Set("oc_ri_find_client_cb_by_token", Napi::Function::New(env, N_oc_ri_find_client_cb_by_token));
  exports.Set("oc_ri_free_client_cbs_by_endpoint", Napi::Function::New(env, N_oc_ri_free_client_cbs_by_endpoint));
  exports.Set("oc_ri_free_client_cbs_by_mid", Napi::Function::New(env, N_oc_ri_free_client_cbs_by_mid));
  exports.Set("oc_ri_get_client_cb", Napi::Function::New(env, N_oc_ri_get_client_cb));
  exports.Set("oc_ri_invoke_client_cb", Napi::Function::New(env, N_oc_ri_invoke_client_cb));
  exports.Set("oc_ri_is_client_cb_valid", Napi::Function::New(env, N_oc_ri_is_client_cb_valid));
  exports.Set("oc_ri_process_discovery_payload", Napi::Function::New(env, N_oc_ri_process_discovery_payload));
  exports.Set("oc_clock_encode_time_rfc3339", Napi::Function::New(env, N_oc_clock_encode_time_rfc3339));
  exports.Set("oc_clock_parse_time_rfc3339", Napi::Function::New(env, N_oc_clock_parse_time_rfc3339));
  exports.Set("oc_clock_time_rfc3339", Napi::Function::New(env, N_oc_clock_time_rfc3339));
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_deregister", Napi::Function::New(env, N_oc_cloud_deregister));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_register", Napi::Function::New(env, N_oc_cloud_register));
#endif
  exports.Set("oc_check_if_collection", Napi::Function::New(env, N_oc_check_if_collection));
  exports.Set("oc_collection_add", Napi::Function::New(env, N_oc_collection_add));
  exports.Set("oc_collection_alloc", Napi::Function::New(env, N_oc_collection_alloc));
  exports.Set("oc_collection_free", Napi::Function::New(env, N_oc_collection_free));
  exports.Set("oc_collection_get_all", Napi::Function::New(env, N_oc_collection_get_all));
#if defined(OC_COLLECTIONS_IF_CREATE)
  exports.Set("oc_collections_free_rt_factories", Napi::Function::New(env, N_oc_collections_free_rt_factories));
#endif
  exports.Set("oc_get_collection_by_uri", Napi::Function::New(env, N_oc_get_collection_by_uri));
  exports.Set("oc_get_link_by_uri", Napi::Function::New(env, N_oc_get_link_by_uri));
  exports.Set("oc_get_next_collection_with_link", Napi::Function::New(env, N_oc_get_next_collection_with_link));
  exports.Set("oc_handle_collection_request", Napi::Function::New(env, N_oc_handle_collection_request));
  exports.Set("oc_link_set_interfaces", Napi::Function::New(env, N_oc_link_set_interfaces));
  exports.Set("handle_network_interface_event_callback", Napi::Function::New(env, N_handle_network_interface_event_callback));
  exports.Set("handle_session_event_callback", Napi::Function::New(env, N_handle_session_event_callback));
#if defined(OC_TCP)
  exports.Set("oc_connectivity_end_session", Napi::Function::New(env, N_oc_connectivity_end_session));
#endif
  exports.Set("oc_connectivity_get_endpoints", Napi::Function::New(env, N_oc_connectivity_get_endpoints));
  exports.Set("oc_connectivity_init", Napi::Function::New(env, N_oc_connectivity_init));
  exports.Set("oc_connectivity_shutdown", Napi::Function::New(env, N_oc_connectivity_shutdown));
  exports.Set("oc_dns_lookup", Napi::Function::New(env, N_oc_dns_lookup));
  exports.Set("oc_send_buffer", Napi::Function::New(env, N_oc_send_buffer));
  exports.Set("oc_send_discovery_request", Napi::Function::New(env, N_oc_send_discovery_request));
#if defined(OC_TCP)
  exports.Set("oc_tcp_get_csm_state", Napi::Function::New(env, N_oc_tcp_get_csm_state));
#endif
#if defined(OC_TCP)
  exports.Set("oc_tcp_update_csm_state", Napi::Function::New(env, N_oc_tcp_update_csm_state));
#endif
  exports.Set("oc_core_encode_interfaces_mask", Napi::Function::New(env, N_oc_core_encode_interfaces_mask));
  exports.Set("oc_core_get_resource_by_index", Napi::Function::New(env, N_oc_core_get_resource_by_index));
  exports.Set("oc_core_populate_resource", Napi::Function::New(env, N_oc_core_populate_resource));
  exports.Set("oc_store_uri", Napi::Function::New(env, N_oc_store_uri));
  exports.Set("oc_create_discovery_resource", Napi::Function::New(env, N_oc_create_discovery_resource));
  exports.Set("oc_endpoint_list_copy", Napi::Function::New(env, N_oc_endpoint_list_copy));
  exports.Set("_oc_alloc_string", Napi::Function::New(env, N__oc_alloc_string));
  exports.Set("_oc_alloc_string_array", Napi::Function::New(env, N__oc_alloc_string_array));
  exports.Set("_oc_free_array", Napi::Function::New(env, N__oc_free_array));
  exports.Set("_oc_free_string", Napi::Function::New(env, N__oc_free_string));
  exports.Set("_oc_new_array", Napi::Function::New(env, N__oc_new_array));
  exports.Set("_oc_new_string", Napi::Function::New(env, N__oc_new_string));
  exports.Set("oc_concat_strings", Napi::Function::New(env, N_oc_concat_strings));
  exports.Set("oc_join_string_array", Napi::Function::New(env, N_oc_join_string_array));
  exports.Set("oc_memb_init", Napi::Function::New(env, N_oc_memb_init));
  exports.Set("oc_memb_inmemb", Napi::Function::New(env, N_oc_memb_inmemb));
  exports.Set("oc_memb_numfree", Napi::Function::New(env, N_oc_memb_numfree));
  exports.Set("oc_memb_set_buffers_avail_cb", Napi::Function::New(env, N_oc_memb_set_buffers_avail_cb));
#if defined(OC_MEMORY_TRACE)
  exports.Set("oc_mem_trace_add_pace", Napi::Function::New(env, N_oc_mem_trace_add_pace));
#endif
#if defined(OC_MEMORY_TRACE)
  exports.Set("oc_mem_trace_init", Napi::Function::New(env, N_oc_mem_trace_init));
#endif
#if defined(OC_MEMORY_TRACE)
  exports.Set("oc_mem_trace_shutdown", Napi::Function::New(env, N_oc_mem_trace_shutdown));
#endif
  exports.Set("_oc_mmem_alloc", Napi::Function::New(env, N__oc_mmem_alloc));
  exports.Set("_oc_mmem_free", Napi::Function::New(env, N__oc_mmem_free));
  exports.Set("oc_mmem_init", Napi::Function::New(env, N_oc_mmem_init));
  exports.Set("oc_network_event", Napi::Function::New(env, N_oc_network_event));
  exports.Set("oc_network_interface_event", Napi::Function::New(env, N_oc_network_interface_event));
  exports.Set("oc_network_event_handler_mutex_destroy", Napi::Function::New(env, N_oc_network_event_handler_mutex_destroy));
  exports.Set("oc_network_event_handler_mutex_init", Napi::Function::New(env, N_oc_network_event_handler_mutex_init));
  exports.Set("oc_network_event_handler_mutex_lock", Napi::Function::New(env, N_oc_network_event_handler_mutex_lock));
  exports.Set("oc_network_event_handler_mutex_unlock", Napi::Function::New(env, N_oc_network_event_handler_mutex_unlock));
  exports.Set("oc_add_network_interface_event_callback", Napi::Function::New(env, N_oc_add_network_interface_event_callback));
  exports.Set("oc_add_session_event_callback", Napi::Function::New(env, N_oc_add_session_event_callback));
  exports.Set("oc_remove_network_interface_event_callback", Napi::Function::New(env, N_oc_remove_network_interface_event_callback));
  exports.Set("oc_remove_session_event_callback", Napi::Function::New(env, N_oc_remove_session_event_callback));
  exports.Set("oc_free_rep", Napi::Function::New(env, N_oc_free_rep));
  exports.Set("oc_parse_rep", Napi::Function::New(env, N_oc_parse_rep));
  exports.Set("oc_rep_get_encoded_payload_size", Napi::Function::New(env, N_oc_rep_get_encoded_payload_size));
  exports.Set("oc_rep_get_encoder_buf", Napi::Function::New(env, N_oc_rep_get_encoder_buf));
  exports.Set("oc_rep_get_int", Napi::Function::New(env, N_oc_rep_get_int));
  exports.Set("oc_rep_get_int_array", Napi::Function::New(env, N_oc_rep_get_int_array));
  exports.Set("oc_rep_new", Napi::Function::New(env, N_oc_rep_new));
  exports.Set("oc_rep_set_pool", Napi::Function::New(env, N_oc_rep_set_pool));
#if defined(OC_SERVER)
  exports.Set("oc_ri_add_resource", Napi::Function::New(env, N_oc_ri_add_resource));
#endif
  exports.Set("oc_ri_add_timed_event_callback_ticks", Napi::Function::New(env, N_oc_ri_add_timed_event_callback_ticks));
#if defined(OC_SERVER)
  exports.Set("oc_ri_alloc_resource", Napi::Function::New(env, N_oc_ri_alloc_resource));
#endif
#if defined(OC_SERVER)
  exports.Set("oc_ri_delete_resource", Napi::Function::New(env, N_oc_ri_delete_resource));
#endif
  exports.Set("oc_ri_free_resource_properties", Napi::Function::New(env, N_oc_ri_free_resource_properties));
  exports.Set("oc_ri_get_app_resource_by_uri", Napi::Function::New(env, N_oc_ri_get_app_resource_by_uri));
  exports.Set("oc_ri_get_app_resources", Napi::Function::New(env, N_oc_ri_get_app_resources));
  exports.Set("oc_ri_get_interface_mask", Napi::Function::New(env, N_oc_ri_get_interface_mask));
  exports.Set("oc_ri_get_query_nth_key_value", Napi::Function::New(env, N_oc_ri_get_query_nth_key_value));
  exports.Set("oc_ri_get_query_value", Napi::Function::New(env, N_oc_ri_get_query_value));
  exports.Set("oc_ri_init", Napi::Function::New(env, N_oc_ri_init));
  exports.Set("oc_ri_remove_timed_event_callback", Napi::Function::New(env, N_oc_ri_remove_timed_event_callback));
  exports.Set("oc_ri_shutdown", Napi::Function::New(env, N_oc_ri_shutdown));
  exports.Set("oc_status_code", Napi::Function::New(env, N_oc_status_code));
  exports.Set("_oc_signal_event_loop", Napi::Function::New(env, N__oc_signal_event_loop));
  exports.Set("oc_storage_read", Napi::Function::New(env, N_oc_storage_read));
  exports.Set("oc_storage_write", Napi::Function::New(env, N_oc_storage_write));
  exports.Set("helper_rep_add_int", Napi::Function::New(env, N_helper_rep_add_int));
  exports.Set("helper_rep_set_array", Napi::Function::New(env, N_helper_rep_set_array));
  exports.Set("helper_rep_get_cbor_errno", Napi::Function::New(env, N_helper_rep_get_cbor_errno));
  exports.Set("helper_oc_do_ip_discovery", Napi::Function::New(env, N_helper_oc_do_ip_discovery));
  return exports;
}
