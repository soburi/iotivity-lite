#include "structs.h"
#include "functions.h"
using namespace std;
using namespace Napi;
Napi::Object module_init(Napi::Env env, Napi::Object exports) {
  exports.Set("CborEncoder", OCCborEncoder::GetClass(env));
  exports.Set("AceResource", OCAceResource::GetClass(env));
  exports.Set("AceSubject", OCAceSubject::GetClass(env));
  exports.Set("Array", OCArray::GetClass(env));
  exports.Set("BlockwiseRequestState", OCBlockwiseRequestState::GetClass(env));
  exports.Set("BlockwiseResponseState", OCBlockwiseResponseState::GetClass(env));
  exports.Set("BlockwiseState", OCBlockwiseState::GetClass(env));
  exports.Set("ClientCallback", OCClientCallback::GetClass(env));
  exports.Set("ClientHandler", OCClientHandler::GetClass(env));
  exports.Set("ClientResponse", OCClientResponse::GetClass(env));
  exports.Set("CloudContext", OCCloudContext::GetClass(env));
  exports.Set("CloudStore", OCCloudStore::GetClass(env));
  exports.Set("Collection", OCCollection::GetClass(env));
  exports.Set("CredData", OCCredData::GetClass(env));
  exports.Set("DeviceInfo", OCDeviceInfo::GetClass(env));
  exports.Set("Endpoint", OCEndpoint::GetClass(env));
  exports.Set("DevAddr", DevAddr::GetClass(env));
  exports.Set("Etimer", OCEtimer::GetClass(env));
  exports.Set("EventCallback", OCEventCallback::GetClass(env));
  exports.Set("Handler", OCHandler::GetClass(env));
  exports.Set("IPv4Addr", OCIPv4Addr::GetClass(env));
  exports.Set("IPv6Addr", OCIPv6Addr::GetClass(env));
  exports.Set("LEAddr", OCLEAddr::GetClass(env));
  exports.Set("LinkParams", OCLinkParams::GetClass(env));
  exports.Set("Link", OCLink::GetClass(env));
  exports.Set("Memb", OCMemb::GetClass(env));
  exports.Set("Message", OCMessage::GetClass(env));
  exports.Set("Mmem", OCMmem::GetClass(env));
  exports.Set("NetworkInterfaceCb", OCNetworkInterfaceCb::GetClass(env));
  exports.Set("PlatformInfo", OCPlatformInfo::GetClass(env));
  exports.Set("Process", OCProcess::GetClass(env));
  exports.Set("PropertiesCb", OCPropertiesCb::GetClass(env));
  exports.Set("Representation", OCRepresentation::GetClass(env));
  exports.Set("Value", OCValue::GetClass(env));
  exports.Set("RequestHandler", OCRequestHandler::GetClass(env));
  exports.Set("Request", OCRequest::GetClass(env));
  exports.Set("Resource", OCResource::GetClass(env));
  exports.Set("ResponseBuffer", OCResponseBuffer::GetClass(env));
  exports.Set("Response", OCResponse::GetClass(env));
  exports.Set("Role", OCRole::GetClass(env));
  exports.Set("ResourceType", OCResourceType::GetClass(env));
  exports.Set("SecurityAce", OCSecurityAce::GetClass(env));
  exports.Set("SecurityAcl", OCSecurityAcl::GetClass(env));
  exports.Set("Cred", OCCred::GetClass(env));
  exports.Set("Creds", OCCreds::GetClass(env));
  exports.Set("SeparateResponse", OCSeparateResponse::GetClass(env));
  exports.Set("SessionEventCb", OCSessionEventCb::GetClass(env));
  exports.Set("StringArrayIterator", OCStringArrayIterator::GetClass(env));
  exports.Set("StringArray", OCStringArray::GetClass(env));
  exports.Set("SoftwareUpdateHandler", OCSoftwareUpdateHandler::GetClass(env));
  exports.Set("Timer", OCTimer::GetClass(env));
  exports.Set("Uuid", OCUuid::GetClass(env));
  exports.Set("AceConnectionType", OCAceConnectionType::GetClass(env));
  exports.Set("AcePermissionsMask", OCAcePermissionsMask::GetClass(env));
  exports.Set("AceSubjectType", OCAceSubjectType::GetClass(env));
  exports.Set("AceWildcard", OCAceWildcard::GetClass(env));
  exports.Set("BlockwiseRole", OCBlockwiseRole::GetClass(env));
  exports.Set("CloudError", OCCloudError::GetClass(env));
  exports.Set("CloudStatusMask", OCCloudStatusMask::GetClass(env));
  exports.Set("ContentFormat", OCContentFormat::GetClass(env));
  exports.Set("CoreResource", OCCoreResource::GetClass(env));
  exports.Set("CloudPrivisoningStatus", OCCloudPrivisoningStatus::GetClass(env));
  exports.Set("DiscoveryFlags", OCDiscoveryFlags::GetClass(env));
  exports.Set("Enum", OCEnum::GetClass(env));
  exports.Set("EventCallbackResult", OCEventCallbackResult::GetClass(env));
  exports.Set("InterfaceEvent", OCInterfaceEvent::GetClass(env));
  exports.Set("InterfaceMask", OCInterfaceMask::GetClass(env));
  exports.Set("Method", OCMethod::GetClass(env));
  exports.Set("PositionDescription", OCPositionDescription::GetClass(env));
  exports.Set("Qos", OCQos::GetClass(env));
  exports.Set("RepValueType", OCRepValueType::GetClass(env));
  exports.Set("ResourcePropertiesMask", OCResourcePropertiesMask::GetClass(env));
  exports.Set("CredType", OCCredType::GetClass(env));
  exports.Set("CredUsage", OCCredUsage::GetClass(env));
  exports.Set("Encoding", OCEncoding::GetClass(env));
  exports.Set("SessionState", OCSessionState::GetClass(env));
  exports.Set("SpTypesMask", OCSpTypesMask::GetClass(env));
  exports.Set("Status", OCStatus::GetClass(env));
  exports.Set("SoftwareUpdateResult", OCSoftwareUpdateResult::GetClass(env));
  exports.Set("FVersion", OCFVersion::GetClass(env));
#if defined(OC_TCP)
  exports.Set("tcpCsmState", tcpCsmState::GetClass(env));
#endif
  exports.Set("TransportFlags", OCTransportFlags::GetClass(env));
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
  exports.Set("oc_resource_set_default_interface", Napi::Function::New(env, N_oc_resource_set_default_interface));
  exports.Set("oc_main_poll", Napi::Function::New(env, N_oc_main_poll));
  exports.Set("oc_abort", Napi::Function::New(env, N_oc_abort));
  exports.Set("oc_exit", Napi::Function::New(env, N_oc_exit));
  exports.Set("oc_base64_decode", Napi::Function::New(env, N_oc_base64_decode));
  exports.Set("oc_base64_encode", Napi::Function::New(env, N_oc_base64_encode));
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
  exports.Set("oc_clock_encode_time_rfc3339", Napi::Function::New(env, N_oc_clock_encode_time_rfc3339));
  exports.Set("oc_clock_parse_time_rfc3339", Napi::Function::New(env, N_oc_clock_parse_time_rfc3339));
  exports.Set("oc_clock_time_rfc3339", Napi::Function::New(env, N_oc_clock_time_rfc3339));
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
  exports.Set("oc_core_encode_interfaces_mask", Napi::Function::New(env, N_oc_core_encode_interfaces_mask));
  exports.Set("oc_core_get_resource_by_index", Napi::Function::New(env, N_oc_core_get_resource_by_index));
  exports.Set("oc_core_populate_resource", Napi::Function::New(env, N_oc_core_populate_resource));
  exports.Set("oc_store_uri", Napi::Function::New(env, N_oc_store_uri));
  exports.Set("oc_create_discovery_resource", Napi::Function::New(env, N_oc_create_discovery_resource));
  exports.Set("oc_endpoint_list_copy", Napi::Function::New(env, N_oc_endpoint_list_copy));
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
  exports.Set("oc_mmem_init", Napi::Function::New(env, N_oc_mmem_init));
  exports.Set("oc_network_event", Napi::Function::New(env, N_oc_network_event));
  exports.Set("oc_network_interface_event", Napi::Function::New(env, N_oc_network_interface_event));
  exports.Set("oc_network_event_handler_mutex_destroy", Napi::Function::New(env, N_oc_network_event_handler_mutex_destroy));
  exports.Set("oc_network_event_handler_mutex_init", Napi::Function::New(env, N_oc_network_event_handler_mutex_init));
  exports.Set("oc_network_event_handler_mutex_lock", Napi::Function::New(env, N_oc_network_event_handler_mutex_lock));
  exports.Set("oc_network_event_handler_mutex_unlock", Napi::Function::New(env, N_oc_network_event_handler_mutex_unlock));
  exports.Set("oc_free_rep", Napi::Function::New(env, N_oc_free_rep));
  exports.Set("oc_rep_new", Napi::Function::New(env, N_oc_rep_new));
  exports.Set("oc_status_code", Napi::Function::New(env, N_oc_status_code));
  return exports;
}
