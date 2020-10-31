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
  exports.Set("coap_get_header_accept", Napi::Function::New(env, N_coap_get_header_accept));
  exports.Set("coap_get_header_block1", Napi::Function::New(env, N_coap_get_header_block1));
  exports.Set("coap_get_header_block2", Napi::Function::New(env, N_coap_get_header_block2));
  exports.Set("coap_get_header_content_format", Napi::Function::New(env, N_coap_get_header_content_format));
  exports.Set("coap_get_header_etag", Napi::Function::New(env, N_coap_get_header_etag));
  exports.Set("coap_get_header_if_match", Napi::Function::New(env, N_coap_get_header_if_match));
#if 0
  exports.Set("coap_get_header_if_none_match", Napi::Function::New(env, N_coap_get_header_if_none_match));
#endif
  exports.Set("coap_get_header_location_path", Napi::Function::New(env, N_coap_get_header_location_path));
  exports.Set("coap_get_header_location_query", Napi::Function::New(env, N_coap_get_header_location_query));
  exports.Set("coap_get_header_max_age", Napi::Function::New(env, N_coap_get_header_max_age));
  exports.Set("coap_get_header_observe", Napi::Function::New(env, N_coap_get_header_observe));
  exports.Set("coap_get_header_proxy_scheme", Napi::Function::New(env, N_coap_get_header_proxy_scheme));
  exports.Set("coap_get_header_proxy_uri", Napi::Function::New(env, N_coap_get_header_proxy_uri));
  exports.Set("coap_get_header_size1", Napi::Function::New(env, N_coap_get_header_size1));
  exports.Set("coap_get_header_size2", Napi::Function::New(env, N_coap_get_header_size2));
  exports.Set("coap_get_header_uri_host", Napi::Function::New(env, N_coap_get_header_uri_host));
  exports.Set("coap_get_header_uri_path", Napi::Function::New(env, N_coap_get_header_uri_path));
  exports.Set("coap_get_header_uri_query", Napi::Function::New(env, N_coap_get_header_uri_query));
  exports.Set("coap_get_mid", Napi::Function::New(env, N_coap_get_mid));
  exports.Set("coap_get_payload", Napi::Function::New(env, N_coap_get_payload));
  exports.Set("coap_get_post_variable", Napi::Function::New(env, N_coap_get_post_variable));
  exports.Set("coap_get_query_variable", Napi::Function::New(env, N_coap_get_query_variable));
  exports.Set("coap_init_connection", Napi::Function::New(env, N_coap_init_connection));
  exports.Set("coap_send_message", Napi::Function::New(env, N_coap_send_message));
  exports.Set("coap_serialize_message", Napi::Function::New(env, N_coap_serialize_message));
  exports.Set("coap_set_header_accept", Napi::Function::New(env, N_coap_set_header_accept));
  exports.Set("coap_set_header_block1", Napi::Function::New(env, N_coap_set_header_block1));
  exports.Set("coap_set_header_block2", Napi::Function::New(env, N_coap_set_header_block2));
  exports.Set("coap_set_header_content_format", Napi::Function::New(env, N_coap_set_header_content_format));
  exports.Set("coap_set_header_etag", Napi::Function::New(env, N_coap_set_header_etag));
#if 0
  exports.Set("coap_set_header_if_match", Napi::Function::New(env, N_coap_set_header_if_match));
#endif
#if 0
  exports.Set("coap_set_header_if_none_match", Napi::Function::New(env, N_coap_set_header_if_none_match));
#endif
#if 0
  exports.Set("coap_set_header_location_path", Napi::Function::New(env, N_coap_set_header_location_path));
#endif
  exports.Set("coap_set_header_location_query", Napi::Function::New(env, N_coap_set_header_location_query));
  exports.Set("coap_set_header_max_age", Napi::Function::New(env, N_coap_set_header_max_age));
  exports.Set("coap_set_header_observe", Napi::Function::New(env, N_coap_set_header_observe));
#if 0
  exports.Set("coap_set_header_proxy_scheme", Napi::Function::New(env, N_coap_set_header_proxy_scheme));
#endif
#if 0
  exports.Set("coap_set_header_proxy_uri", Napi::Function::New(env, N_coap_set_header_proxy_uri));
#endif
  exports.Set("coap_set_header_size1", Napi::Function::New(env, N_coap_set_header_size1));
  exports.Set("coap_set_header_size2", Napi::Function::New(env, N_coap_set_header_size2));
#if 0
  exports.Set("coap_set_header_uri_host", Napi::Function::New(env, N_coap_set_header_uri_host));
#endif
  exports.Set("coap_set_header_uri_path", Napi::Function::New(env, N_coap_set_header_uri_path));
  exports.Set("coap_set_header_uri_query", Napi::Function::New(env, N_coap_set_header_uri_query));
  exports.Set("coap_set_payload", Napi::Function::New(env, N_coap_set_payload));
  exports.Set("coap_set_status_code", Napi::Function::New(env, N_coap_set_status_code));
  exports.Set("coap_set_token", Napi::Function::New(env, N_coap_set_token));
  exports.Set("coap_tcp_get_packet_size", Napi::Function::New(env, N_coap_tcp_get_packet_size));
  exports.Set("coap_tcp_init_message", Napi::Function::New(env, N_coap_tcp_init_message));
  exports.Set("coap_tcp_parse_message", Napi::Function::New(env, N_coap_tcp_parse_message));
  exports.Set("coap_udp_init_message", Napi::Function::New(env, N_coap_udp_init_message));
  exports.Set("coap_udp_parse_message", Napi::Function::New(env, N_coap_udp_parse_message));
  exports.Set("coap_check_signal_message", Napi::Function::New(env, N_coap_check_signal_message));
  exports.Set("coap_send_abort_message", Napi::Function::New(env, N_coap_send_abort_message));
  exports.Set("coap_send_csm_message", Napi::Function::New(env, N_coap_send_csm_message));
  exports.Set("coap_send_ping_message", Napi::Function::New(env, N_coap_send_ping_message));
  exports.Set("coap_send_pong_message", Napi::Function::New(env, N_coap_send_pong_message));
  exports.Set("coap_send_release_message", Napi::Function::New(env, N_coap_send_release_message));
  exports.Set("coap_signal_get_alt_addr", Napi::Function::New(env, N_coap_signal_get_alt_addr));
  exports.Set("coap_signal_get_bad_csm", Napi::Function::New(env, N_coap_signal_get_bad_csm));
  exports.Set("coap_signal_get_blockwise_transfer", Napi::Function::New(env, N_coap_signal_get_blockwise_transfer));
  exports.Set("coap_signal_get_custody", Napi::Function::New(env, N_coap_signal_get_custody));
  exports.Set("coap_signal_get_hold_off", Napi::Function::New(env, N_coap_signal_get_hold_off));
  exports.Set("coap_signal_get_max_msg_size", Napi::Function::New(env, N_coap_signal_get_max_msg_size));
  exports.Set("coap_signal_set_alt_addr", Napi::Function::New(env, N_coap_signal_set_alt_addr));
  exports.Set("coap_signal_set_bad_csm", Napi::Function::New(env, N_coap_signal_set_bad_csm));
  exports.Set("coap_signal_set_blockwise_transfer", Napi::Function::New(env, N_coap_signal_set_blockwise_transfer));
  exports.Set("coap_signal_set_custody", Napi::Function::New(env, N_coap_signal_set_custody));
  exports.Set("coap_signal_set_hold_off", Napi::Function::New(env, N_coap_signal_set_hold_off));
  exports.Set("coap_signal_set_max_msg_size", Napi::Function::New(env, N_coap_signal_set_max_msg_size));
  exports.Set("handle_coap_signal_message", Napi::Function::New(env, N_handle_coap_signal_message));
  exports.Set("coap_init_engine", Napi::Function::New(env, N_coap_init_engine));
  exports.Set("coap_receive", Napi::Function::New(env, N_coap_receive));
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_assert_all_roles", Napi::Function::New(env, N_oc_assert_all_roles));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_assert_role", Napi::Function::New(env, N_oc_assert_role));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_auto_assert_roles", Napi::Function::New(env, N_oc_auto_assert_roles));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_get_all_roles", Napi::Function::New(env, N_oc_get_all_roles));
#endif
  exports.Set("oc_close_session", Napi::Function::New(env, N_oc_close_session));
  exports.Set("oc_do_delete", Napi::Function::New(env, N_oc_do_delete));
  exports.Set("oc_do_get", Napi::Function::New(env, N_oc_do_get));
  exports.Set("oc_do_ip_discovery", Napi::Function::New(env, N_oc_do_ip_discovery));
  exports.Set("oc_do_ip_discovery_all", Napi::Function::New(env, N_oc_do_ip_discovery_all));
  exports.Set("oc_do_ip_discovery_all_at_endpoint", Napi::Function::New(env, N_oc_do_ip_discovery_all_at_endpoint));
  exports.Set("oc_do_ip_discovery_at_endpoint", Napi::Function::New(env, N_oc_do_ip_discovery_at_endpoint));
  exports.Set("oc_do_ip_multicast", Napi::Function::New(env, N_oc_do_ip_multicast));
  exports.Set("oc_do_observe", Napi::Function::New(env, N_oc_do_observe));
  exports.Set("oc_do_post", Napi::Function::New(env, N_oc_do_post));
  exports.Set("oc_do_put", Napi::Function::New(env, N_oc_do_put));
  exports.Set("oc_do_realm_local_ipv6_discovery", Napi::Function::New(env, N_oc_do_realm_local_ipv6_discovery));
  exports.Set("oc_do_realm_local_ipv6_discovery_all", Napi::Function::New(env, N_oc_do_realm_local_ipv6_discovery_all));
  exports.Set("oc_do_realm_local_ipv6_multicast", Napi::Function::New(env, N_oc_do_realm_local_ipv6_multicast));
  exports.Set("oc_do_site_local_ipv6_discovery", Napi::Function::New(env, N_oc_do_site_local_ipv6_discovery));
  exports.Set("oc_do_site_local_ipv6_discovery_all", Napi::Function::New(env, N_oc_do_site_local_ipv6_discovery_all));
  exports.Set("oc_do_site_local_ipv6_multicast", Napi::Function::New(env, N_oc_do_site_local_ipv6_multicast));
  exports.Set("oc_free_server_endpoints", Napi::Function::New(env, N_oc_free_server_endpoints));
  exports.Set("oc_init_post", Napi::Function::New(env, N_oc_init_post));
  exports.Set("oc_init_put", Napi::Function::New(env, N_oc_init_put));
#if defined(OC_TCP)
  exports.Set("oc_send_ping", Napi::Function::New(env, N_oc_send_ping));
#endif
  exports.Set("oc_stop_multicast", Napi::Function::New(env, N_oc_stop_multicast));
  exports.Set("oc_stop_observe", Napi::Function::New(env, N_oc_stop_observe));
  exports.Set("oc_add_collection", Napi::Function::New(env, N_oc_add_collection));
  exports.Set("oc_collection_add_link", Napi::Function::New(env, N_oc_collection_add_link));
  exports.Set("oc_collection_add_mandatory_rt", Napi::Function::New(env, N_oc_collection_add_mandatory_rt));
  exports.Set("oc_collection_add_supported_rt", Napi::Function::New(env, N_oc_collection_add_supported_rt));
  exports.Set("oc_collection_get_collections", Napi::Function::New(env, N_oc_collection_get_collections));
  exports.Set("oc_collection_get_links", Napi::Function::New(env, N_oc_collection_get_links));
  exports.Set("oc_collection_remove_link", Napi::Function::New(env, N_oc_collection_remove_link));
#if defined(OC_COLLECTIONS_IF_CREATE)
  exports.Set("oc_collections_add_rt_factory", Napi::Function::New(env, N_oc_collections_add_rt_factory));
#endif
  exports.Set("oc_delete_collection", Napi::Function::New(env, N_oc_delete_collection));
  exports.Set("oc_delete_link", Napi::Function::New(env, N_oc_delete_link));
  exports.Set("oc_link_add_link_param", Napi::Function::New(env, N_oc_link_add_link_param));
  exports.Set("oc_link_add_rel", Napi::Function::New(env, N_oc_link_add_rel));
  exports.Set("oc_new_collection", Napi::Function::New(env, N_oc_new_collection));
  exports.Set("oc_new_link", Napi::Function::New(env, N_oc_new_link));
  exports.Set("oc_remove_delayed_callback", Napi::Function::New(env, N_oc_remove_delayed_callback));
  exports.Set("oc_set_delayed_callback", Napi::Function::New(env, N_oc_set_delayed_callback));
  exports.Set("oc_set_immutable_device_identifier", Napi::Function::New(env, N_oc_set_immutable_device_identifier));
  exports.Set("oc_add_resource", Napi::Function::New(env, N_oc_add_resource));
  exports.Set("oc_delete_resource", Napi::Function::New(env, N_oc_delete_resource));
  exports.Set("oc_device_bind_resource_type", Napi::Function::New(env, N_oc_device_bind_resource_type));
  exports.Set("oc_get_diagnostic_message", Napi::Function::New(env, N_oc_get_diagnostic_message));
  exports.Set("oc_get_query_value", Napi::Function::New(env, N_oc_get_query_value));
  exports.Set("oc_get_request_payload_raw", Napi::Function::New(env, N_oc_get_request_payload_raw));
  exports.Set("oc_get_response_payload_raw", Napi::Function::New(env, N_oc_get_response_payload_raw));
  exports.Set("oc_ignore_request", Napi::Function::New(env, N_oc_ignore_request));
  exports.Set("oc_indicate_separate_response", Napi::Function::New(env, N_oc_indicate_separate_response));
  exports.Set("oc_init_query_iterator", Napi::Function::New(env, N_oc_init_query_iterator));
  exports.Set("oc_iterate_query", Napi::Function::New(env, N_oc_iterate_query));
  exports.Set("oc_iterate_query_get_values", Napi::Function::New(env, N_oc_iterate_query_get_values));
  exports.Set("oc_new_resource", Napi::Function::New(env, N_oc_new_resource));
  exports.Set("oc_notify_observers", Napi::Function::New(env, N_oc_notify_observers));
  exports.Set("oc_process_baseline_interface", Napi::Function::New(env, N_oc_process_baseline_interface));
  exports.Set("oc_resource_bind_resource_interface", Napi::Function::New(env, N_oc_resource_bind_resource_interface));
  exports.Set("oc_resource_bind_resource_type", Napi::Function::New(env, N_oc_resource_bind_resource_type));
#if defined(OC_SECURITY)
  exports.Set("oc_resource_make_public", Napi::Function::New(env, N_oc_resource_make_public));
#endif
  exports.Set("oc_resource_set_default_interface", Napi::Function::New(env, N_oc_resource_set_default_interface));
  exports.Set("oc_resource_set_discoverable", Napi::Function::New(env, N_oc_resource_set_discoverable));
  exports.Set("oc_resource_set_observable", Napi::Function::New(env, N_oc_resource_set_observable));
  exports.Set("oc_resource_set_periodic_observable", Napi::Function::New(env, N_oc_resource_set_periodic_observable));
  exports.Set("oc_resource_set_properties_cbs", Napi::Function::New(env, N_oc_resource_set_properties_cbs));
  exports.Set("oc_resource_set_request_handler", Napi::Function::New(env, N_oc_resource_set_request_handler));
  exports.Set("oc_resource_tag_func_desc", Napi::Function::New(env, N_oc_resource_tag_func_desc));
  exports.Set("oc_resource_tag_pos_desc", Napi::Function::New(env, N_oc_resource_tag_pos_desc));
  exports.Set("oc_resource_tag_pos_rel", Napi::Function::New(env, N_oc_resource_tag_pos_rel));
  exports.Set("oc_send_diagnostic_message", Napi::Function::New(env, N_oc_send_diagnostic_message));
  exports.Set("oc_send_response", Napi::Function::New(env, N_oc_send_response));
  exports.Set("oc_send_response_raw", Napi::Function::New(env, N_oc_send_response_raw));
  exports.Set("oc_send_separate_response", Napi::Function::New(env, N_oc_send_separate_response));
  exports.Set("oc_set_con_write_cb", Napi::Function::New(env, N_oc_set_con_write_cb));
  exports.Set("oc_set_separate_response_buffer", Napi::Function::New(env, N_oc_set_separate_response_buffer));
  exports.Set("oc_timer_expired", Napi::Function::New(env, N_oc_timer_expired));
  exports.Set("oc_timer_remaining", Napi::Function::New(env, N_oc_timer_remaining));
  exports.Set("oc_timer_reset", Napi::Function::New(env, N_oc_timer_reset));
  exports.Set("oc_timer_restart", Napi::Function::New(env, N_oc_timer_restart));
  exports.Set("oc_timer_set", Napi::Function::New(env, N_oc_timer_set));
  exports.Set("coap_free_all_observers", Napi::Function::New(env, N_coap_free_all_observers));
#if defined(XXX)
  exports.Set("coap_get_observers", Napi::Function::New(env, N_coap_get_observers));
#endif
  exports.Set("coap_notify_collection_baseline", Napi::Function::New(env, N_coap_notify_collection_baseline));
  exports.Set("coap_notify_collection_batch", Napi::Function::New(env, N_coap_notify_collection_batch));
  exports.Set("coap_notify_collection_links_list", Napi::Function::New(env, N_coap_notify_collection_links_list));
  exports.Set("coap_notify_collection_observers", Napi::Function::New(env, N_coap_notify_collection_observers));
  exports.Set("coap_notify_observers", Napi::Function::New(env, N_coap_notify_observers));
  exports.Set("coap_observe_handler", Napi::Function::New(env, N_coap_observe_handler));
  exports.Set("coap_remove_observer", Napi::Function::New(env, N_coap_remove_observer));
  exports.Set("coap_remove_observer_by_client", Napi::Function::New(env, N_coap_remove_observer_by_client));
  exports.Set("coap_remove_observer_by_mid", Napi::Function::New(env, N_coap_remove_observer_by_mid));
  exports.Set("coap_remove_observer_by_resource", Napi::Function::New(env, N_coap_remove_observer_by_resource));
  exports.Set("coap_remove_observer_by_token", Napi::Function::New(env, N_coap_remove_observer_by_token));
  exports.Set("coap_remove_observers_on_dos_change", Napi::Function::New(env, N_coap_remove_observers_on_dos_change));
  exports.Set("oc_add_device", Napi::Function::New(env, N_oc_add_device));
#if defined(OC_SECURITY)
  exports.Set("oc_add_ownership_status_cb", Napi::Function::New(env, N_oc_add_ownership_status_cb));
#endif
  exports.Set("oc_get_con_res_announced", Napi::Function::New(env, N_oc_get_con_res_announced));
  exports.Set("oc_init_platform", Napi::Function::New(env, N_oc_init_platform));
#if defined(OC_SECURITY)
  exports.Set("oc_is_owned_device", Napi::Function::New(env, N_oc_is_owned_device));
#endif
  exports.Set("oc_main_init", Napi::Function::New(env, N_oc_main_init));
  exports.Set("oc_main_poll", Napi::Function::New(env, N_oc_main_poll));
  exports.Set("oc_main_shutdown", Napi::Function::New(env, N_oc_main_shutdown));
#if defined(OC_SECURITY)
  exports.Set("oc_remove_ownership_status_cb", Napi::Function::New(env, N_oc_remove_ownership_status_cb));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_reset", Napi::Function::New(env, N_oc_reset));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_reset_device", Napi::Function::New(env, N_oc_reset_device));
#endif
  exports.Set("oc_set_con_res_announced", Napi::Function::New(env, N_oc_set_con_res_announced));
  exports.Set("oc_set_factory_presets_cb", Napi::Function::New(env, N_oc_set_factory_presets_cb));
#if defined(OC_SECURITY)
  exports.Set("oc_set_random_pin_callback", Napi::Function::New(env, N_oc_set_random_pin_callback));
#endif
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
  exports.Set("oc_get_block_size", Napi::Function::New(env, N_oc_get_block_size));
  exports.Set("oc_get_max_app_data_size", Napi::Function::New(env, N_oc_get_max_app_data_size));
  exports.Set("oc_get_mtu_size", Napi::Function::New(env, N_oc_get_mtu_size));
  exports.Set("oc_set_max_app_data_size", Napi::Function::New(env, N_oc_set_max_app_data_size));
  exports.Set("oc_set_mtu_size", Napi::Function::New(env, N_oc_set_mtu_size));
  exports.Set("oc_ri_alloc_client_cb", Napi::Function::New(env, N_oc_ri_alloc_client_cb));
  exports.Set("oc_ri_find_client_cb_by_mid", Napi::Function::New(env, N_oc_ri_find_client_cb_by_mid));
  exports.Set("oc_ri_find_client_cb_by_token", Napi::Function::New(env, N_oc_ri_find_client_cb_by_token));
  exports.Set("oc_ri_free_client_cbs_by_endpoint", Napi::Function::New(env, N_oc_ri_free_client_cbs_by_endpoint));
  exports.Set("oc_ri_free_client_cbs_by_mid", Napi::Function::New(env, N_oc_ri_free_client_cbs_by_mid));
  exports.Set("oc_ri_get_client_cb", Napi::Function::New(env, N_oc_ri_get_client_cb));
  exports.Set("oc_ri_invoke_client_cb", Napi::Function::New(env, N_oc_ri_invoke_client_cb));
  exports.Set("oc_ri_is_client_cb_valid", Napi::Function::New(env, N_oc_ri_is_client_cb_valid));
  exports.Set("oc_ri_process_discovery_payload", Napi::Function::New(env, N_oc_ri_process_discovery_payload));
  exports.Set("oc_clock_init", Napi::Function::New(env, N_oc_clock_init));
  exports.Set("oc_clock_seconds", Napi::Function::New(env, N_oc_clock_seconds));
  exports.Set("oc_clock_time", Napi::Function::New(env, N_oc_clock_time));
  exports.Set("oc_clock_wait", Napi::Function::New(env, N_oc_clock_wait));
  exports.Set("oc_clock_encode_time_rfc3339", Napi::Function::New(env, N_oc_clock_encode_time_rfc3339));
  exports.Set("oc_clock_parse_time_rfc3339", Napi::Function::New(env, N_oc_clock_parse_time_rfc3339));
  exports.Set("oc_clock_time_rfc3339", Napi::Function::New(env, N_oc_clock_time_rfc3339));
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_add_resource", Napi::Function::New(env, N_oc_cloud_add_resource));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_delete_resource", Napi::Function::New(env, N_oc_cloud_delete_resource));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_deregister", Napi::Function::New(env, N_oc_cloud_deregister));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_discover_resources", Napi::Function::New(env, N_oc_cloud_discover_resources));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_get_context", Napi::Function::New(env, N_oc_cloud_get_context));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_get_token_expiry", Napi::Function::New(env, N_oc_cloud_get_token_expiry));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_login", Napi::Function::New(env, N_oc_cloud_login));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_logout", Napi::Function::New(env, N_oc_cloud_logout));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_manager_start", Napi::Function::New(env, N_oc_cloud_manager_start));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_manager_stop", Napi::Function::New(env, N_oc_cloud_manager_stop));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_provision_conf_resource", Napi::Function::New(env, N_oc_cloud_provision_conf_resource));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_publish_resources", Napi::Function::New(env, N_oc_cloud_publish_resources));
#endif
#if defined(OC_CLOUD)
  exports.Set("oc_cloud_refresh_token", Napi::Function::New(env, N_oc_cloud_refresh_token));
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
  exports.Set("oc_core_add_new_device", Napi::Function::New(env, N_oc_core_add_new_device));
  exports.Set("oc_core_encode_interfaces_mask", Napi::Function::New(env, N_oc_core_encode_interfaces_mask));
  exports.Set("oc_core_get_device_id", Napi::Function::New(env, N_oc_core_get_device_id));
  exports.Set("oc_core_get_device_info", Napi::Function::New(env, N_oc_core_get_device_info));
  exports.Set("oc_core_get_latency", Napi::Function::New(env, N_oc_core_get_latency));
  exports.Set("oc_core_get_num_devices", Napi::Function::New(env, N_oc_core_get_num_devices));
  exports.Set("oc_core_get_platform_info", Napi::Function::New(env, N_oc_core_get_platform_info));
  exports.Set("oc_core_get_resource_by_index", Napi::Function::New(env, N_oc_core_get_resource_by_index));
  exports.Set("oc_core_get_resource_by_uri", Napi::Function::New(env, N_oc_core_get_resource_by_uri));
  exports.Set("oc_core_init", Napi::Function::New(env, N_oc_core_init));
  exports.Set("oc_core_init_platform", Napi::Function::New(env, N_oc_core_init_platform));
  exports.Set("oc_core_is_DCR", Napi::Function::New(env, N_oc_core_is_DCR));
  exports.Set("oc_core_populate_resource", Napi::Function::New(env, N_oc_core_populate_resource));
  exports.Set("oc_core_set_latency", Napi::Function::New(env, N_oc_core_set_latency));
  exports.Set("oc_core_shutdown", Napi::Function::New(env, N_oc_core_shutdown));
  exports.Set("oc_filter_resource_by_rt", Napi::Function::New(env, N_oc_filter_resource_by_rt));
  exports.Set("oc_store_uri", Napi::Function::New(env, N_oc_store_uri));
#if defined(OC_SECURITY)
  exports.Set("oc_cred_credtype_string", Napi::Function::New(env, N_oc_cred_credtype_string));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_cred_parse_credusage", Napi::Function::New(env, N_oc_cred_parse_credusage));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_cred_parse_encoding", Napi::Function::New(env, N_oc_cred_parse_encoding));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_cred_read_credusage", Napi::Function::New(env, N_oc_cred_read_credusage));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_cred_read_encoding", Napi::Function::New(env, N_oc_cred_read_encoding));
#endif
  exports.Set("oc_create_discovery_resource", Napi::Function::New(env, N_oc_create_discovery_resource));
  exports.Set("oc_endpoint_compare", Napi::Function::New(env, N_oc_endpoint_compare));
  exports.Set("oc_endpoint_compare_address", Napi::Function::New(env, N_oc_endpoint_compare_address));
  exports.Set("oc_endpoint_copy", Napi::Function::New(env, N_oc_endpoint_copy));
#if defined(XXX)
  exports.Set("oc_endpoint_list_copy", Napi::Function::New(env, N_oc_endpoint_list_copy));
#endif
  exports.Set("oc_endpoint_set_di", Napi::Function::New(env, N_oc_endpoint_set_di));
  exports.Set("oc_endpoint_set_local_address", Napi::Function::New(env, N_oc_endpoint_set_local_address));
  exports.Set("oc_endpoint_string_parse_path", Napi::Function::New(env, N_oc_endpoint_string_parse_path));
  exports.Set("oc_endpoint_to_string", Napi::Function::New(env, N_oc_endpoint_to_string));
  exports.Set("oc_free_endpoint", Napi::Function::New(env, N_oc_free_endpoint));
  exports.Set("oc_ipv6_endpoint_is_link_local", Napi::Function::New(env, N_oc_ipv6_endpoint_is_link_local));
  exports.Set("oc_new_endpoint", Napi::Function::New(env, N_oc_new_endpoint));
  exports.Set("oc_string_to_endpoint", Napi::Function::New(env, N_oc_string_to_endpoint));
  exports.Set("oc_enum_pos_desc_to_str", Napi::Function::New(env, N_oc_enum_pos_desc_to_str));
  exports.Set("oc_enum_to_str", Napi::Function::New(env, N_oc_enum_to_str));
  exports.Set("_oc_alloc_string", Napi::Function::New(env, N__oc_alloc_string));
  exports.Set("_oc_alloc_string_array", Napi::Function::New(env, N__oc_alloc_string_array));
#if defined(XXX)
  exports.Set("_oc_byte_string_array_add_item", Napi::Function::New(env, N__oc_byte_string_array_add_item));
#endif
#if defined(XXX)
  exports.Set("_oc_copy_byte_string_to_array", Napi::Function::New(env, N__oc_copy_byte_string_to_array));
#endif
#if defined(XXX)
  exports.Set("_oc_copy_string_to_array", Napi::Function::New(env, N__oc_copy_string_to_array));
#endif
  exports.Set("_oc_free_array", Napi::Function::New(env, N__oc_free_array));
  exports.Set("_oc_free_string", Napi::Function::New(env, N__oc_free_string));
  exports.Set("_oc_new_array", Napi::Function::New(env, N__oc_new_array));
  exports.Set("_oc_new_string", Napi::Function::New(env, N__oc_new_string));
#if defined(XXX)
  exports.Set("_oc_string_array_add_item", Napi::Function::New(env, N__oc_string_array_add_item));
#endif
  exports.Set("oc_concat_strings", Napi::Function::New(env, N_oc_concat_strings));
  exports.Set("oc_join_string_array", Napi::Function::New(env, N_oc_join_string_array));
#if defined(OC_IDD_API)
  exports.Set("oc_set_introspection_data", Napi::Function::New(env, N_oc_set_introspection_data));
#endif
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
#if defined(OC_SECURITY)
  exports.Set("oc_obt_ace_add_permission", Napi::Function::New(env, N_oc_obt_ace_add_permission));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_ace_new_resource", Napi::Function::New(env, N_oc_obt_ace_new_resource));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_ace_resource_set_href", Napi::Function::New(env, N_oc_obt_ace_resource_set_href));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_ace_resource_set_wc", Napi::Function::New(env, N_oc_obt_ace_resource_set_wc));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_obt_add_roleid", Napi::Function::New(env, N_oc_obt_add_roleid));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_delete_ace_by_aceid", Napi::Function::New(env, N_oc_obt_delete_ace_by_aceid));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_delete_cred_by_credid", Napi::Function::New(env, N_oc_obt_delete_cred_by_credid));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_delete_own_cred_by_credid", Napi::Function::New(env, N_oc_obt_delete_own_cred_by_credid));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_device_hard_reset", Napi::Function::New(env, N_oc_obt_device_hard_reset));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_all_resources", Napi::Function::New(env, N_oc_obt_discover_all_resources));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_owned_devices", Napi::Function::New(env, N_oc_obt_discover_owned_devices));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_owned_devices_realm_local_ipv6", Napi::Function::New(env, N_oc_obt_discover_owned_devices_realm_local_ipv6));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_owned_devices_site_local_ipv6", Napi::Function::New(env, N_oc_obt_discover_owned_devices_site_local_ipv6));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_unowned_devices", Napi::Function::New(env, N_oc_obt_discover_unowned_devices));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_unowned_devices_realm_local_ipv6", Napi::Function::New(env, N_oc_obt_discover_unowned_devices_realm_local_ipv6));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_discover_unowned_devices_site_local_ipv6", Napi::Function::New(env, N_oc_obt_discover_unowned_devices_site_local_ipv6));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_free_ace", Napi::Function::New(env, N_oc_obt_free_ace));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_free_acl", Napi::Function::New(env, N_oc_obt_free_acl));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_free_creds", Napi::Function::New(env, N_oc_obt_free_creds));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_obt_free_roleid", Napi::Function::New(env, N_oc_obt_free_roleid));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_init", Napi::Function::New(env, N_oc_obt_init));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_new_ace_for_connection", Napi::Function::New(env, N_oc_obt_new_ace_for_connection));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_new_ace_for_role", Napi::Function::New(env, N_oc_obt_new_ace_for_role));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_new_ace_for_subject", Napi::Function::New(env, N_oc_obt_new_ace_for_subject));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_obt_perform_cert_otm", Napi::Function::New(env, N_oc_obt_perform_cert_otm));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_perform_just_works_otm", Napi::Function::New(env, N_oc_obt_perform_just_works_otm));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_perform_random_pin_otm", Napi::Function::New(env, N_oc_obt_perform_random_pin_otm));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_provision_ace", Napi::Function::New(env, N_oc_obt_provision_ace));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_provision_auth_wildcard_ace", Napi::Function::New(env, N_oc_obt_provision_auth_wildcard_ace));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_obt_provision_identity_certificate", Napi::Function::New(env, N_oc_obt_provision_identity_certificate));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_provision_pairwise_credentials", Napi::Function::New(env, N_oc_obt_provision_pairwise_credentials));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_obt_provision_role_certificate", Napi::Function::New(env, N_oc_obt_provision_role_certificate));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_provision_role_wildcard_ace", Napi::Function::New(env, N_oc_obt_provision_role_wildcard_ace));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_request_random_pin", Napi::Function::New(env, N_oc_obt_request_random_pin));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_retrieve_acl", Napi::Function::New(env, N_oc_obt_retrieve_acl));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_retrieve_creds", Napi::Function::New(env, N_oc_obt_retrieve_creds));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_retrieve_own_creds", Napi::Function::New(env, N_oc_obt_retrieve_own_creds));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_set_sd_info", Napi::Function::New(env, N_oc_obt_set_sd_info));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_obt_shutdown", Napi::Function::New(env, N_oc_obt_shutdown));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_pki_add_mfg_cert", Napi::Function::New(env, N_oc_pki_add_mfg_cert));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_pki_add_mfg_intermediate_cert", Napi::Function::New(env, N_oc_pki_add_mfg_intermediate_cert));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_pki_add_mfg_trust_anchor", Napi::Function::New(env, N_oc_pki_add_mfg_trust_anchor));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
  exports.Set("oc_pki_add_trust_anchor", Napi::Function::New(env, N_oc_pki_add_trust_anchor));
#endif
#if defined(OC_SECURITY)
  exports.Set("oc_pki_set_security_profile", Napi::Function::New(env, N_oc_pki_set_security_profile));
#endif
  exports.Set("oc_random_destroy", Napi::Function::New(env, N_oc_random_destroy));
  exports.Set("oc_random_init", Napi::Function::New(env, N_oc_random_init));
  exports.Set("oc_random_value", Napi::Function::New(env, N_oc_random_value));
  exports.Set("oc_free_rep", Napi::Function::New(env, N_oc_free_rep));
  exports.Set("oc_parse_rep", Napi::Function::New(env, N_oc_parse_rep));
  exports.Set("oc_rep_get_bool", Napi::Function::New(env, N_oc_rep_get_bool));
  exports.Set("oc_rep_get_bool_array", Napi::Function::New(env, N_oc_rep_get_bool_array));
  exports.Set("oc_rep_get_byte_string", Napi::Function::New(env, N_oc_rep_get_byte_string));
  exports.Set("oc_rep_get_byte_string_array", Napi::Function::New(env, N_oc_rep_get_byte_string_array));
  exports.Set("oc_rep_get_cbor_errno", Napi::Function::New(env, N_oc_rep_get_cbor_errno));
  exports.Set("oc_rep_clear_cbor_errno", Napi::Function::New(env, N_oc_rep_clear_cbor_errno));
  exports.Set("oc_rep_get_double", Napi::Function::New(env, N_oc_rep_get_double));
  exports.Set("oc_rep_get_double_array", Napi::Function::New(env, N_oc_rep_get_double_array));
  exports.Set("oc_rep_get_encoded_payload_size", Napi::Function::New(env, N_oc_rep_get_encoded_payload_size));
  exports.Set("oc_rep_get_encoder_buf", Napi::Function::New(env, N_oc_rep_get_encoder_buf));
  exports.Set("oc_rep_get_int", Napi::Function::New(env, N_oc_rep_get_int));
  exports.Set("oc_rep_get_int_array", Napi::Function::New(env, N_oc_rep_get_int_array));
  exports.Set("oc_rep_get_object", Napi::Function::New(env, N_oc_rep_get_object));
  exports.Set("oc_rep_get_object_array", Napi::Function::New(env, N_oc_rep_get_object_array));
  exports.Set("oc_rep_get_string", Napi::Function::New(env, N_oc_rep_get_string));
  exports.Set("oc_rep_get_string_array", Napi::Function::New(env, N_oc_rep_get_string_array));
  exports.Set("oc_rep_new", Napi::Function::New(env, N_oc_rep_new));
  exports.Set("oc_rep_set_pool", Napi::Function::New(env, N_oc_rep_set_pool));
  exports.Set("oc_rep_to_json", Napi::Function::New(env, N_oc_rep_to_json));
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
  exports.Set("oc_ri_is_app_resource_valid", Napi::Function::New(env, N_oc_ri_is_app_resource_valid));
  exports.Set("oc_ri_remove_timed_event_callback", Napi::Function::New(env, N_oc_ri_remove_timed_event_callback));
  exports.Set("oc_ri_shutdown", Napi::Function::New(env, N_oc_ri_shutdown));
  exports.Set("oc_status_code", Napi::Function::New(env, N_oc_status_code));
#if defined(OC_TCP)
  exports.Set("oc_session_end_event", Napi::Function::New(env, N_oc_session_end_event));
#endif
#if defined(OC_TCP)
  exports.Set("oc_session_events_set_event_delay", Napi::Function::New(env, N_oc_session_events_set_event_delay));
#endif
#if defined(OC_TCP)
  exports.Set("oc_session_start_event", Napi::Function::New(env, N_oc_session_start_event));
#endif
  exports.Set("_oc_signal_event_loop", Napi::Function::New(env, N__oc_signal_event_loop));
  exports.Set("oc_storage_config", Napi::Function::New(env, N_oc_storage_config));
  exports.Set("oc_storage_read", Napi::Function::New(env, N_oc_storage_read));
  exports.Set("oc_storage_write", Napi::Function::New(env, N_oc_storage_write));
#if defined(OC_SOFTWARE_UPDATE)
  exports.Set("oc_swupdate_notify_done", Napi::Function::New(env, N_oc_swupdate_notify_done));
#endif
#if defined(OC_SOFTWARE_UPDATE)
  exports.Set("oc_swupdate_notify_downloaded", Napi::Function::New(env, N_oc_swupdate_notify_downloaded));
#endif
#if defined(OC_SOFTWARE_UPDATE)
  exports.Set("oc_swupdate_notify_new_version_available", Napi::Function::New(env, N_oc_swupdate_notify_new_version_available));
#endif
#if defined(OC_SOFTWARE_UPDATE)
  exports.Set("oc_swupdate_notify_upgrading", Napi::Function::New(env, N_oc_swupdate_notify_upgrading));
#endif
#if defined(OC_SOFTWARE_UPDATE)
  exports.Set("oc_swupdate_set_impl", Napi::Function::New(env, N_oc_swupdate_set_impl));
#endif
  exports.Set("oc_gen_uuid", Napi::Function::New(env, N_oc_gen_uuid));
  exports.Set("oc_str_to_uuid", Napi::Function::New(env, N_oc_str_to_uuid));
  exports.Set("oc_uuid_to_str", Napi::Function::New(env, N_oc_uuid_to_str));
  exports.Set("coap_separate_accept", Napi::Function::New(env, N_coap_separate_accept));
  exports.Set("coap_separate_clear", Napi::Function::New(env, N_coap_separate_clear));
  exports.Set("coap_separate_resume", Napi::Function::New(env, N_coap_separate_resume));
  exports.Set("coap_check_transactions", Napi::Function::New(env, N_coap_check_transactions));
  exports.Set("coap_clear_transaction", Napi::Function::New(env, N_coap_clear_transaction));
  exports.Set("coap_free_all_transactions", Napi::Function::New(env, N_coap_free_all_transactions));
  exports.Set("coap_free_transactions_by_endpoint", Napi::Function::New(env, N_coap_free_transactions_by_endpoint));
  exports.Set("coap_get_transaction_by_mid", Napi::Function::New(env, N_coap_get_transaction_by_mid));
  exports.Set("coap_new_transaction", Napi::Function::New(env, N_coap_new_transaction));
  exports.Set("coap_register_as_transaction_handler", Napi::Function::New(env, N_coap_register_as_transaction_handler));
  exports.Set("coap_send_transaction", Napi::Function::New(env, N_coap_send_transaction));
  exports.Set("helper_rep_set_double", Napi::Function::New(env, N_helper_rep_set_double));
  exports.Set("helper_rep_set_long", Napi::Function::New(env, N_helper_rep_set_long));
  exports.Set("helper_rep_set_uint", Napi::Function::New(env, N_helper_rep_set_uint));
  exports.Set("helper_rep_set_boolean", Napi::Function::New(env, N_helper_rep_set_boolean));
  exports.Set("helper_rep_set_text_string", Napi::Function::New(env, N_helper_rep_set_text_string));
  exports.Set("helper_rep_set_byte_string", Napi::Function::New(env, N_helper_rep_set_byte_string));
  exports.Set("helper_rep_start_array", Napi::Function::New(env, N_helper_rep_start_array));
  exports.Set("helper_rep_end_array", Napi::Function::New(env, N_helper_rep_end_array));
  exports.Set("helper_rep_start_links_array", Napi::Function::New(env, N_helper_rep_start_links_array));
  exports.Set("helper_rep_end_links_array", Napi::Function::New(env, N_helper_rep_end_links_array));
  exports.Set("helper_rep_begin_root_object", Napi::Function::New(env, N_helper_rep_begin_root_object));
  exports.Set("helper_rep_end_root_object", Napi::Function::New(env, N_helper_rep_end_root_object));
  exports.Set("helper_rep_add_byte_string", Napi::Function::New(env, N_helper_rep_add_byte_string));
  exports.Set("helper_rep_add_text_string", Napi::Function::New(env, N_helper_rep_add_text_string));
  exports.Set("helper_rep_add_double", Napi::Function::New(env, N_helper_rep_add_double));
  exports.Set("helper_rep_add_int", Napi::Function::New(env, N_helper_rep_add_int));
  exports.Set("helper_rep_add_boolean", Napi::Function::New(env, N_helper_rep_add_boolean));
  exports.Set("helper_rep_set_key", Napi::Function::New(env, N_helper_rep_set_key));
  exports.Set("helper_rep_set_array", Napi::Function::New(env, N_helper_rep_set_array));
  exports.Set("helper_rep_close_array", Napi::Function::New(env, N_helper_rep_close_array));
  exports.Set("helper_rep_start_object", Napi::Function::New(env, N_helper_rep_start_object));
  exports.Set("helper_rep_end_object", Napi::Function::New(env, N_helper_rep_end_object));
  exports.Set("helper_rep_object_array_start_item", Napi::Function::New(env, N_helper_rep_object_array_start_item));
  exports.Set("helper_rep_object_array_end_item", Napi::Function::New(env, N_helper_rep_object_array_end_item));
  exports.Set("helper_rep_open_object", Napi::Function::New(env, N_helper_rep_open_object));
  exports.Set("helper_rep_close_object", Napi::Function::New(env, N_helper_rep_close_object));
  exports.Set("helper_rep_set_long_array", Napi::Function::New(env, N_helper_rep_set_long_array));
  exports.Set("helper_rep_set_bool_array", Napi::Function::New(env, N_helper_rep_set_bool_array));
  exports.Set("helper_rep_set_double_array", Napi::Function::New(env, N_helper_rep_set_double_array));
  exports.Set("helper_rep_rep_set_string_array", Napi::Function::New(env, N_helper_rep_rep_set_string_array));
  exports.Set("helper_rep_get_rep_from_root_object", Napi::Function::New(env, N_helper_rep_get_rep_from_root_object));
  exports.Set("helper_rep_get_cbor_errno", Napi::Function::New(env, N_helper_rep_get_cbor_errno));
  exports.Set("helper_rep_get_long", Napi::Function::New(env, N_helper_rep_get_long));
  exports.Set("helper_rep_get_bool", Napi::Function::New(env, N_helper_rep_get_bool));
  exports.Set("helper_rep_get_double", Napi::Function::New(env, N_helper_rep_get_double));
  exports.Set("helper_rep_get_byte_string", Napi::Function::New(env, N_helper_rep_get_byte_string));
  exports.Set("helper_rep_get_string", Napi::Function::New(env, N_helper_rep_get_string));
  exports.Set("helper_rep_get_long_array", Napi::Function::New(env, N_helper_rep_get_long_array));
  exports.Set("helper_rep_get_bool_array", Napi::Function::New(env, N_helper_rep_get_bool_array));
  exports.Set("helper_rep_get_double_array", Napi::Function::New(env, N_helper_rep_get_double_array));
  exports.Set("helper_rep_get_byte_string_array", Napi::Function::New(env, N_helper_rep_get_byte_string_array));
  exports.Set("helper_rep_get_string_array", Napi::Function::New(env, N_helper_rep_get_string_array));
  exports.Set("helper_rep_get_object", Napi::Function::New(env, N_helper_rep_get_object));
  exports.Set("helper_rep_get_object_array", Napi::Function::New(env, N_helper_rep_get_object_array));
  return exports;
}
