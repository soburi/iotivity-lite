#include "helper.h"
Napi::Value N_coap_get_header_accept(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_block1(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_block2(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_content_format(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_etag(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_if_match(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_coap_get_header_if_none_match(const Napi::CallbackInfo&);
#endif
Napi::Value N_coap_get_header_location_path(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_location_query(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_max_age(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_observe(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_proxy_scheme(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_proxy_uri(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_size1(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_size2(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_uri_host(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_uri_path(const Napi::CallbackInfo&);
Napi::Value N_coap_get_header_uri_query(const Napi::CallbackInfo&);
Napi::Value N_coap_get_mid(const Napi::CallbackInfo&);
Napi::Value N_coap_get_payload(const Napi::CallbackInfo&);
Napi::Value N_coap_get_post_variable(const Napi::CallbackInfo&);
Napi::Value N_coap_get_query_variable(const Napi::CallbackInfo&);
Napi::Value N_coap_init_connection(const Napi::CallbackInfo&);
Napi::Value N_coap_send_message(const Napi::CallbackInfo&);
Napi::Value N_coap_serialize_message(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_accept(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_block1(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_block2(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_content_format(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_etag(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_coap_set_header_if_match(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_coap_set_header_if_none_match(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_coap_set_header_location_path(const Napi::CallbackInfo&);
#endif
Napi::Value N_coap_set_header_location_query(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_max_age(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_observe(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_coap_set_header_proxy_scheme(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_coap_set_header_proxy_uri(const Napi::CallbackInfo&);
#endif
Napi::Value N_coap_set_header_size1(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_size2(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_coap_set_header_uri_host(const Napi::CallbackInfo&);
#endif
Napi::Value N_coap_set_header_uri_path(const Napi::CallbackInfo&);
Napi::Value N_coap_set_header_uri_query(const Napi::CallbackInfo&);
Napi::Value N_coap_set_payload(const Napi::CallbackInfo&);
Napi::Value N_coap_set_status_code(const Napi::CallbackInfo&);
Napi::Value N_coap_set_token(const Napi::CallbackInfo&);
Napi::Value N_coap_tcp_get_packet_size(const Napi::CallbackInfo&);
Napi::Value N_coap_tcp_init_message(const Napi::CallbackInfo&);
Napi::Value N_coap_tcp_parse_message(const Napi::CallbackInfo&);
Napi::Value N_coap_udp_init_message(const Napi::CallbackInfo&);
Napi::Value N_coap_udp_parse_message(const Napi::CallbackInfo&);
Napi::Value N_coap_check_signal_message(const Napi::CallbackInfo&);
Napi::Value N_coap_send_abort_message(const Napi::CallbackInfo&);
Napi::Value N_coap_send_csm_message(const Napi::CallbackInfo&);
Napi::Value N_coap_send_ping_message(const Napi::CallbackInfo&);
Napi::Value N_coap_send_pong_message(const Napi::CallbackInfo&);
Napi::Value N_coap_send_release_message(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_get_alt_addr(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_get_bad_csm(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_get_blockwise_transfer(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_get_custody(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_get_hold_off(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_get_max_msg_size(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_set_alt_addr(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_set_bad_csm(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_set_blockwise_transfer(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_set_custody(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_set_hold_off(const Napi::CallbackInfo&);
Napi::Value N_coap_signal_set_max_msg_size(const Napi::CallbackInfo&);
Napi::Value N_handle_coap_signal_message(const Napi::CallbackInfo&);
Napi::Value N_coap_init_engine(const Napi::CallbackInfo&);
Napi::Value N_coap_receive(const Napi::CallbackInfo&);
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_assert_all_roles(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_assert_role(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_auto_assert_roles(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_get_all_roles(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_close_session(const Napi::CallbackInfo&);
Napi::Value N_oc_do_delete(const Napi::CallbackInfo&);
Napi::Value N_oc_do_get(const Napi::CallbackInfo&);
Napi::Value N_oc_do_ip_discovery(const Napi::CallbackInfo&);
Napi::Value N_oc_do_ip_discovery_all(const Napi::CallbackInfo&);
Napi::Value N_oc_do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo&);
Napi::Value N_oc_do_ip_discovery_at_endpoint(const Napi::CallbackInfo&);
Napi::Value N_oc_do_ip_multicast(const Napi::CallbackInfo&);
Napi::Value N_oc_do_observe(const Napi::CallbackInfo&);
Napi::Value N_oc_do_post(const Napi::CallbackInfo&);
Napi::Value N_oc_do_put(const Napi::CallbackInfo&);
Napi::Value N_oc_do_realm_local_ipv6_discovery(const Napi::CallbackInfo&);
Napi::Value N_oc_do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo&);
Napi::Value N_oc_do_realm_local_ipv6_multicast(const Napi::CallbackInfo&);
Napi::Value N_oc_do_site_local_ipv6_discovery(const Napi::CallbackInfo&);
Napi::Value N_oc_do_site_local_ipv6_discovery_all(const Napi::CallbackInfo&);
Napi::Value N_oc_do_site_local_ipv6_multicast(const Napi::CallbackInfo&);
Napi::Value N_oc_free_server_endpoints(const Napi::CallbackInfo&);
Napi::Value N_oc_init_post(const Napi::CallbackInfo&);
Napi::Value N_oc_init_put(const Napi::CallbackInfo&);
#if defined(OC_TCP)
Napi::Value N_oc_send_ping(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_stop_multicast(const Napi::CallbackInfo&);
Napi::Value N_oc_stop_observe(const Napi::CallbackInfo&);
Napi::Value N_oc_add_collection(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_add_link(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_add_mandatory_rt(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_add_supported_rt(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_get_collections(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_get_links(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_remove_link(const Napi::CallbackInfo&);
#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_add_rt_factory(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_delete_collection(const Napi::CallbackInfo&);
Napi::Value N_oc_delete_link(const Napi::CallbackInfo&);
Napi::Value N_oc_link_add_link_param(const Napi::CallbackInfo&);
Napi::Value N_oc_link_add_rel(const Napi::CallbackInfo&);
Napi::Value N_oc_new_collection(const Napi::CallbackInfo&);
Napi::Value N_oc_new_link(const Napi::CallbackInfo&);
Napi::Value N_oc_remove_delayed_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_set_delayed_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_set_immutable_device_identifier(const Napi::CallbackInfo&);
Napi::Value N_oc_add_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_delete_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_device_bind_resource_type(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_oc_get_diagnostic_message(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_oc_get_query_value(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_oc_get_request_payload_raw(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_oc_get_response_payload_raw(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_ignore_request(const Napi::CallbackInfo&);
Napi::Value N_oc_indicate_separate_response(const Napi::CallbackInfo&);
Napi::Value N_oc_init_query_iterator(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_oc_iterate_query(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N_oc_iterate_query_get_values(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_new_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_notify_observers(const Napi::CallbackInfo&);
Napi::Value N_oc_process_baseline_interface(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_bind_resource_interface(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_bind_resource_type(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_resource_make_public(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_resource_set_default_interface(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_set_discoverable(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_set_observable(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_set_periodic_observable(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_set_properties_cbs(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_set_request_handler(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_tag_func_desc(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_tag_pos_desc(const Napi::CallbackInfo&);
Napi::Value N_oc_resource_tag_pos_rel(const Napi::CallbackInfo&);
Napi::Value N_oc_send_diagnostic_message(const Napi::CallbackInfo&);
Napi::Value N_oc_send_response(const Napi::CallbackInfo&);
Napi::Value N_oc_send_response_raw(const Napi::CallbackInfo&);
Napi::Value N_oc_send_separate_response(const Napi::CallbackInfo&);
Napi::Value N_oc_set_con_write_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_set_separate_response_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_timer_expired(const Napi::CallbackInfo&);
Napi::Value N_oc_timer_remaining(const Napi::CallbackInfo&);
Napi::Value N_oc_timer_reset(const Napi::CallbackInfo&);
Napi::Value N_oc_timer_restart(const Napi::CallbackInfo&);
Napi::Value N_oc_timer_set(const Napi::CallbackInfo&);
Napi::Value N_coap_free_all_observers(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_coap_get_observers(const Napi::CallbackInfo&);
#endif
Napi::Value N_coap_notify_collection_baseline(const Napi::CallbackInfo&);
Napi::Value N_coap_notify_collection_batch(const Napi::CallbackInfo&);
Napi::Value N_coap_notify_collection_links_list(const Napi::CallbackInfo&);
Napi::Value N_coap_notify_collection_observers(const Napi::CallbackInfo&);
Napi::Value N_coap_notify_observers(const Napi::CallbackInfo&);
Napi::Value N_coap_observe_handler(const Napi::CallbackInfo&);
Napi::Value N_coap_remove_observer(const Napi::CallbackInfo&);
Napi::Value N_coap_remove_observer_by_client(const Napi::CallbackInfo&);
Napi::Value N_coap_remove_observer_by_mid(const Napi::CallbackInfo&);
Napi::Value N_coap_remove_observer_by_resource(const Napi::CallbackInfo&);
Napi::Value N_coap_remove_observer_by_token(const Napi::CallbackInfo&);
Napi::Value N_coap_remove_observers_on_dos_change(const Napi::CallbackInfo&);
Napi::Value N_oc_add_device(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_add_ownership_status_cb(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_get_con_res_announced(const Napi::CallbackInfo&);
Napi::Value N_oc_init_platform(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_is_owned_device(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_main_init(const Napi::CallbackInfo&);
Napi::Value N_oc_main_poll(const Napi::CallbackInfo&);
Napi::Value N_oc_main_shutdown(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_remove_ownership_status_cb(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_reset(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_reset_device(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_set_con_res_announced(const Napi::CallbackInfo&);
Napi::Value N_oc_set_factory_presets_cb(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_set_random_pin_callback(const Napi::CallbackInfo&);
#endif
Napi::Value N_abort_impl(const Napi::CallbackInfo&);
Napi::Value N_exit_impl(const Napi::CallbackInfo&);
Napi::Value N_oc_abort(const Napi::CallbackInfo&);
Napi::Value N_oc_exit(const Napi::CallbackInfo&);
Napi::Value N_oc_base64_decode(const Napi::CallbackInfo&);
Napi::Value N_oc_base64_encode(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_alloc_request_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_alloc_response_buffer(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_oc_blockwise_dispatch_block(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_blockwise_find_request_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_request_buffer_by_client_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_request_buffer_by_mid(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_request_buffer_by_token(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_response_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_response_buffer_by_client_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_response_buffer_by_mid(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_find_response_buffer_by_token(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_free_request_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_free_response_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_handle_block(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_scrub_buffers(const Napi::CallbackInfo&);
Napi::Value N_oc_blockwise_scrub_buffers_for_client_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_allocate_message(const Napi::CallbackInfo&);
Napi::Value N_oc_allocate_message_from_pool(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions_for_device(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_internal_allocate_outgoing_message(const Napi::CallbackInfo&);
Napi::Value N_oc_message_add_ref(const Napi::CallbackInfo&);
Napi::Value N_oc_message_unref(const Napi::CallbackInfo&);
Napi::Value N_oc_recv_message(const Napi::CallbackInfo&);
Napi::Value N_oc_send_message(const Napi::CallbackInfo&);
Napi::Value N_oc_set_buffers_avail_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_get_block_size(const Napi::CallbackInfo&);
Napi::Value N_oc_get_max_app_data_size(const Napi::CallbackInfo&);
Napi::Value N_oc_get_mtu_size(const Napi::CallbackInfo&);
Napi::Value N_oc_set_max_app_data_size(const Napi::CallbackInfo&);
Napi::Value N_oc_set_mtu_size(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_alloc_client_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_find_client_cb_by_mid(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_find_client_cb_by_token(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_free_client_cbs_by_endpoint(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_free_client_cbs_by_mid(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_get_client_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_invoke_client_cb(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_is_client_cb_valid(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_process_discovery_payload(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_init(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_seconds(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_time(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_wait(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_encode_time_rfc3339(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_parse_time_rfc3339(const Napi::CallbackInfo&);
Napi::Value N_oc_clock_time_rfc3339(const Napi::CallbackInfo&);
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_add_resource(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_delete_resource(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_deregister(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_discover_resources(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_get_context(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_get_token_expiry(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_login(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_logout(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_manager_start(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_manager_stop(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_provision_conf_resource(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_publish_resources(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_refresh_token(const Napi::CallbackInfo&);
#endif
#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_register(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_check_if_collection(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_add(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_alloc(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_free(const Napi::CallbackInfo&);
Napi::Value N_oc_collection_get_all(const Napi::CallbackInfo&);
#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_free_rt_factories(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_get_collection_by_uri(const Napi::CallbackInfo&);
Napi::Value N_oc_get_link_by_uri(const Napi::CallbackInfo&);
Napi::Value N_oc_get_next_collection_with_link(const Napi::CallbackInfo&);
Napi::Value N_oc_handle_collection_request(const Napi::CallbackInfo&);
Napi::Value N_oc_link_set_interfaces(const Napi::CallbackInfo&);
Napi::Value N_handle_network_interface_event_callback(const Napi::CallbackInfo&);
Napi::Value N_handle_session_event_callback(const Napi::CallbackInfo&);
#if defined(OC_TCP)
Napi::Value N_oc_connectivity_end_session(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_connectivity_get_endpoints(const Napi::CallbackInfo&);
Napi::Value N_oc_connectivity_init(const Napi::CallbackInfo&);
Napi::Value N_oc_connectivity_shutdown(const Napi::CallbackInfo&);
Napi::Value N_oc_dns_lookup(const Napi::CallbackInfo&);
Napi::Value N_oc_send_buffer(const Napi::CallbackInfo&);
Napi::Value N_oc_send_discovery_request(const Napi::CallbackInfo&);
#if defined(OC_TCP)
Napi::Value N_oc_tcp_get_csm_state(const Napi::CallbackInfo&);
#endif
#if defined(OC_TCP)
Napi::Value N_oc_tcp_update_csm_state(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_core_add_new_device(const Napi::CallbackInfo&);
Napi::Value N_oc_core_encode_interfaces_mask(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_device_id(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_device_info(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_latency(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_num_devices(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_platform_info(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_resource_by_index(const Napi::CallbackInfo&);
Napi::Value N_oc_core_get_resource_by_uri(const Napi::CallbackInfo&);
Napi::Value N_oc_core_init(const Napi::CallbackInfo&);
Napi::Value N_oc_core_init_platform(const Napi::CallbackInfo&);
Napi::Value N_oc_core_is_DCR(const Napi::CallbackInfo&);
Napi::Value N_oc_core_populate_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_core_set_latency(const Napi::CallbackInfo&);
Napi::Value N_oc_core_shutdown(const Napi::CallbackInfo&);
Napi::Value N_oc_filter_resource_by_rt(const Napi::CallbackInfo&);
Napi::Value N_oc_store_uri(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_cred_credtype_string(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_cred_parse_credusage(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_cred_parse_encoding(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_cred_read_credusage(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_cred_read_encoding(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_create_discovery_resource(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_compare(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_compare_address(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_copy(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N_oc_endpoint_list_copy(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_endpoint_set_di(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_set_local_address(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_string_parse_path(const Napi::CallbackInfo&);
Napi::Value N_oc_endpoint_to_string(const Napi::CallbackInfo&);
Napi::Value N_oc_free_endpoint(const Napi::CallbackInfo&);
Napi::Value N_oc_ipv6_endpoint_is_link_local(const Napi::CallbackInfo&);
Napi::Value N_oc_new_endpoint(const Napi::CallbackInfo&);
Napi::Value N_oc_string_to_endpoint(const Napi::CallbackInfo&);
Napi::Value N_oc_enum_pos_desc_to_str(const Napi::CallbackInfo&);
Napi::Value N_oc_enum_to_str(const Napi::CallbackInfo&);
Napi::Value N__oc_alloc_string(const Napi::CallbackInfo&);
Napi::Value N__oc_alloc_string_array(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N__oc_byte_string_array_add_item(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N__oc_copy_byte_string_to_array(const Napi::CallbackInfo&);
#endif
#if defined(XXX)
Napi::Value N__oc_copy_string_to_array(const Napi::CallbackInfo&);
#endif
Napi::Value N__oc_free_array(const Napi::CallbackInfo&);
Napi::Value N__oc_free_string(const Napi::CallbackInfo&);
Napi::Value N__oc_new_array(const Napi::CallbackInfo&);
Napi::Value N__oc_new_string(const Napi::CallbackInfo&);
#if defined(XXX)
Napi::Value N__oc_string_array_add_item(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_concat_strings(const Napi::CallbackInfo&);
Napi::Value N_oc_join_string_array(const Napi::CallbackInfo&);
#if defined(OC_IDD_API)
Napi::Value N_oc_set_introspection_data(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_memb_init(const Napi::CallbackInfo&);
Napi::Value N_oc_memb_inmemb(const Napi::CallbackInfo&);
Napi::Value N_oc_memb_numfree(const Napi::CallbackInfo&);
Napi::Value N_oc_memb_set_buffers_avail_cb(const Napi::CallbackInfo&);
#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_add_pace(const Napi::CallbackInfo&);
#endif
#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_init(const Napi::CallbackInfo&);
#endif
#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_shutdown(const Napi::CallbackInfo&);
#endif
Napi::Value N__oc_mmem_alloc(const Napi::CallbackInfo&);
Napi::Value N__oc_mmem_free(const Napi::CallbackInfo&);
Napi::Value N_oc_mmem_init(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event(const Napi::CallbackInfo&);
Napi::Value N_oc_network_interface_event(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_destroy(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_init(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_lock(const Napi::CallbackInfo&);
Napi::Value N_oc_network_event_handler_mutex_unlock(const Napi::CallbackInfo&);
Napi::Value N_oc_add_network_interface_event_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_add_session_event_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_remove_network_interface_event_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_remove_session_event_callback(const Napi::CallbackInfo&);
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_add_permission(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_new_resource(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_resource_set_href(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_ace_resource_set_wc(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_add_roleid(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_delete_ace_by_aceid(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_delete_cred_by_credid(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_delete_own_cred_by_credid(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_device_hard_reset(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_all_resources(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_owned_devices(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_unowned_devices(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_free_ace(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_free_acl(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_free_creds(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_free_roleid(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_init(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_new_ace_for_connection(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_new_ace_for_role(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_new_ace_for_subject(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_perform_cert_otm(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_perform_just_works_otm(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_perform_random_pin_otm(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_ace(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_auth_wildcard_ace(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_provision_identity_certificate(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_pairwise_credentials(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_obt_provision_role_certificate(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_provision_role_wildcard_ace(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_request_random_pin(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_retrieve_acl(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_retrieve_creds(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_retrieve_own_creds(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_set_sd_info(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_obt_shutdown(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_mfg_cert(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_mfg_intermediate_cert(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_mfg_trust_anchor(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value N_oc_pki_add_trust_anchor(const Napi::CallbackInfo&);
#endif
#if defined(OC_SECURITY)
Napi::Value N_oc_pki_set_security_profile(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_random_destroy(const Napi::CallbackInfo&);
Napi::Value N_oc_random_init(const Napi::CallbackInfo&);
Napi::Value N_oc_random_value(const Napi::CallbackInfo&);
Napi::Value N_oc_free_rep(const Napi::CallbackInfo&);
Napi::Value N_oc_parse_rep(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_bool(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_bool_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_byte_string(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_byte_string_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_cbor_errno(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_double(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_double_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_encoded_payload_size(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_encoder_buf(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_int(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_int_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_object(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_object_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_string(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_get_string_array(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_new(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_set_pool(const Napi::CallbackInfo&);
Napi::Value N_oc_rep_to_json(const Napi::CallbackInfo&);
#if defined(OC_SERVER)
Napi::Value N_oc_ri_add_resource(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_ri_add_timed_event_callback_ticks(const Napi::CallbackInfo&);
#if defined(OC_SERVER)
Napi::Value N_oc_ri_alloc_resource(const Napi::CallbackInfo&);
#endif
#if defined(OC_SERVER)
Napi::Value N_oc_ri_delete_resource(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_ri_free_resource_properties(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_get_app_resource_by_uri(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_get_app_resources(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_get_interface_mask(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_get_query_nth_key_value(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_get_query_value(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_init(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_is_app_resource_valid(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_remove_timed_event_callback(const Napi::CallbackInfo&);
Napi::Value N_oc_ri_shutdown(const Napi::CallbackInfo&);
Napi::Value N_oc_status_code(const Napi::CallbackInfo&);
#if defined(OC_TCP)
Napi::Value N_oc_session_end_event(const Napi::CallbackInfo&);
#endif
#if defined(OC_TCP)
Napi::Value N_oc_session_events_set_event_delay(const Napi::CallbackInfo&);
#endif
#if defined(OC_TCP)
Napi::Value N_oc_session_start_event(const Napi::CallbackInfo&);
#endif
Napi::Value N__oc_signal_event_loop(const Napi::CallbackInfo&);
Napi::Value N_oc_storage_config(const Napi::CallbackInfo&);
Napi::Value N_oc_storage_read(const Napi::CallbackInfo&);
Napi::Value N_oc_storage_write(const Napi::CallbackInfo&);
#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_done(const Napi::CallbackInfo&);
#endif
#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_downloaded(const Napi::CallbackInfo&);
#endif
#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_new_version_available(const Napi::CallbackInfo&);
#endif
#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_notify_upgrading(const Napi::CallbackInfo&);
#endif
#if defined(OC_SOFTWARE_UPDATE)
Napi::Value N_oc_swupdate_set_impl(const Napi::CallbackInfo&);
#endif
Napi::Value N_oc_gen_uuid(const Napi::CallbackInfo&);
Napi::Value N_oc_str_to_uuid(const Napi::CallbackInfo&);
Napi::Value N_oc_uuid_to_str(const Napi::CallbackInfo&);
Napi::Value N_coap_separate_accept(const Napi::CallbackInfo&);
Napi::Value N_coap_separate_clear(const Napi::CallbackInfo&);
Napi::Value N_coap_separate_resume(const Napi::CallbackInfo&);
Napi::Value N_coap_check_transactions(const Napi::CallbackInfo&);
Napi::Value N_coap_clear_transaction(const Napi::CallbackInfo&);
Napi::Value N_coap_free_all_transactions(const Napi::CallbackInfo&);
Napi::Value N_coap_free_transactions_by_endpoint(const Napi::CallbackInfo&);
Napi::Value N_coap_get_transaction_by_mid(const Napi::CallbackInfo&);
Napi::Value N_coap_new_transaction(const Napi::CallbackInfo&);
Napi::Value N_coap_register_as_transaction_handler(const Napi::CallbackInfo&);
Napi::Value N_coap_send_transaction(const Napi::CallbackInfo&);
