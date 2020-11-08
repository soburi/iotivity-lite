#pragma once

#include <napi.h>
#include <oc_rep.h>

class OCBufferSettings : public Napi::ObjectWrap<OCBufferSettings>
{
public:
    OCBufferSettings(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value set_mtu_size(const Napi::CallbackInfo& info);
    static Napi::Value get_mtu_size(const Napi::CallbackInfo& info);
    static Napi::Value set_max_app_data_size(const Napi::CallbackInfo& info);
    static Napi::Value get_max_app_data_size(const Napi::CallbackInfo& info);
    static Napi::Value get_block_size(const Napi::CallbackInfo& info);
};

class OCClock : public Napi::ObjectWrap<OCClock>
{
public:
    OCClock(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value init(const Napi::CallbackInfo& info);
    static Napi::Value time(const Napi::CallbackInfo& info);
    static Napi::Value seconds(const Napi::CallbackInfo& info);
    static Napi::Value wait(const Napi::CallbackInfo& info);
};

class OCCloud : public Napi::ObjectWrap<OCCloud>
{
public:
    OCCloud(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
#if defined(OC_CLOUD)
    static Napi::Value get_context(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value manager_start(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value manager_stop(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value cloud_login(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value cloud_logout(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value cloud_refresh_token(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value get_token_expiry(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value add_resource(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value delete_resource(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value publish_resources(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value discover_resources(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value provision_conf_resource(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value cloud_register(const Napi::CallbackInfo& info);
#endif
#if defined(OC_CLOUD)
    static Napi::Value cloud_deregister(const Napi::CallbackInfo& info);
#endif
};

class OCCoreRes : public Napi::ObjectWrap<OCCoreRes>
{
public:
    OCCoreRes(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value init(const Napi::CallbackInfo& info);
    static Napi::Value init_platform(const Napi::CallbackInfo& info);
    static Napi::Value shutdown(const Napi::CallbackInfo& info);
    static Napi::Value get_num_devices(const Napi::CallbackInfo& info);
    static Napi::Value get_device_id(const Napi::CallbackInfo& info);
    static Napi::Value get_device_info(const Napi::CallbackInfo& info);
    static Napi::Value get_platform_info(const Napi::CallbackInfo& info);
    static Napi::Value get_resource_by_uri(const Napi::CallbackInfo& info);
    static Napi::Value filter_resource_by_rt(const Napi::CallbackInfo& info);
    static Napi::Value is_DCR(const Napi::CallbackInfo& info);
    static Napi::Value set_latency(const Napi::CallbackInfo& info);
    static Napi::Value get_latency(const Napi::CallbackInfo& info);
    static Napi::Value add_new_device(const Napi::CallbackInfo& info);
};

class OCEnumUtil : public Napi::ObjectWrap<OCEnumUtil>
{
public:
    OCEnumUtil(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value enum_to_str(const Napi::CallbackInfo& info);
    static Napi::Value pos_desc_to_str(const Napi::CallbackInfo& info);
};

class OCIntrospection : public Napi::ObjectWrap<OCIntrospection>
{
public:
    OCIntrospection(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
#if defined(OC_IDD_API)
    static Napi::Value set_introspection_data(const Napi::CallbackInfo& info);
#endif
};

class OCMain : public Napi::ObjectWrap<OCMain>
{
public:
    OCMain(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value add_collection(const Napi::CallbackInfo& info);
    static Napi::Value add_device(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY)
    static Napi::Value add_ownership_status_cb(const Napi::CallbackInfo& info);
#endif
    static Napi::Value add_resource(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value assert_all_roles(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value assert_role(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value auto_assert_roles(const Napi::CallbackInfo& info);
#endif
    static Napi::Value close_session(const Napi::CallbackInfo& info);
    static Napi::Value collection_add_link(const Napi::CallbackInfo& info);
    static Napi::Value collection_add_mandatory_rt(const Napi::CallbackInfo& info);
    static Napi::Value collection_add_supported_rt(const Napi::CallbackInfo& info);
    static Napi::Value collection_get_collections(const Napi::CallbackInfo& info);
    static Napi::Value collection_get_links(const Napi::CallbackInfo& info);
    static Napi::Value collection_remove_link(const Napi::CallbackInfo& info);
    static Napi::Value delete_collection(const Napi::CallbackInfo& info);
    static Napi::Value delete_link(const Napi::CallbackInfo& info);
    static Napi::Value delete_resource(const Napi::CallbackInfo& info);
    static Napi::Value device_bind_resource_type(const Napi::CallbackInfo& info);
    static Napi::Value do_delete(const Napi::CallbackInfo& info);
    static Napi::Value do_get(const Napi::CallbackInfo& info);
    static Napi::Value do_ip_discovery(const Napi::CallbackInfo& info);
    static Napi::Value do_ip_discovery_all(const Napi::CallbackInfo& info);
    static Napi::Value do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo& info);
    static Napi::Value do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info);
    static Napi::Value do_ip_multicast(const Napi::CallbackInfo& info);
    static Napi::Value do_observe(const Napi::CallbackInfo& info);
    static Napi::Value do_post(const Napi::CallbackInfo& info);
    static Napi::Value do_put(const Napi::CallbackInfo& info);
    static Napi::Value do_realm_local_ipv6_discovery(const Napi::CallbackInfo& info);
    static Napi::Value do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo& info);
    static Napi::Value do_realm_local_ipv6_multicast(const Napi::CallbackInfo& info);
    static Napi::Value do_site_local_ipv6_discovery(const Napi::CallbackInfo& info);
    static Napi::Value do_site_local_ipv6_discovery_all(const Napi::CallbackInfo& info);
    static Napi::Value do_site_local_ipv6_multicast(const Napi::CallbackInfo& info);
    static Napi::Value free_server_endpoints(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value get_all_roles(const Napi::CallbackInfo& info);
#endif
    static Napi::Value get_con_res_announced(const Napi::CallbackInfo& info);
    static Napi::Value ignore_request(const Napi::CallbackInfo& info);
    static Napi::Value indicate_separate_response(const Napi::CallbackInfo& info);
    static Napi::Value init_platform(const Napi::CallbackInfo& info);
    static Napi::Value init_post(const Napi::CallbackInfo& info);
    static Napi::Value init_put(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY)
    static Napi::Value is_owned_device(const Napi::CallbackInfo& info);
#endif
    static Napi::Value link_add_link_param(const Napi::CallbackInfo& info);
    static Napi::Value link_add_rel(const Napi::CallbackInfo& info);
    static Napi::Value main_init(const Napi::CallbackInfo& info);
    static Napi::Value main_loop(const Napi::CallbackInfo& info);
    static Napi::Value main_shutdown(const Napi::CallbackInfo& info);
    static Napi::Value new_collection(const Napi::CallbackInfo& info);
    static Napi::Value new_link(const Napi::CallbackInfo& info);
    static Napi::Value remove_delayed_callback(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY)
    static Napi::Value remove_ownership_status_cb(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value reset(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value reset_device(const Napi::CallbackInfo& info);
#endif
    static Napi::Value ri_is_app_resource_valid(const Napi::CallbackInfo& info);
    static Napi::Value send_diagnostic_message(const Napi::CallbackInfo& info);
#if defined(OC_TCP)
    static Napi::Value send_ping(const Napi::CallbackInfo& info);
#endif
    static Napi::Value send_response(const Napi::CallbackInfo& info);
    static Napi::Value send_response_raw(const Napi::CallbackInfo& info);
    static Napi::Value send_separate_response(const Napi::CallbackInfo& info);
    static Napi::Value set_con_res_announced(const Napi::CallbackInfo& info);
    static Napi::Value set_con_write_cb(const Napi::CallbackInfo& info);
    static Napi::Value set_delayed_callback(const Napi::CallbackInfo& info);
    static Napi::Value set_factory_presets_cb(const Napi::CallbackInfo& info);
#if defined(OC_SECURITY)
    static Napi::Value set_random_pin_callback(const Napi::CallbackInfo& info);
#endif
    static Napi::Value set_separate_response_buffer(const Napi::CallbackInfo& info);
    static Napi::Value stop_multicast(const Napi::CallbackInfo& info);
    static Napi::Value stop_observe(const Napi::CallbackInfo& info);
};

class OCNetworkMonitor : public Napi::ObjectWrap<OCNetworkMonitor>
{
public:
    OCNetworkMonitor(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value add_network_interface_event_callback(const Napi::CallbackInfo& info);
    static Napi::Value remove_network_interface_event_callback(const Napi::CallbackInfo& info);
    static Napi::Value add_session_event_callback(const Napi::CallbackInfo& info);
    static Napi::Value remove_session_event_callback(const Napi::CallbackInfo& info);
};

class OCObt : public Napi::ObjectWrap<OCObt>
{
public:
    OCObt(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
#if defined(OC_SECURITY)
    static Napi::Value ace_add_permission(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value ace_new_resource(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value ace_resource_set_href(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value ace_resource_set_wc(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value add_roleid(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value delete_ace_by_aceid(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value delete_cred_by_credid(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value delete_own_cred_by_credid(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value device_hard_reset(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_all_resources(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_owned_devices(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_unowned_devices(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value free_ace(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value free_acl(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value free_creds(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value free_roleid(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value init(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value new_ace_for_connection(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value new_ace_for_role(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value new_ace_for_subject(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value perform_cert_otm(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value perform_just_works_otm(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value perform_random_pin_otm(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value provision_ace(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value provision_auth_wildcard_ace(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value provision_identity_certificate(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value provision_pairwise_credentials(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value provision_role_certificate(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value provision_role_wildcard_ace(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value request_random_pin(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value retrieve_acl(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value retrieve_creds(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value retrieve_own_creds(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value set_sd_info(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value shutdown(const Napi::CallbackInfo& info);
#endif
};

class OCPki : public Napi::ObjectWrap<OCPki>
{
public:
    OCPki(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value add_mfg_cert(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value add_mfg_trust_anchor(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value add_mfg_intermediate_cert(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    static Napi::Value add_trust_anchor(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SECURITY)
    static Napi::Value set_security_profile(const Napi::CallbackInfo& info);
#endif
};

class OCRandom : public Napi::ObjectWrap<OCRandom>
{
public:
    OCRandom(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value init(const Napi::CallbackInfo& info);
    static Napi::Value destroy(const Napi::CallbackInfo& info);
    static Napi::Value random_value(const Napi::CallbackInfo& info);
};

class OCSessionEvents : public Napi::ObjectWrap<OCSessionEvents>
{
public:
    OCSessionEvents(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
#if defined(OC_TCP)
    static Napi::Value start_event(const Napi::CallbackInfo& info);
#endif
#if defined(OC_TCP)
    static Napi::Value end_event(const Napi::CallbackInfo& info);
#endif
#if defined(OC_TCP)
    static Napi::Value set_event_delay(const Napi::CallbackInfo& info);
#endif
};

class OCSoftwareUpdate : public Napi::ObjectWrap<OCSoftwareUpdate>
{
public:
    OCSoftwareUpdate(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
#if defined(OC_SOFTWARE_UPDATE)
    static Napi::Value notify_downloaded(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SOFTWARE_UPDATE)
    static Napi::Value notify_upgrading(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SOFTWARE_UPDATE)
    static Napi::Value notify_done(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SOFTWARE_UPDATE)
    static Napi::Value notify_new_version_available(const Napi::CallbackInfo& info);
#endif
#if defined(OC_SOFTWARE_UPDATE)
    static Napi::Value set_impl(const Napi::CallbackInfo& info);
#endif
};

class OCStorage : public Napi::ObjectWrap<OCStorage>
{
public:
    OCStorage(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference constructor;
    static Napi::Value config(const Napi::CallbackInfo& info);
    static Napi::Value read(const Napi::CallbackInfo& info);
    static Napi::Value write(const Napi::CallbackInfo& info);
};

