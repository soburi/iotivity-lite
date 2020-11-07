#include "iotivity_lite.h"
#include "structs.h"
#include "functions.h"
#include "helper.h"
using namespace Napi;

Napi::Object module_init(Napi::Env env, Napi::Object exports);
Napi::Object Init(Napi::Env env, Napi::Object exports);
NODE_API_MODULE(addon, Init)

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("OCMain", OCMain::GetClass(env));
    exports.Set("OCObt", OCObt::GetClass(env));
    exports.Set("OCBufferSettings", OCBufferSettings::GetClass(env));
    exports.Set("OCClock", OCClock::GetClass(env));
    exports.Set("OCCloud", OCCloud::GetClass(env));
    exports.Set("OCCredUtil", OCCredUtil::GetClass(env));
    exports.Set("OCEndpointUtil", OCEndpointUtil::GetClass(env));
    exports.Set("OCEnumUtil", OCEnumUtil::GetClass(env));
    exports.Set("OCIntrospection", OCIntrospection::GetClass(env));
    exports.Set("OCPki", OCPki::GetClass(env));
    exports.Set("OCRandom", OCRandom::GetClass(env));
    exports.Set("OCSessionEvents", OCSessionEvents::GetClass(env));
    exports.Set("OCSoftwareUpdate", OCSoftwareUpdate::GetClass(env));
    exports.Set("OCStorage", OCStorage::GetClass(env));
    exports.Set("OCUuidUtil", OCUuidUtil::GetClass(env));
    exports.Set("OCCoreRes", OCCoreRes::GetClass(env));
    exports.Set("OCRep", OCRep::GetClass(env));
    exports.Set("OCStringArrayIterator", OCStringArrayIterator::GetClass(env));
    return module_init(env, exports);
}
OCMain::OCMain(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCMain::GetClass(Napi::Env env) {
    return DefineClass(env, "OCMain", {
        OCMain::StaticMethod("add_collection", &OCMain::add_collection),
        OCMain::StaticMethod("add_device", &OCMain::add_device),
        OCMain::StaticMethod("add_ownership_status_cb", &OCMain::add_ownership_status_cb),
        OCMain::StaticMethod("add_resource", &OCMain::add_resource),
        OCMain::StaticMethod("assert_all_roles", &OCMain::assert_all_roles),
        OCMain::StaticMethod("assert_role", &OCMain::assert_role),
        OCMain::StaticMethod("auto_assert_roles", &OCMain::auto_assert_roles),
        OCMain::StaticMethod("close_session", &OCMain::close_session),
        OCMain::StaticMethod("collection_add_link", &OCMain::collection_add_link),
        OCMain::StaticMethod("collection_add_mandatory_rt", &OCMain::collection_add_mandatory_rt),
        OCMain::StaticMethod("collection_add_supported_rt", &OCMain::collection_add_supported_rt),
        OCMain::StaticMethod("collection_get_collections", &OCMain::collection_get_collections),
        OCMain::StaticMethod("collection_get_links", &OCMain::collection_get_links),
        OCMain::StaticMethod("collection_remove_link", &OCMain::collection_remove_link),
        OCMain::StaticMethod("delete_collection", &OCMain::delete_collection),
        OCMain::StaticMethod("delete_link", &OCMain::delete_link),
        OCMain::StaticMethod("delete_resource", &OCMain::delete_resource),
        OCMain::StaticMethod("device_bind_resource_type", &OCMain::device_bind_resource_type),
        OCMain::StaticMethod("do_delete", &OCMain::do_delete),
        OCMain::StaticMethod("do_get", &OCMain::do_get),
        OCMain::StaticMethod("do_ip_discovery", &OCMain::do_ip_discovery),
        OCMain::StaticMethod("do_ip_discovery_all", &OCMain::do_ip_discovery_all),
        OCMain::StaticMethod("do_ip_discovery_all_at_endpoint", &OCMain::do_ip_discovery_all_at_endpoint),
        OCMain::StaticMethod("do_ip_discovery_at_endpoint", &OCMain::do_ip_discovery_at_endpoint),
        OCMain::StaticMethod("do_ip_multicast", &OCMain::do_ip_multicast),
        OCMain::StaticMethod("do_observe", &OCMain::do_observe),
        OCMain::StaticMethod("do_post", &OCMain::do_post),
        OCMain::StaticMethod("do_put", &OCMain::do_put),
        OCMain::StaticMethod("do_realm_local_ipv6_discovery", &OCMain::do_realm_local_ipv6_discovery),
        OCMain::StaticMethod("do_realm_local_ipv6_discovery_all", &OCMain::do_realm_local_ipv6_discovery_all),
        OCMain::StaticMethod("do_realm_local_ipv6_multicast", &OCMain::do_realm_local_ipv6_multicast),
        OCMain::StaticMethod("do_site_local_ipv6_discovery", &OCMain::do_site_local_ipv6_discovery),
        OCMain::StaticMethod("do_site_local_ipv6_discovery_all", &OCMain::do_site_local_ipv6_discovery_all),
        OCMain::StaticMethod("do_site_local_ipv6_multicast", &OCMain::do_site_local_ipv6_multicast),
        OCMain::StaticMethod("free_server_endpoints", &OCMain::free_server_endpoints),
        OCMain::StaticMethod("get_all_roles", &OCMain::get_all_roles),
        OCMain::StaticMethod("get_con_res_announced", &OCMain::get_con_res_announced),
        OCMain::StaticMethod("ignore_request", &OCMain::ignore_request),
        OCMain::StaticMethod("indicate_separate_response", &OCMain::indicate_separate_response),
        OCMain::StaticMethod("init_platform", &OCMain::init_platform),
        OCMain::StaticMethod("init_post", &OCMain::init_post),
        OCMain::StaticMethod("init_put", &OCMain::init_put),
        OCMain::StaticMethod("is_owned_device", &OCMain::is_owned_device),
        OCMain::StaticMethod("link_add_link_param", &OCMain::link_add_link_param),
        OCMain::StaticMethod("link_add_rel", &OCMain::link_add_rel),
        OCMain::StaticMethod("main_init", &OCMain::main_init),
        OCMain::StaticMethod("main_loop", &OCMain::main_loop),
        OCMain::StaticMethod("main_shutdown", &OCMain::main_shutdown),
        OCMain::StaticMethod("new_collection", &OCMain::new_collection),
        OCMain::StaticMethod("new_link", &OCMain::new_link),
        OCMain::StaticMethod("new_resource", &OCMain::new_resource),
        OCMain::StaticMethod("notify_observers", &OCMain::notify_observers),
        OCMain::StaticMethod("process_baseline_interface", &OCMain::process_baseline_interface),
        OCMain::StaticMethod("remove_delayed_callback", &OCMain::remove_delayed_callback),
        OCMain::StaticMethod("remove_ownership_status_cb", &OCMain::remove_ownership_status_cb),
        OCMain::StaticMethod("reset", &OCMain::reset),
        OCMain::StaticMethod("reset_device", &OCMain::reset_device),
        OCMain::StaticMethod("resource_bind_resource_interface", &OCMain::resource_bind_resource_interface),
        OCMain::StaticMethod("resource_bind_resource_type", &OCMain::resource_bind_resource_type),
        OCMain::StaticMethod("resource_make_public", &OCMain::resource_make_public),
        OCMain::StaticMethod("resource_set_default_interface", &OCMain::resource_set_default_interface),
        OCMain::StaticMethod("resource_set_discoverable", &OCMain::resource_set_discoverable),
        OCMain::StaticMethod("resource_set_observable", &OCMain::resource_set_observable),
        OCMain::StaticMethod("resource_set_periodic_observable", &OCMain::resource_set_periodic_observable),
        OCMain::StaticMethod("resource_set_properties_cbs", &OCMain::resource_set_properties_cbs),
        OCMain::StaticMethod("resource_set_request_handler", &OCMain::resource_set_request_handler),
        OCMain::StaticMethod("ri_is_app_resource_valid", &OCMain::ri_is_app_resource_valid),
        OCMain::StaticMethod("send_diagnostic_message", &OCMain::send_diagnostic_message),
        OCMain::StaticMethod("send_ping", &OCMain::send_ping),
        OCMain::StaticMethod("send_response", &OCMain::send_response),
        OCMain::StaticMethod("send_response_raw", &OCMain::send_response_raw),
        OCMain::StaticMethod("send_separate_response", &OCMain::send_separate_response),
        OCMain::StaticMethod("set_con_res_announced", &OCMain::set_con_res_announced),
        OCMain::StaticMethod("set_con_write_cb", &OCMain::set_con_write_cb),
        OCMain::StaticMethod("set_delayed_callback", &OCMain::set_delayed_callback),
        OCMain::StaticMethod("set_factory_presets_cb", &OCMain::set_factory_presets_cb),
        OCMain::StaticMethod("set_random_pin_callback", &OCMain::set_random_pin_callback),
        OCMain::StaticMethod("set_separate_response_buffer", &OCMain::set_separate_response_buffer),
        OCMain::StaticMethod("stop_multicast", &OCMain::stop_multicast),
        OCMain::StaticMethod("stop_observe", &OCMain::stop_observe),
    });
}

Napi::Value OCMain::add_collection(const Napi::CallbackInfo& info) { return N_oc_add_collection(info); };
Napi::Value OCMain::add_device(const Napi::CallbackInfo& info) { return N_oc_add_device(info); };
Napi::Value OCMain::add_ownership_status_cb(const Napi::CallbackInfo& info) { return N_oc_add_ownership_status_cb(info); };
Napi::Value OCMain::add_resource(const Napi::CallbackInfo& info) { return N_oc_add_resource(info); };
Napi::Value OCMain::assert_all_roles(const Napi::CallbackInfo& info) { return N_oc_assert_all_roles(info); };
Napi::Value OCMain::assert_role(const Napi::CallbackInfo& info) { return N_oc_assert_role(info); };
Napi::Value OCMain::auto_assert_roles(const Napi::CallbackInfo& info) { return N_oc_auto_assert_roles(info); };
Napi::Value OCMain::close_session(const Napi::CallbackInfo& info) { return N_oc_close_session(info); };
Napi::Value OCMain::collection_add_link(const Napi::CallbackInfo& info) { return N_oc_collection_add_link(info); };
Napi::Value OCMain::collection_add_mandatory_rt(const Napi::CallbackInfo& info) { return N_oc_collection_add_mandatory_rt(info); };
Napi::Value OCMain::collection_add_supported_rt(const Napi::CallbackInfo& info) { return N_oc_collection_add_supported_rt(info); };
Napi::Value OCMain::collection_get_collections(const Napi::CallbackInfo& info) { return N_oc_collection_get_collections(info); };
Napi::Value OCMain::collection_get_links(const Napi::CallbackInfo& info) { return N_oc_collection_get_links(info); };
Napi::Value OCMain::collection_remove_link(const Napi::CallbackInfo& info) { return N_oc_collection_remove_link(info); };
Napi::Value OCMain::delete_collection(const Napi::CallbackInfo& info) { return N_oc_delete_collection(info); };
Napi::Value OCMain::delete_link(const Napi::CallbackInfo& info) { return N_oc_delete_link(info); };
Napi::Value OCMain::delete_resource(const Napi::CallbackInfo& info) { return N_oc_delete_resource(info); };
Napi::Value OCMain::device_bind_resource_type(const Napi::CallbackInfo& info) { return N_oc_device_bind_resource_type(info); };
Napi::Value OCMain::do_delete(const Napi::CallbackInfo& info) { return N_oc_do_delete(info); };
Napi::Value OCMain::do_get(const Napi::CallbackInfo& info) { return N_oc_do_get(info); };
Napi::Value OCMain::do_ip_discovery(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery(info); };
Napi::Value OCMain::do_ip_discovery_all(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery_all(info); };
Napi::Value OCMain::do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery_all_at_endpoint(info); };
Napi::Value OCMain::do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery_at_endpoint(info); };
Napi::Value OCMain::do_ip_multicast(const Napi::CallbackInfo& info) { return N_oc_do_ip_multicast(info); };
Napi::Value OCMain::do_observe(const Napi::CallbackInfo& info) { return N_oc_do_observe(info); };
Napi::Value OCMain::do_post(const Napi::CallbackInfo& info) { return N_oc_do_post(info); };
Napi::Value OCMain::do_put(const Napi::CallbackInfo& info) { return N_oc_do_put(info); };
Napi::Value OCMain::do_realm_local_ipv6_discovery(const Napi::CallbackInfo& info) { return N_oc_do_realm_local_ipv6_discovery(info); };
Napi::Value OCMain::do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo& info) { return N_oc_do_realm_local_ipv6_discovery_all(info); };
Napi::Value OCMain::do_realm_local_ipv6_multicast(const Napi::CallbackInfo& info) { return N_oc_do_realm_local_ipv6_multicast(info); };
Napi::Value OCMain::do_site_local_ipv6_discovery(const Napi::CallbackInfo& info) { return N_oc_do_site_local_ipv6_discovery(info); };
Napi::Value OCMain::do_site_local_ipv6_discovery_all(const Napi::CallbackInfo& info) { return N_oc_do_site_local_ipv6_discovery_all(info); };
Napi::Value OCMain::do_site_local_ipv6_multicast(const Napi::CallbackInfo& info) { return N_oc_do_site_local_ipv6_multicast(info); };
Napi::Value OCMain::free_server_endpoints(const Napi::CallbackInfo& info) { return N_oc_free_server_endpoints(info); };
Napi::Value OCMain::get_all_roles(const Napi::CallbackInfo& info) { return N_oc_get_all_roles(info); };
Napi::Value OCMain::get_con_res_announced(const Napi::CallbackInfo& info) { return N_oc_get_con_res_announced(info); };
Napi::Value OCMain::ignore_request(const Napi::CallbackInfo& info) { return N_oc_ignore_request(info); };
Napi::Value OCMain::indicate_separate_response(const Napi::CallbackInfo& info) { return N_oc_indicate_separate_response(info); };
Napi::Value OCMain::init_platform(const Napi::CallbackInfo& info) { return N_oc_init_platform(info); };
Napi::Value OCMain::init_post(const Napi::CallbackInfo& info) { return N_oc_init_post(info); };
Napi::Value OCMain::init_put(const Napi::CallbackInfo& info) { return N_oc_init_put(info); };
Napi::Value OCMain::is_owned_device(const Napi::CallbackInfo& info) { return N_oc_is_owned_device(info); };
Napi::Value OCMain::link_add_link_param(const Napi::CallbackInfo& info) { return N_oc_link_add_link_param(info); };
Napi::Value OCMain::link_add_rel(const Napi::CallbackInfo& info) { return N_oc_link_add_rel(info); };
Napi::Value OCMain::main_init(const Napi::CallbackInfo& info) { return N_oc_main_init(info); };
Napi::Value OCMain::main_loop(const Napi::CallbackInfo& info) { return N_helper_main_loop(info); };
Napi::Value OCMain::main_shutdown(const Napi::CallbackInfo& info) { return N_oc_main_shutdown(info); };
Napi::Value OCMain::new_collection(const Napi::CallbackInfo& info) { return N_oc_new_collection(info); };
Napi::Value OCMain::new_link(const Napi::CallbackInfo& info) { return N_oc_new_link(info); };
Napi::Value OCMain::new_resource(const Napi::CallbackInfo& info) { return N_oc_new_resource(info); };
Napi::Value OCMain::notify_observers(const Napi::CallbackInfo& info) { return N_oc_notify_observers(info); };
Napi::Value OCMain::process_baseline_interface(const Napi::CallbackInfo& info) { return N_oc_process_baseline_interface(info); };
Napi::Value OCMain::remove_delayed_callback(const Napi::CallbackInfo& info) { return N_oc_remove_delayed_callback(info); };
Napi::Value OCMain::remove_ownership_status_cb(const Napi::CallbackInfo& info) { return N_oc_remove_ownership_status_cb(info); };
Napi::Value OCMain::reset(const Napi::CallbackInfo& info) { return N_oc_reset(info); };
Napi::Value OCMain::reset_device(const Napi::CallbackInfo& info) { return N_oc_reset_device(info); };
Napi::Value OCMain::resource_bind_resource_interface(const Napi::CallbackInfo& info) { return N_oc_resource_bind_resource_interface(info); };
Napi::Value OCMain::resource_bind_resource_type(const Napi::CallbackInfo& info) { return N_oc_resource_bind_resource_type(info); };
Napi::Value OCMain::resource_make_public(const Napi::CallbackInfo& info) { return N_oc_resource_make_public(info); };
Napi::Value OCMain::resource_set_default_interface(const Napi::CallbackInfo& info) { return N_oc_resource_set_default_interface(info); };
Napi::Value OCMain::resource_set_discoverable(const Napi::CallbackInfo& info) { return N_oc_resource_set_discoverable(info); };
Napi::Value OCMain::resource_set_observable(const Napi::CallbackInfo& info) { return N_oc_resource_set_observable(info); };
Napi::Value OCMain::resource_set_periodic_observable(const Napi::CallbackInfo& info) { return N_oc_resource_set_periodic_observable(info); };
Napi::Value OCMain::resource_set_properties_cbs(const Napi::CallbackInfo& info) { return N_oc_resource_set_properties_cbs(info); };
Napi::Value OCMain::resource_set_request_handler(const Napi::CallbackInfo& info) { return N_oc_resource_set_request_handler(info); };
Napi::Value OCMain::ri_is_app_resource_valid(const Napi::CallbackInfo& info) { return N_oc_ri_is_app_resource_valid(info); };
Napi::Value OCMain::send_diagnostic_message(const Napi::CallbackInfo& info) { return N_oc_send_diagnostic_message(info); };
Napi::Value OCMain::send_ping(const Napi::CallbackInfo& info) { return N_oc_send_ping(info); };
Napi::Value OCMain::send_response(const Napi::CallbackInfo& info) { return N_oc_send_response(info); };
Napi::Value OCMain::send_response_raw(const Napi::CallbackInfo& info) { return N_oc_send_response_raw(info); };
Napi::Value OCMain::send_separate_response(const Napi::CallbackInfo& info) { return N_oc_send_separate_response(info); };
Napi::Value OCMain::set_con_res_announced(const Napi::CallbackInfo& info) { return N_oc_set_con_res_announced(info); };
Napi::Value OCMain::set_con_write_cb(const Napi::CallbackInfo& info) { return N_oc_set_con_write_cb(info); };
Napi::Value OCMain::set_delayed_callback(const Napi::CallbackInfo& info) { return N_oc_set_delayed_callback(info); };
Napi::Value OCMain::set_factory_presets_cb(const Napi::CallbackInfo& info) { return N_oc_set_factory_presets_cb(info); };
Napi::Value OCMain::set_random_pin_callback(const Napi::CallbackInfo& info) { return N_oc_set_random_pin_callback(info); };
Napi::Value OCMain::set_separate_response_buffer(const Napi::CallbackInfo& info) { return N_oc_set_separate_response_buffer(info); };
Napi::Value OCMain::stop_multicast(const Napi::CallbackInfo& info) { return N_oc_stop_multicast(info); };
Napi::Value OCMain::stop_observe(const Napi::CallbackInfo& info) { return N_oc_stop_observe(info); };
Napi::FunctionReference OCMain::constructor;

OCObt::OCObt(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCObt::GetClass(Napi::Env env) {
    return DefineClass(env, "OCObt", {
        OCObt::StaticMethod("ace_add_permission", &OCObt::ace_add_permission),
        OCObt::StaticMethod("ace_new_resource", &OCObt::ace_new_resource),
        OCObt::StaticMethod("ace_resource_set_href", &OCObt::ace_resource_set_href),
        OCObt::StaticMethod("ace_resource_set_wc", &OCObt::ace_resource_set_wc),
        OCObt::StaticMethod("add_roleid", &OCObt::add_roleid),
        OCObt::StaticMethod("delete_ace_by_aceid", &OCObt::delete_ace_by_aceid),
        OCObt::StaticMethod("delete_cred_by_credid", &OCObt::delete_cred_by_credid),
        OCObt::StaticMethod("delete_own_cred_by_credid", &OCObt::delete_own_cred_by_credid),
        OCObt::StaticMethod("device_hard_reset", &OCObt::device_hard_reset),
        OCObt::StaticMethod("discover_all_resources", &OCObt::discover_all_resources),
        OCObt::StaticMethod("discover_owned_devices", &OCObt::discover_owned_devices),
        OCObt::StaticMethod("discover_owned_devices_realm_local_ipv6", &OCObt::discover_owned_devices_realm_local_ipv6),
        OCObt::StaticMethod("discover_owned_devices_site_local_ipv6", &OCObt::discover_owned_devices_site_local_ipv6),
        OCObt::StaticMethod("discover_unowned_devices", &OCObt::discover_unowned_devices),
        OCObt::StaticMethod("discover_unowned_devices_realm_local_ipv6", &OCObt::discover_unowned_devices_realm_local_ipv6),
        OCObt::StaticMethod("discover_unowned_devices_site_local_ipv6", &OCObt::discover_unowned_devices_site_local_ipv6),
        OCObt::StaticMethod("free_ace", &OCObt::free_ace),
        OCObt::StaticMethod("free_acl", &OCObt::free_acl),
        OCObt::StaticMethod("free_creds", &OCObt::free_creds),
        OCObt::StaticMethod("free_roleid", &OCObt::free_roleid),
        OCObt::StaticMethod("init", &OCObt::init),
        OCObt::StaticMethod("new_ace_for_connection", &OCObt::new_ace_for_connection),
        OCObt::StaticMethod("new_ace_for_role", &OCObt::new_ace_for_role),
        OCObt::StaticMethod("new_ace_for_subject", &OCObt::new_ace_for_subject),
        OCObt::StaticMethod("perform_cert_otm", &OCObt::perform_cert_otm),
        OCObt::StaticMethod("perform_just_works_otm", &OCObt::perform_just_works_otm),
        OCObt::StaticMethod("perform_random_pin_otm", &OCObt::perform_random_pin_otm),
        OCObt::StaticMethod("provision_ace", &OCObt::provision_ace),
        OCObt::StaticMethod("provision_auth_wildcard_ace", &OCObt::provision_auth_wildcard_ace),
        OCObt::StaticMethod("provision_identity_certificate", &OCObt::provision_identity_certificate),
        OCObt::StaticMethod("provision_pairwise_credentials", &OCObt::provision_pairwise_credentials),
        OCObt::StaticMethod("provision_role_certificate", &OCObt::provision_role_certificate),
        OCObt::StaticMethod("provision_role_wildcard_ace", &OCObt::provision_role_wildcard_ace),
        OCObt::StaticMethod("request_random_pin", &OCObt::request_random_pin),
        OCObt::StaticMethod("retrieve_acl", &OCObt::retrieve_acl),
        OCObt::StaticMethod("retrieve_creds", &OCObt::retrieve_creds),
        OCObt::StaticMethod("retrieve_own_creds", &OCObt::retrieve_own_creds),
        OCObt::StaticMethod("set_sd_info", &OCObt::set_sd_info),
        OCObt::StaticMethod("shutdown", &OCObt::shutdown),
    });
}

Napi::Value OCObt::ace_add_permission(const Napi::CallbackInfo& info) { return N_oc_obt_ace_add_permission(info); };
Napi::Value OCObt::ace_new_resource(const Napi::CallbackInfo& info) { return N_oc_obt_ace_new_resource(info); };
Napi::Value OCObt::ace_resource_set_href(const Napi::CallbackInfo& info) { return N_oc_obt_ace_resource_set_href(info); };
Napi::Value OCObt::ace_resource_set_wc(const Napi::CallbackInfo& info) { return N_oc_obt_ace_resource_set_wc(info); };
Napi::Value OCObt::add_roleid(const Napi::CallbackInfo& info) { return N_oc_obt_add_roleid(info); };
Napi::Value OCObt::delete_ace_by_aceid(const Napi::CallbackInfo& info) { return N_oc_obt_delete_ace_by_aceid(info); };
Napi::Value OCObt::delete_cred_by_credid(const Napi::CallbackInfo& info) { return N_oc_obt_delete_cred_by_credid(info); };
Napi::Value OCObt::delete_own_cred_by_credid(const Napi::CallbackInfo& info) { return N_oc_obt_delete_own_cred_by_credid(info); };
Napi::Value OCObt::device_hard_reset(const Napi::CallbackInfo& info) { return N_oc_obt_device_hard_reset(info); };
Napi::Value OCObt::discover_all_resources(const Napi::CallbackInfo& info) { return N_oc_obt_discover_all_resources(info); };
Napi::Value OCObt::discover_owned_devices(const Napi::CallbackInfo& info) { return N_oc_obt_discover_owned_devices(info); };
Napi::Value OCObt::discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) { return N_oc_obt_discover_owned_devices_realm_local_ipv6(info); };
Napi::Value OCObt::discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo& info) { return N_oc_obt_discover_owned_devices_site_local_ipv6(info); };
Napi::Value OCObt::discover_unowned_devices(const Napi::CallbackInfo& info) { return N_oc_obt_discover_unowned_devices(info); };
Napi::Value OCObt::discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo& info) { return N_oc_obt_discover_unowned_devices_realm_local_ipv6(info); };
Napi::Value OCObt::discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo& info) { return N_oc_obt_discover_unowned_devices_site_local_ipv6(info); };
Napi::Value OCObt::free_ace(const Napi::CallbackInfo& info) { return N_oc_obt_free_ace(info); };
Napi::Value OCObt::free_acl(const Napi::CallbackInfo& info) { return N_oc_obt_free_acl(info); };
Napi::Value OCObt::free_creds(const Napi::CallbackInfo& info) { return N_oc_obt_free_creds(info); };
Napi::Value OCObt::free_roleid(const Napi::CallbackInfo& info) { return N_oc_obt_free_roleid(info); };
Napi::Value OCObt::init(const Napi::CallbackInfo& info) { return N_oc_obt_init(info); };
Napi::Value OCObt::new_ace_for_connection(const Napi::CallbackInfo& info) { return N_oc_obt_new_ace_for_connection(info); };
Napi::Value OCObt::new_ace_for_role(const Napi::CallbackInfo& info) { return N_oc_obt_new_ace_for_role(info); };
Napi::Value OCObt::new_ace_for_subject(const Napi::CallbackInfo& info) { return N_oc_obt_new_ace_for_subject(info); };
Napi::Value OCObt::perform_cert_otm(const Napi::CallbackInfo& info) { return N_oc_obt_perform_cert_otm(info); };
Napi::Value OCObt::perform_just_works_otm(const Napi::CallbackInfo& info) { return N_oc_obt_perform_just_works_otm(info); };
Napi::Value OCObt::perform_random_pin_otm(const Napi::CallbackInfo& info) { return N_oc_obt_perform_random_pin_otm(info); };
Napi::Value OCObt::provision_ace(const Napi::CallbackInfo& info) { return N_oc_obt_provision_ace(info); };
Napi::Value OCObt::provision_auth_wildcard_ace(const Napi::CallbackInfo& info) { return N_oc_obt_provision_auth_wildcard_ace(info); };
Napi::Value OCObt::provision_identity_certificate(const Napi::CallbackInfo& info) { return N_oc_obt_provision_identity_certificate(info); };
Napi::Value OCObt::provision_pairwise_credentials(const Napi::CallbackInfo& info) { return N_oc_obt_provision_pairwise_credentials(info); };
Napi::Value OCObt::provision_role_certificate(const Napi::CallbackInfo& info) { return N_oc_obt_provision_role_certificate(info); };
Napi::Value OCObt::provision_role_wildcard_ace(const Napi::CallbackInfo& info) { return N_oc_obt_provision_role_wildcard_ace(info); };
Napi::Value OCObt::request_random_pin(const Napi::CallbackInfo& info) { return N_oc_obt_request_random_pin(info); };
Napi::Value OCObt::retrieve_acl(const Napi::CallbackInfo& info) { return N_oc_obt_retrieve_acl(info); };
Napi::Value OCObt::retrieve_creds(const Napi::CallbackInfo& info) { return N_oc_obt_retrieve_creds(info); };
Napi::Value OCObt::retrieve_own_creds(const Napi::CallbackInfo& info) { return N_oc_obt_retrieve_own_creds(info); };
Napi::Value OCObt::set_sd_info(const Napi::CallbackInfo& info) { return N_oc_obt_set_sd_info(info); };
Napi::Value OCObt::shutdown(const Napi::CallbackInfo& info) { return N_oc_obt_shutdown(info); };
Napi::FunctionReference OCObt::constructor;

OCBufferSettings::OCBufferSettings(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCBufferSettings::GetClass(Napi::Env env) {
    return DefineClass(env, "OCBufferSettings", {
        OCBufferSettings::StaticMethod("set_mtu_size", &OCBufferSettings::set_mtu_size),
        OCBufferSettings::StaticMethod("get_mtu_size", &OCBufferSettings::get_mtu_size),
        OCBufferSettings::StaticMethod("set_max_app_data_size", &OCBufferSettings::set_max_app_data_size),
        OCBufferSettings::StaticMethod("get_max_app_data_size", &OCBufferSettings::get_max_app_data_size),
        OCBufferSettings::StaticMethod("get_block_size", &OCBufferSettings::get_block_size),
    });
}

Napi::Value OCBufferSettings::set_mtu_size(const Napi::CallbackInfo& info) { return N_oc_set_mtu_size(info); };
Napi::Value OCBufferSettings::get_mtu_size(const Napi::CallbackInfo& info) { return N_oc_get_mtu_size(info); };
Napi::Value OCBufferSettings::set_max_app_data_size(const Napi::CallbackInfo& info) { return N_oc_set_max_app_data_size(info); };
Napi::Value OCBufferSettings::get_max_app_data_size(const Napi::CallbackInfo& info) { return N_oc_get_max_app_data_size(info); };
Napi::Value OCBufferSettings::get_block_size(const Napi::CallbackInfo& info) { return N_oc_get_block_size(info); };
Napi::FunctionReference OCBufferSettings::constructor;

OCClock::OCClock(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCClock::GetClass(Napi::Env env) {
    return DefineClass(env, "OCClock", {
        OCClock::StaticMethod("clock_init", &OCClock::clock_init),
        OCClock::StaticMethod("clock_time", &OCClock::clock_time),
        OCClock::StaticMethod("clock_seconds", &OCClock::clock_seconds),
        OCClock::StaticMethod("clock_wait", &OCClock::clock_wait),
    });
}

Napi::Value OCClock::clock_init(const Napi::CallbackInfo& info) { return N_oc_clock_init(info); };
Napi::Value OCClock::clock_time(const Napi::CallbackInfo& info) { return N_oc_clock_time(info); };
Napi::Value OCClock::clock_seconds(const Napi::CallbackInfo& info) { return N_oc_clock_seconds(info); };
Napi::Value OCClock::clock_wait(const Napi::CallbackInfo& info) { return N_oc_clock_wait(info); };
Napi::FunctionReference OCClock::constructor;

OCCloud::OCCloud(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCloud::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCloud", {
        OCCloud::StaticMethod("get_context", &OCCloud::get_context),
        OCCloud::StaticMethod("manager_start", &OCCloud::manager_start),
        OCCloud::StaticMethod("manager_stop", &OCCloud::manager_stop),
        OCCloud::StaticMethod("login", &OCCloud::login),
        OCCloud::StaticMethod("logout", &OCCloud::logout),
        OCCloud::StaticMethod("refresh_token", &OCCloud::refresh_token),
        OCCloud::StaticMethod("get_token_expiry", &OCCloud::get_token_expiry),
        OCCloud::StaticMethod("add_resource", &OCCloud::add_resource),
        OCCloud::StaticMethod("delete_resource", &OCCloud::delete_resource),
        OCCloud::StaticMethod("publish_resources", &OCCloud::publish_resources),
        OCCloud::StaticMethod("discover_resources", &OCCloud::discover_resources),
        OCCloud::StaticMethod("provision_conf_resource", &OCCloud::provision_conf_resource),
    });
}

Napi::Value OCCloud::get_context(const Napi::CallbackInfo& info) { return N_oc_cloud_get_context(info); };
Napi::Value OCCloud::manager_start(const Napi::CallbackInfo& info) { return N_oc_cloud_manager_start(info); };
Napi::Value OCCloud::manager_stop(const Napi::CallbackInfo& info) { return N_oc_cloud_manager_stop(info); };
Napi::Value OCCloud::login(const Napi::CallbackInfo& info) { return N_oc_cloud_login(info); };
Napi::Value OCCloud::logout(const Napi::CallbackInfo& info) { return N_oc_cloud_logout(info); };
Napi::Value OCCloud::refresh_token(const Napi::CallbackInfo& info) { return N_oc_cloud_refresh_token(info); };
Napi::Value OCCloud::get_token_expiry(const Napi::CallbackInfo& info) { return N_oc_cloud_get_token_expiry(info); };
Napi::Value OCCloud::add_resource(const Napi::CallbackInfo& info) { return N_oc_cloud_add_resource(info); };
Napi::Value OCCloud::delete_resource(const Napi::CallbackInfo& info) { return N_oc_cloud_delete_resource(info); };
Napi::Value OCCloud::publish_resources(const Napi::CallbackInfo& info) { return N_oc_cloud_publish_resources(info); };
Napi::Value OCCloud::discover_resources(const Napi::CallbackInfo& info) { return N_oc_cloud_discover_resources(info); };
Napi::Value OCCloud::provision_conf_resource(const Napi::CallbackInfo& info) { return N_oc_cloud_provision_conf_resource(info); };
Napi::FunctionReference OCCloud::constructor;

OCCredUtil::OCCredUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCredUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCredUtil", {
        OCCredUtil::StaticMethod("read_credusage", &OCCredUtil::read_credusage),
        OCCredUtil::StaticMethod("read_encoding", &OCCredUtil::read_encoding),
        OCCredUtil::StaticMethod("parse_credusage", &OCCredUtil::parse_credusage),
        OCCredUtil::StaticMethod("parse_encoding", &OCCredUtil::parse_encoding),
        OCCredUtil::StaticMethod("credtype_string", &OCCredUtil::credtype_string),
    });
}

Napi::Value OCCredUtil::read_credusage(const Napi::CallbackInfo& info) { return N_oc_cred_read_credusage(info); };
Napi::Value OCCredUtil::read_encoding(const Napi::CallbackInfo& info) { return N_oc_cred_read_encoding(info); };
Napi::Value OCCredUtil::parse_credusage(const Napi::CallbackInfo& info) { return N_oc_cred_parse_credusage(info); };
Napi::Value OCCredUtil::parse_encoding(const Napi::CallbackInfo& info) { return N_oc_cred_parse_encoding(info); };
Napi::Value OCCredUtil::credtype_string(const Napi::CallbackInfo& info) { return N_oc_cred_credtype_string(info); };
Napi::FunctionReference OCCredUtil::constructor;

OCEndpointUtil::OCEndpointUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCEndpointUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCEndpointUtil", {
        OCEndpointUtil::StaticMethod("to_string", &OCEndpointUtil::to_string),
        OCEndpointUtil::StaticMethod("compare", &OCEndpointUtil::compare),
        OCEndpointUtil::StaticMethod("copy", &OCEndpointUtil::copy),
        OCEndpointUtil::StaticMethod("free_endpoint", &OCEndpointUtil::free_endpoint),
        OCEndpointUtil::StaticMethod("string_to_endpoint", &OCEndpointUtil::string_to_endpoint),
        OCEndpointUtil::StaticMethod("new_endpoint", &OCEndpointUtil::new_endpoint),
        OCEndpointUtil::StaticMethod("endpoint_string_parse_path", &OCEndpointUtil::endpoint_string_parse_path),
        OCEndpointUtil::StaticMethod("set_di", &OCEndpointUtil::set_di),
        OCEndpointUtil::StaticMethod("ipv6_endpoint_is_link_local", &OCEndpointUtil::ipv6_endpoint_is_link_local),
        OCEndpointUtil::StaticMethod("compare_address", &OCEndpointUtil::compare_address),
        OCEndpointUtil::StaticMethod("set_local_address", &OCEndpointUtil::set_local_address),
    });
}

Napi::Value OCEndpointUtil::to_string(const Napi::CallbackInfo& info) { return N_oc_endpoint_to_string(info); };
Napi::Value OCEndpointUtil::compare(const Napi::CallbackInfo& info) { return N_oc_endpoint_compare(info); };
Napi::Value OCEndpointUtil::copy(const Napi::CallbackInfo& info) { return N_oc_endpoint_copy(info); };
Napi::Value OCEndpointUtil::free_endpoint(const Napi::CallbackInfo& info) { return N_oc_free_endpoint(info); };
Napi::Value OCEndpointUtil::string_to_endpoint(const Napi::CallbackInfo& info) { return N_oc_string_to_endpoint(info); };
Napi::Value OCEndpointUtil::new_endpoint(const Napi::CallbackInfo& info) { return N_oc_new_endpoint(info); };
Napi::Value OCEndpointUtil::endpoint_string_parse_path(const Napi::CallbackInfo& info) { return N_oc_endpoint_string_parse_path(info); };
Napi::Value OCEndpointUtil::set_di(const Napi::CallbackInfo& info) { return N_oc_endpoint_set_di(info); };
Napi::Value OCEndpointUtil::ipv6_endpoint_is_link_local(const Napi::CallbackInfo& info) { return N_oc_ipv6_endpoint_is_link_local(info); };
Napi::Value OCEndpointUtil::compare_address(const Napi::CallbackInfo& info) { return N_oc_endpoint_compare_address(info); };
Napi::Value OCEndpointUtil::set_local_address(const Napi::CallbackInfo& info) { return N_oc_endpoint_set_local_address(info); };
Napi::FunctionReference OCEndpointUtil::constructor;

OCEnumUtil::OCEnumUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCEnumUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCEnumUtil", {
        OCEnumUtil::StaticMethod("enum_to_str", &OCEnumUtil::enum_to_str),
        OCEnumUtil::StaticMethod("pos_desc_to_str", &OCEnumUtil::pos_desc_to_str),
    });
}

Napi::Value OCEnumUtil::enum_to_str(const Napi::CallbackInfo& info) { return N_oc_enum_to_str(info); };
Napi::Value OCEnumUtil::pos_desc_to_str(const Napi::CallbackInfo& info) { return N_oc_enum_pos_desc_to_str(info); };
Napi::FunctionReference OCEnumUtil::constructor;

OCIntrospection::OCIntrospection(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCIntrospection::GetClass(Napi::Env env) {
    return DefineClass(env, "OCIntrospection", {
        OCIntrospection::StaticMethod("set_introspection_data", &OCIntrospection::set_introspection_data),
    });
}

Napi::Value OCIntrospection::set_introspection_data(const Napi::CallbackInfo& info) { return N_oc_set_introspection_data(info); };
Napi::FunctionReference OCIntrospection::constructor;

OCPki::OCPki(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCPki::GetClass(Napi::Env env) {
    return DefineClass(env, "OCPki", {
        OCPki::StaticMethod("add_mfg_cert", &OCPki::add_mfg_cert),
        OCPki::StaticMethod("add_mfg_trust_anchor", &OCPki::add_mfg_trust_anchor),
        OCPki::StaticMethod("add_mfg_intermediate_cert", &OCPki::add_mfg_intermediate_cert),
        OCPki::StaticMethod("add_trust_anchor", &OCPki::add_trust_anchor),
        OCPki::StaticMethod("set_security_profile", &OCPki::set_security_profile),
    });
}

Napi::Value OCPki::add_mfg_cert(const Napi::CallbackInfo& info) { return N_oc_pki_add_mfg_cert(info); };
Napi::Value OCPki::add_mfg_trust_anchor(const Napi::CallbackInfo& info) { return N_oc_pki_add_mfg_trust_anchor(info); };
Napi::Value OCPki::add_mfg_intermediate_cert(const Napi::CallbackInfo& info) { return N_oc_pki_add_mfg_intermediate_cert(info); };
Napi::Value OCPki::add_trust_anchor(const Napi::CallbackInfo& info) { return N_oc_pki_add_trust_anchor(info); };
Napi::Value OCPki::set_security_profile(const Napi::CallbackInfo& info) { return N_oc_pki_set_security_profile(info); };
Napi::FunctionReference OCPki::constructor;

OCRandom::OCRandom(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCRandom::GetClass(Napi::Env env) {
    return DefineClass(env, "OCRandom", {
        OCRandom::StaticMethod("init", &OCRandom::init),
        OCRandom::StaticMethod("destroy", &OCRandom::destroy),
        OCRandom::StaticMethod("random_value", &OCRandom::random_value),
    });
}

Napi::Value OCRandom::init(const Napi::CallbackInfo& info) { return N_oc_random_init(info); };
Napi::Value OCRandom::destroy(const Napi::CallbackInfo& info) { return N_oc_random_destroy(info); };
Napi::Value OCRandom::random_value(const Napi::CallbackInfo& info) { return N_oc_random_value(info); };
Napi::FunctionReference OCRandom::constructor;

OCSessionEvents::OCSessionEvents(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCSessionEvents::GetClass(Napi::Env env) {
    return DefineClass(env, "OCSessionEvents", {
        OCSessionEvents::StaticMethod("start_event", &OCSessionEvents::start_event),
        OCSessionEvents::StaticMethod("end_event", &OCSessionEvents::end_event),
        OCSessionEvents::StaticMethod("set_event_delay", &OCSessionEvents::set_event_delay),
    });
}

Napi::Value OCSessionEvents::start_event(const Napi::CallbackInfo& info) { return N_oc_session_start_event(info); };
Napi::Value OCSessionEvents::end_event(const Napi::CallbackInfo& info) { return N_oc_session_end_event(info); };
Napi::Value OCSessionEvents::set_event_delay(const Napi::CallbackInfo& info) { return N_oc_session_events_set_event_delay(info); };
Napi::FunctionReference OCSessionEvents::constructor;

OCSoftwareUpdate::OCSoftwareUpdate(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCSoftwareUpdate::GetClass(Napi::Env env) {
    return DefineClass(env, "OCSoftwareUpdate", {
        OCSoftwareUpdate::StaticMethod("notify_downloaded", &OCSoftwareUpdate::notify_downloaded),
        OCSoftwareUpdate::StaticMethod("notify_upgrading", &OCSoftwareUpdate::notify_upgrading),
        OCSoftwareUpdate::StaticMethod("notify_done", &OCSoftwareUpdate::notify_done),
        OCSoftwareUpdate::StaticMethod("notify_new_version_available", &OCSoftwareUpdate::notify_new_version_available),
        OCSoftwareUpdate::StaticMethod("set_impl", &OCSoftwareUpdate::set_impl),
    });
}

Napi::Value OCSoftwareUpdate::notify_downloaded(const Napi::CallbackInfo& info) { return N_oc_swupdate_notify_downloaded(info); };
Napi::Value OCSoftwareUpdate::notify_upgrading(const Napi::CallbackInfo& info) { return N_oc_swupdate_notify_upgrading(info); };
Napi::Value OCSoftwareUpdate::notify_done(const Napi::CallbackInfo& info) { return N_oc_swupdate_notify_done(info); };
Napi::Value OCSoftwareUpdate::notify_new_version_available(const Napi::CallbackInfo& info) { return N_oc_swupdate_notify_new_version_available(info); };
Napi::Value OCSoftwareUpdate::set_impl(const Napi::CallbackInfo& info) { return N_oc_swupdate_set_impl(info); };
Napi::FunctionReference OCSoftwareUpdate::constructor;

OCStorage::OCStorage(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCStorage::GetClass(Napi::Env env) {
    return DefineClass(env, "OCStorage", {
        OCStorage::StaticMethod("storage_config", &OCStorage::storage_config),
    });
}

Napi::Value OCStorage::storage_config(const Napi::CallbackInfo& info) { return N_oc_storage_config(info); };
Napi::FunctionReference OCStorage::constructor;

OCUuidUtil::OCUuidUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCUuidUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCUuidUtil", {
        OCUuidUtil::StaticMethod("str_to_uuid", &OCUuidUtil::str_to_uuid),
        OCUuidUtil::StaticMethod("uuid_to_str", &OCUuidUtil::uuid_to_str),
        OCUuidUtil::StaticMethod("gen_uuid", &OCUuidUtil::gen_uuid),
    });
}

Napi::Value OCUuidUtil::str_to_uuid(const Napi::CallbackInfo& info) { return N_oc_str_to_uuid(info); };
Napi::Value OCUuidUtil::uuid_to_str(const Napi::CallbackInfo& info) { return N_oc_uuid_to_str(info); };
Napi::Value OCUuidUtil::gen_uuid(const Napi::CallbackInfo& info) { return N_oc_gen_uuid(info); };
Napi::FunctionReference OCUuidUtil::constructor;

OCCoreRes::OCCoreRes(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCoreRes::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCoreRes", {
        OCCoreRes::StaticMethod("init", &OCCoreRes::init),
        OCCoreRes::StaticMethod("init_platform", &OCCoreRes::init_platform),
        OCCoreRes::StaticMethod("shutdown", &OCCoreRes::shutdown),
        OCCoreRes::StaticMethod("get_num_devices", &OCCoreRes::get_num_devices),
        OCCoreRes::StaticMethod("get_device_id", &OCCoreRes::get_device_id),
        OCCoreRes::StaticMethod("get_device_info", &OCCoreRes::get_device_info),
        OCCoreRes::StaticMethod("get_platform_info", &OCCoreRes::get_platform_info),
        OCCoreRes::StaticMethod("get_resource_by_uri", &OCCoreRes::get_resource_by_uri),
        OCCoreRes::StaticMethod("filter_resource_by_rt", &OCCoreRes::filter_resource_by_rt),
        OCCoreRes::StaticMethod("is_DCR", &OCCoreRes::is_DCR),
        OCCoreRes::StaticMethod("set_latency", &OCCoreRes::set_latency),
        OCCoreRes::StaticMethod("get_latency", &OCCoreRes::get_latency),
        OCCoreRes::StaticMethod("add_new_device", &OCCoreRes::add_new_device),
    });
}

Napi::Value OCCoreRes::init(const Napi::CallbackInfo& info) { return N_oc_core_init(info); };
Napi::Value OCCoreRes::init_platform(const Napi::CallbackInfo& info) { return N_oc_core_init_platform(info); };
Napi::Value OCCoreRes::shutdown(const Napi::CallbackInfo& info) { return N_oc_core_shutdown(info); };
Napi::Value OCCoreRes::get_num_devices(const Napi::CallbackInfo& info) { return N_oc_core_get_num_devices(info); };
Napi::Value OCCoreRes::get_device_id(const Napi::CallbackInfo& info) { return N_oc_core_get_device_id(info); };
Napi::Value OCCoreRes::get_device_info(const Napi::CallbackInfo& info) { return N_oc_core_get_device_info(info); };
Napi::Value OCCoreRes::get_platform_info(const Napi::CallbackInfo& info) { return N_oc_core_get_platform_info(info); };
Napi::Value OCCoreRes::get_resource_by_uri(const Napi::CallbackInfo& info) { return N_oc_core_get_resource_by_uri(info); };
Napi::Value OCCoreRes::filter_resource_by_rt(const Napi::CallbackInfo& info) { return N_oc_filter_resource_by_rt(info); };
Napi::Value OCCoreRes::is_DCR(const Napi::CallbackInfo& info) { return N_oc_core_is_DCR(info); };
Napi::Value OCCoreRes::set_latency(const Napi::CallbackInfo& info) { return N_oc_core_set_latency(info); };
Napi::Value OCCoreRes::get_latency(const Napi::CallbackInfo& info) { return N_oc_core_get_latency(info); };
Napi::Value OCCoreRes::add_new_device(const Napi::CallbackInfo& info) { return N_oc_core_add_new_device(info); };
Napi::FunctionReference OCCoreRes::constructor;

OCRep::OCRep(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCRep::GetClass(Napi::Env env) {
    return DefineClass(env, "OCRep", {
        OCRep::StaticMethod("add_boolean", &OCRep::add_boolean),
        OCRep::StaticMethod("add_byte_string", &OCRep::add_byte_string),
        OCRep::StaticMethod("add_double", &OCRep::add_double),
        OCRep::StaticMethod("add_text_string", &OCRep::add_text_string),
        OCRep::StaticMethod("start_array", &OCRep::start_array),
        OCRep::StaticMethod("start_links_array", &OCRep::start_links_array),
        OCRep::StaticMethod("start_object", &OCRep::start_object),
        OCRep::StaticMethod("start_root_object", &OCRep::start_root_object),
        OCRep::StaticMethod("clear_cbor_errno", &OCRep::clear_cbor_errno),
        OCRep::StaticMethod("close_array", &OCRep::close_array),
        OCRep::StaticMethod("close_object", &OCRep::close_object),
        OCRep::StaticMethod("delete_buffer", &OCRep::delete_buffer),
        OCRep::StaticMethod("end_array", &OCRep::end_array),
        OCRep::StaticMethod("end_links_array", &OCRep::end_links_array),
        OCRep::StaticMethod("end_object", &OCRep::end_object),
        OCRep::StaticMethod("end_root_object", &OCRep::end_root_object),
        OCRep::StaticMethod("get_bool", &OCRep::get_bool),
        OCRep::StaticMethod("get_bool_array", &OCRep::get_bool_array),
        OCRep::StaticMethod("get_byte_string", &OCRep::get_byte_string),
        OCRep::StaticMethod("get_byte_string_array", &OCRep::get_byte_string_array),
        OCRep::StaticMethod("get_cbor_errno", &OCRep::get_cbor_errno),
        OCRep::StaticMethod("get_double", &OCRep::get_double),
        OCRep::StaticMethod("get_double_array", &OCRep::get_double_array),
        OCRep::StaticMethod("get_object", &OCRep::get_object),
        OCRep::StaticMethod("get_object_array", &OCRep::get_object_array),
        OCRep::StaticMethod("get_rep_from_root_object", &OCRep::get_rep_from_root_object),
        OCRep::StaticMethod("get_string", &OCRep::get_string),
        OCRep::StaticMethod("get_string_array", &OCRep::get_string_array),
        OCRep::StaticMethod("new_buffer", &OCRep::new_buffer),
        OCRep::StaticMethod("object_array_start_item", &OCRep::object_array_start_item),
        OCRep::StaticMethod("object_array_end_item", &OCRep::object_array_end_item),
        OCRep::StaticMethod("oc_array_to_bool_array", &OCRep::oc_array_to_bool_array),
        OCRep::StaticMethod("oc_array_to_double_array", &OCRep::oc_array_to_double_array),
        OCRep::StaticMethod("oc_array_to_int_array", &OCRep::oc_array_to_int_array),
        OCRep::StaticMethod("oc_array_to_string_array", &OCRep::oc_array_to_string_array),
        OCRep::StaticMethod("open_array", &OCRep::open_array),
        OCRep::StaticMethod("open_object", &OCRep::open_object),
        OCRep::StaticMethod("set_boolean", &OCRep::set_boolean),
        OCRep::StaticMethod("set_bool_array", &OCRep::set_bool_array),
        OCRep::StaticMethod("set_byte_string", &OCRep::set_byte_string),
        OCRep::StaticMethod("set_double", &OCRep::set_double),
        OCRep::StaticMethod("set_double_array", &OCRep::set_double_array),
        OCRep::StaticMethod("set_key", &OCRep::set_key),
        OCRep::StaticMethod("set_long", &OCRep::set_long),
        OCRep::StaticMethod("set_long_array", &OCRep::set_long_array),
        OCRep::StaticMethod("set_string_array", &OCRep::set_string_array),
        OCRep::StaticMethod("set_text_string", &OCRep::set_text_string),
        OCRep::StaticMethod("set_uint", &OCRep::set_uint),
        OCRep::StaticMethod("to_json", &OCRep::to_json),
    });
}

Napi::Value OCRep::add_boolean(const Napi::CallbackInfo& info) { return N_helper_rep_add_boolean(info); };
Napi::Value OCRep::add_byte_string(const Napi::CallbackInfo& info) { return N_helper_rep_add_byte_string(info); };
Napi::Value OCRep::add_double(const Napi::CallbackInfo& info) { return N_helper_rep_add_double(info); };
Napi::Value OCRep::add_text_string(const Napi::CallbackInfo& info) { return N_helper_rep_add_text_string(info); };
Napi::Value OCRep::start_array(const Napi::CallbackInfo& info) { return N_helper_rep_start_array(info); };
Napi::Value OCRep::start_links_array(const Napi::CallbackInfo& info) { return N_helper_rep_start_links_array(info); };
Napi::Value OCRep::start_object(const Napi::CallbackInfo& info) { return N_helper_rep_start_object(info); };
Napi::Value OCRep::start_root_object(const Napi::CallbackInfo& info) { return N_helper_rep_start_root_object(info); };
Napi::Value OCRep::clear_cbor_errno(const Napi::CallbackInfo& info) { return N_helper_rep_clear_cbor_errno(info); };
Napi::Value OCRep::close_array(const Napi::CallbackInfo& info) { return N_helper_rep_close_array(info); };
Napi::Value OCRep::close_object(const Napi::CallbackInfo& info) { return N_helper_rep_close_object(info); };
Napi::Value OCRep::delete_buffer(const Napi::CallbackInfo& info) { return N_helper_rep_delete_buffer(info); };
Napi::Value OCRep::end_array(const Napi::CallbackInfo& info) { return N_helper_rep_end_array(info); };
Napi::Value OCRep::end_links_array(const Napi::CallbackInfo& info) { return N_helper_rep_end_links_array(info); };
Napi::Value OCRep::end_object(const Napi::CallbackInfo& info) { return N_helper_rep_end_object(info); };
Napi::Value OCRep::end_root_object(const Napi::CallbackInfo& info) { return N_helper_rep_end_root_object(info); };
Napi::Value OCRep::get_bool(const Napi::CallbackInfo& info) { return N_oc_rep_get_bool(info); };
Napi::Value OCRep::get_bool_array(const Napi::CallbackInfo& info) { return N_oc_rep_get_bool_array(info); };
Napi::Value OCRep::get_byte_string(const Napi::CallbackInfo& info) { return N_oc_rep_get_byte_string(info); };
Napi::Value OCRep::get_byte_string_array(const Napi::CallbackInfo& info) { return N_oc_rep_get_byte_string_array(info); };
Napi::Value OCRep::get_cbor_errno(const Napi::CallbackInfo& info) { return N_oc_rep_get_cbor_errno(info); };
Napi::Value OCRep::get_double(const Napi::CallbackInfo& info) { return N_oc_rep_get_double(info); };
Napi::Value OCRep::get_double_array(const Napi::CallbackInfo& info) { return N_oc_rep_get_double_array(info); };
Napi::Value OCRep::get_object(const Napi::CallbackInfo& info) { return N_oc_rep_get_object(info); };
Napi::Value OCRep::get_object_array(const Napi::CallbackInfo& info) { return N_oc_rep_get_object_array(info); };
Napi::Value OCRep::get_rep_from_root_object(const Napi::CallbackInfo& info) { return N_helper_rep_get_rep_from_root_object(info); };
Napi::Value OCRep::get_string(const Napi::CallbackInfo& info) { return N_oc_rep_get_string(info); };
Napi::Value OCRep::get_string_array(const Napi::CallbackInfo& info) { return N_oc_rep_get_string_array(info); };
Napi::Value OCRep::new_buffer(const Napi::CallbackInfo& info) { return N_helper_rep_new_buffer(info); };
Napi::Value OCRep::object_array_start_item(const Napi::CallbackInfo& info) { return N_helper_rep_object_array_start_item(info); };
Napi::Value OCRep::object_array_end_item(const Napi::CallbackInfo& info) { return N_helper_rep_object_array_end_item(info); };
Napi::Value OCRep::oc_array_to_bool_array(const Napi::CallbackInfo& info) { return N_helper_rep_oc_array_to_bool_array(info); };
Napi::Value OCRep::oc_array_to_double_array(const Napi::CallbackInfo& info) { return N_helper_rep_oc_array_to_double_array(info); };
Napi::Value OCRep::oc_array_to_int_array(const Napi::CallbackInfo& info) { return N_helper_rep_oc_array_to_int_array(info); };
Napi::Value OCRep::oc_array_to_string_array(const Napi::CallbackInfo& info) { return N_helper_rep_oc_array_to_string_array(info); };
Napi::Value OCRep::open_array(const Napi::CallbackInfo& info) { return N_helper_rep_open_array(info); };
Napi::Value OCRep::open_object(const Napi::CallbackInfo& info) { return N_helper_rep_open_object(info); };
Napi::Value OCRep::set_boolean(const Napi::CallbackInfo& info) { return N_helper_rep_set_boolean(info); };
Napi::Value OCRep::set_bool_array(const Napi::CallbackInfo& info) { return N_helper_rep_set_bool_array(info); };
Napi::Value OCRep::set_byte_string(const Napi::CallbackInfo& info) { return N_helper_rep_set_byte_string(info); };
Napi::Value OCRep::set_double(const Napi::CallbackInfo& info) { return N_helper_rep_set_double(info); };
Napi::Value OCRep::set_double_array(const Napi::CallbackInfo& info) { return N_helper_rep_set_double_array(info); };
Napi::Value OCRep::set_key(const Napi::CallbackInfo& info) { return N_helper_rep_set_key(info); };
Napi::Value OCRep::set_long(const Napi::CallbackInfo& info) { return N_helper_rep_set_long(info); };
Napi::Value OCRep::set_long_array(const Napi::CallbackInfo& info) { return N_helper_rep_set_long_array(info); };
Napi::Value OCRep::set_string_array(const Napi::CallbackInfo& info) { return N_helper_rep_rep_set_string_array(info); };
Napi::Value OCRep::set_text_string(const Napi::CallbackInfo& info) { return N_helper_rep_set_text_string(info); };
Napi::Value OCRep::set_uint(const Napi::CallbackInfo& info) { return N_helper_rep_set_uint(info); };
Napi::Value OCRep::to_json(const Napi::CallbackInfo& info) { return N_oc_rep_to_json(info); };
Napi::FunctionReference OCRep::constructor;

