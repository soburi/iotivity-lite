#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>
#include <memory>

using namespace std;

class OCMain : public Napi::ObjectWrap<OCMain>
{
public:
  OCMain(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCMain::add_collection(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::add_device(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::add_ownership_status_cb(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::add_resource(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::assert_all_roles(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::assert_role(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::auto_assert_roles(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::close_session(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::collection_add_link(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::collection_add_mandatory_rt(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::collection_add_supported_rt(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::collection_get_collections(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::collection_get_links(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::collection_remove_link(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::delete_collection(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::delete_link(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::delete_resource(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::device_bind_resource_type(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_delete(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_get(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_ip_discovery(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_ip_discovery_all(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_ip_multicast(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_observe(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_post(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_put(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_realm_local_ipv6_discovery(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_realm_local_ipv6_multicast(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_site_local_ipv6_discovery(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_site_local_ipv6_discovery_all(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::do_site_local_ipv6_multicast(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::free_server_endpoints(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::get_all_roles(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::get_con_res_announced(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::ignore_request(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::indicate_separate_response(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::init_platform(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::init_post(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::init_put(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::is_owned_device(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::link_add_link_param(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::link_add_rel(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::main_init(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::main_shutdown(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::new_collection(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::new_link(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::new_resource(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::notify_observers(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::process_baseline_interface(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::remove_delayed_callback(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::remove_ownership_status_cb(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::reset(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::reset_device(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_bind_resource_interface(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_bind_resource_type(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_make_public(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_set_default_interface(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_set_discoverable(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_set_observable(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_set_periodic_observable(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_set_properties_cbs(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::resource_set_request_handler(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::ri_is_app_resource_valid(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::send_diagnostic_message(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::send_ping(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::send_response(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::send_response_raw(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::send_separate_response(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::set_con_res_announced(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::set_con_write_cb(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::set_delayed_callback(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::set_factory_presets_cb(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::set_random_pin_callback(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::set_separate_response_buffer(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::stop_multicast(const Napi::CallbackInfo& info);
  static Napi::Value OCMain::stop_observe(const Napi::CallbackInfo& info);
};
class OCObt : public Napi::ObjectWrap<OCObt>
{
public:
  OCObt(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCObt::ace_add_permission(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::ace_new_resource(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::ace_resource_set_href(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::ace_resource_set_wc(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::add_roleid(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::delete_ace_by_aceid(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::delete_cred_by_credid(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::delete_own_cred_by_credid(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::device_hard_reset(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_all_resources(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_owned_devices(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_owned_devices_realm_local_ipv6(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_owned_devices_site_local_ipv6(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_unowned_devices(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_unowned_devices_realm_local_ipv6(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::discover_unowned_devices_site_local_ipv6(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::free_ace(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::free_acl(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::free_creds(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::free_roleid(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::init(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::new_ace_for_connection(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::new_ace_for_role(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::new_ace_for_subject(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::perform_cert_otm(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::perform_just_works_otm(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::perform_random_pin_otm(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::provision_ace(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::provision_auth_wildcard_ace(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::provision_identity_certificate(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::provision_pairwise_credentials(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::provision_role_certificate(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::provision_role_wildcard_ace(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::request_random_pin(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::retrieve_acl(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::retrieve_creds(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::retrieve_own_creds(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::set_sd_info(const Napi::CallbackInfo& info);
  static Napi::Value OCObt::shutdown(const Napi::CallbackInfo& info);
};
class OCBufferSettings : public Napi::ObjectWrap<OCBufferSettings>
{
public:
  OCBufferSettings(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCBufferSettings::set_mtu_size(const Napi::CallbackInfo& info);
  static Napi::Value OCBufferSettings::get_mtu_size(const Napi::CallbackInfo& info);
  static Napi::Value OCBufferSettings::set_max_app_data_size(const Napi::CallbackInfo& info);
  static Napi::Value OCBufferSettings::get_max_app_data_size(const Napi::CallbackInfo& info);
  static Napi::Value OCBufferSettings::get_block_size(const Napi::CallbackInfo& info);
};
class OCClock : public Napi::ObjectWrap<OCClock>
{
public:
  OCClock(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCClock::clock_init(const Napi::CallbackInfo& info);
  static Napi::Value OCClock::clock_time(const Napi::CallbackInfo& info);
  static Napi::Value OCClock::clock_seconds(const Napi::CallbackInfo& info);
  static Napi::Value OCClock::clock_wait(const Napi::CallbackInfo& info);
};
class OCCloud : public Napi::ObjectWrap<OCCloud>
{
public:
  OCCloud(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCCloud::get_context(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::manager_start(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::manager_stop(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::login(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::logout(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::refresh_token(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::get_token_expiry(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::add_resource(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::delete_resource(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::publish_resources(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::discover_resources(const Napi::CallbackInfo& info);
  static Napi::Value OCCloud::provision_conf_resource(const Napi::CallbackInfo& info);
};
class OCCredUtil : public Napi::ObjectWrap<OCCredUtil>
{
public:
  OCCredUtil(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCCredUtil::read_credusage(const Napi::CallbackInfo& info);
  static Napi::Value OCCredUtil::read_encoding(const Napi::CallbackInfo& info);
  static Napi::Value OCCredUtil::parse_credusage(const Napi::CallbackInfo& info);
  static Napi::Value OCCredUtil::parse_encoding(const Napi::CallbackInfo& info);
  static Napi::Value OCCredUtil::credtype_string(const Napi::CallbackInfo& info);
};
class OCEndpointUtil : public Napi::ObjectWrap<OCEndpointUtil>
{
public:
  OCEndpointUtil(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCEndpointUtil::to_string(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::compare(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::copy(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::free_endpoint(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::string_to_endpoint(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::new_endpoint(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::endpoint_string_parse_path(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::set_di(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::ipv6_endpoint_is_link_local(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::compare_address(const Napi::CallbackInfo& info);
  static Napi::Value OCEndpointUtil::set_local_address(const Napi::CallbackInfo& info);
};
class OCEnumUtil : public Napi::ObjectWrap<OCEnumUtil>
{
public:
  OCEnumUtil(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCEnumUtil::enum_to_str(const Napi::CallbackInfo& info);
  static Napi::Value OCEnumUtil::pos_desc_to_str(const Napi::CallbackInfo& info);
};
class OCIntrospection : public Napi::ObjectWrap<OCIntrospection>
{
public:
  OCIntrospection(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCIntrospection::set_introspection_data(const Napi::CallbackInfo& info);
};
class OCPki : public Napi::ObjectWrap<OCPki>
{
public:
  OCPki(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCPki::add_mfg_cert(const Napi::CallbackInfo& info);
  static Napi::Value OCPki::add_mfg_trust_anchor(const Napi::CallbackInfo& info);
  static Napi::Value OCPki::add_mfg_intermediate_cert(const Napi::CallbackInfo& info);
  static Napi::Value OCPki::add_trust_anchor(const Napi::CallbackInfo& info);
  static Napi::Value OCPki::set_security_profile(const Napi::CallbackInfo& info);
};
class OCRandom : public Napi::ObjectWrap<OCRandom>
{
public:
  OCRandom(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCRandom::init(const Napi::CallbackInfo& info);
  static Napi::Value OCRandom::destroy(const Napi::CallbackInfo& info);
  static Napi::Value OCRandom::random_value(const Napi::CallbackInfo& info);
};
class OCSessionEvents : public Napi::ObjectWrap<OCSessionEvents>
{
public:
  OCSessionEvents(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCSessionEvents::start_event(const Napi::CallbackInfo& info);
  static Napi::Value OCSessionEvents::end_event(const Napi::CallbackInfo& info);
  static Napi::Value OCSessionEvents::set_event_delay(const Napi::CallbackInfo& info);
};
class OCSoftwareUpdate : public Napi::ObjectWrap<OCSoftwareUpdate>
{
public:
  OCSoftwareUpdate(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCSoftwareUpdate::notify_downloaded(const Napi::CallbackInfo& info);
  static Napi::Value OCSoftwareUpdate::notify_upgrading(const Napi::CallbackInfo& info);
  static Napi::Value OCSoftwareUpdate::notify_done(const Napi::CallbackInfo& info);
  static Napi::Value OCSoftwareUpdate::notify_new_version_available(const Napi::CallbackInfo& info);
  static Napi::Value OCSoftwareUpdate::set_impl(const Napi::CallbackInfo& info);
};
class OCStorage : public Napi::ObjectWrap<OCStorage>
{
public:
  OCStorage(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCStorage::storage_config(const Napi::CallbackInfo& info);
};
class OCUuidUtil : public Napi::ObjectWrap<OCUuidUtil>
{
public:
  OCUuidUtil(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCUuidUtil::str_to_uuid(const Napi::CallbackInfo& info);
  static Napi::Value OCUuidUtil::uuid_to_str(const Napi::CallbackInfo& info);
  static Napi::Value OCUuidUtil::gen_uuid(const Napi::CallbackInfo& info);
};
class OCCoreRes : public Napi::ObjectWrap<OCCoreRes>
{
public:
  OCCoreRes(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCCoreRes::init(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::init_platform(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::shutdown(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::get_num_devices(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::get_device_id(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::get_device_info(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::get_platform_info(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::get_resource_by_uri(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::filter_resource_by_rt(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::is_DCR(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::set_latency(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::get_latency(const Napi::CallbackInfo& info);
  static Napi::Value OCCoreRes::add_new_device(const Napi::CallbackInfo& info);
};
class OCRep : public Napi::ObjectWrap<OCRep>
{
public:
  OCRep(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  static Napi::Value OCRep::add_boolean(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::add_byte_string(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::add_double(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::add_long(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::add_text_string(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::begin_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::begin_links_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::begin_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::begin_root_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::clear_cbor_errno(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::close_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::close_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::delete_buffer(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::end_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::end_links_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::end_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::end_root_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_boolean(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_boolean_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_byte_string(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_byte_string_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_cbor_errno(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_double(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_double_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_long(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_long_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_object_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_o_c_representaion_from_root_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_string(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::get_string_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::new_buffer(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::object_array_begin_item(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::object_array_end_item(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::oc_array_to_boolean_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::oc_array_to_double_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::oc_array_to_long_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::oc_array_to_string_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::open_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::open_object(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_boolean(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_boolean_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_byte_string(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_double(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_double_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_key(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_long(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_long_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_string_array(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_text_string(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::set_unsigned_int(const Napi::CallbackInfo& info);
  static Napi::Value OCRep::to_json(const Napi::CallbackInfo& info);
};
