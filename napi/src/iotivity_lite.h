#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>
#include <memory>

using namespace std;

class IotivityLite : public Napi::ObjectWrap<IotivityLite>
{
public:
    IotivityLite(const Napi::CallbackInfo&);
    Napi::Value Greet(const Napi::CallbackInfo&);

    Napi::Value Callback(const Napi::CallbackInfo&);

    Napi::Value GetDevice(const Napi::CallbackInfo&);
    void SetDevice(const Napi::CallbackInfo&, const Napi::Value&);

    Napi::Value GetDi(const Napi::CallbackInfo&);
    void SetDi(const Napi::CallbackInfo&, const Napi::Value&);

    static Napi::Function GetClass(Napi::Env);
    static Napi::FunctionReference callback_helper;

private:
    std::string _greeterName;
    oc_endpoint_t endpoint;
};

class OCMain : public Napi::ObjectWrap<OCMain>
{
public:
    OCMain(const Napi::CallbackInfo&);
    static Napi::Function GetClass(Napi::Env);
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
	static Napi::Value OCMain::get_diagnostic_message(const Napi::CallbackInfo& info);
	static Napi::Value OCMain::get_request_payload_raw(const Napi::CallbackInfo& info);
	static Napi::Value OCMain::get_response_payload_raw(const Napi::CallbackInfo& info);
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

