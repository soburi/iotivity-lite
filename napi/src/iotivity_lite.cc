#include "iotivity_lite.h"
#include "structs.h"
#include "functions.h"
using namespace Napi;

IotivityLite::IotivityLite(const Napi::CallbackInfo& info) : ObjectWrap(info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "You need to name yourself")
          .ThrowAsJavaScriptException();
        return;
    }

    //XOCUuid* uuid = new XOCUuid(info);
    this->_greeterName = info[0].As<Napi::String>().Utf8Value();
}

Napi::FunctionReference IotivityLite::callback_helper;

Napi::Value IotivityLite::Callback(const Napi::CallbackInfo& info) {
	OCIPv4Addr* ipv4 = OCIPv4Addr::Unwrap(info[0].As<Object>());
printf("Unwrap %p\n", ipv4);

	Napi::Function func = info[0].As<Napi::Function>();

	IotivityLite::callback_helper = Napi::Persistent(func);
	IotivityLite::callback_helper.SuppressDestruct();

	callback_helper.Call({});

	return info.Env().Null();
}

Napi::Value IotivityLite::Greet(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1) {
        Napi::TypeError::New(env, "Wrong number of arguments")
          .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (!info[0].IsString()) {
        Napi::TypeError::New(env, "You need to introduce yourself to greet")
          .ThrowAsJavaScriptException();
        return env.Null();
    }

    Napi::String name = info[0].As<Napi::String>();

    printf("Hello %s\n", name.Utf8Value().c_str());
    printf("I am %s\n", this->_greeterName.c_str());

    return Napi::String::New(env, this->_greeterName);
}

Napi::Function IotivityLite::GetClass(Napi::Env env) {
    return DefineClass(env, "IotivityLite", {
        IotivityLite::InstanceAccessor("device", &IotivityLite::GetDevice, &IotivityLite::SetDevice),
        IotivityLite::InstanceAccessor("di", &IotivityLite::GetDi, &IotivityLite::SetDi),
        IotivityLite::InstanceAccessor("greet", &IotivityLite::Greet, nullptr),
        IotivityLite::InstanceMethod("callback", &IotivityLite::Callback),
    });
}

Napi::Value IotivityLite::GetDevice(const Napi::CallbackInfo& info) {
    printf("GetDevice\n");
    Napi::Env env = info.Env();
    //XOCUuid* uuid = new XOCUuid(info);
    return Napi::Number::New(env, endpoint.device);
}

void IotivityLite::SetDevice(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDevice\n");
}

Napi::Value IotivityLite::GetDi(const Napi::CallbackInfo& info) {
    printf("GetDi\n");
    //Napi::Env env = info.Env();
    //Object obj = Object::New(env);
    //XOCUuid* uuid = new XOCUuid(env, obj);
    //return XOCUuid::constructor.New({});
    return Napi::Number::New(info.Env(), 0);
}

void IotivityLite::SetDi(const Napi::CallbackInfo& info, const Napi::Value& val) {
    printf("SetDi\n");
}

OCMain::OCMain(const Napi::CallbackInfo& info) : ObjectWrap(info) { }
Napi::Value OCMain::add_collection(const Napi::CallbackInfo& info) { return N_oc_add_collection(info); }
Napi::Value OCMain::add_device(const Napi::CallbackInfo& info) { return N_oc_add_device(info); }
Napi::Value OCMain::add_ownership_status_cb(const Napi::CallbackInfo& info) { return N_oc_add_ownership_status_cb(info); }
Napi::Value OCMain::add_resource(const Napi::CallbackInfo& info) { return N_oc_add_resource(info); }
Napi::Value OCMain::assert_all_roles(const Napi::CallbackInfo& info) { return N_oc_assert_all_roles(info); }
Napi::Value OCMain::assert_role(const Napi::CallbackInfo& info) { return N_oc_assert_role(info); }
Napi::Value OCMain::auto_assert_roles(const Napi::CallbackInfo& info) { return N_oc_auto_assert_roles(info); }
Napi::Value OCMain::close_session(const Napi::CallbackInfo& info) { return N_oc_close_session(info); }
Napi::Value OCMain::collection_add_link(const Napi::CallbackInfo& info) { return N_oc_collection_add_link(info); }
Napi::Value OCMain::collection_add_mandatory_rt(const Napi::CallbackInfo& info) { return N_oc_collection_add_mandatory_rt(info); }
Napi::Value OCMain::collection_add_supported_rt(const Napi::CallbackInfo& info) { return N_oc_collection_add_supported_rt(info); }
Napi::Value OCMain::collection_get_collections(const Napi::CallbackInfo& info) { return N_oc_collection_get_collections(info); }
Napi::Value OCMain::collection_get_links(const Napi::CallbackInfo& info) { return N_oc_collection_get_links(info); }
Napi::Value OCMain::collection_remove_link(const Napi::CallbackInfo& info) { return N_oc_collection_remove_link(info); }
Napi::Value OCMain::delete_collection(const Napi::CallbackInfo& info) { return N_oc_delete_collection(info); }
Napi::Value OCMain::delete_link(const Napi::CallbackInfo& info) { return N_oc_delete_link(info); }
Napi::Value OCMain::delete_resource(const Napi::CallbackInfo& info) { return N_oc_delete_resource(info); }
Napi::Value OCMain::device_bind_resource_type(const Napi::CallbackInfo& info) { return N_oc_device_bind_resource_type(info); }
Napi::Value OCMain::do_delete(const Napi::CallbackInfo& info) { return N_oc_do_delete(info); }
Napi::Value OCMain::do_get(const Napi::CallbackInfo& info) { return N_oc_do_get(info); }
Napi::Value OCMain::do_ip_discovery(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery(info); }
Napi::Value OCMain::do_ip_discovery_all(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery_all(info); }
Napi::Value OCMain::do_ip_discovery_all_at_endpoint(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery_all_at_endpoint(info); }
Napi::Value OCMain::do_ip_discovery_at_endpoint(const Napi::CallbackInfo& info) { return N_oc_do_ip_discovery_at_endpoint(info); }
Napi::Value OCMain::do_ip_multicast(const Napi::CallbackInfo& info) { return N_oc_do_ip_multicast(info); }
Napi::Value OCMain::do_observe(const Napi::CallbackInfo& info) { return N_oc_do_observe(info); }
Napi::Value OCMain::do_post(const Napi::CallbackInfo& info) { return N_oc_do_post(info); }
Napi::Value OCMain::do_put(const Napi::CallbackInfo& info) { return N_oc_do_put(info); }
Napi::Value OCMain::do_realm_local_ipv6_discovery(const Napi::CallbackInfo& info) { return N_oc_do_realm_local_ipv6_discovery(info); }
Napi::Value OCMain::do_realm_local_ipv6_discovery_all(const Napi::CallbackInfo& info) { return N_oc_do_realm_local_ipv6_discovery_all(info); }
Napi::Value OCMain::do_realm_local_ipv6_multicast(const Napi::CallbackInfo& info) { return N_oc_do_realm_local_ipv6_multicast(info); }
Napi::Value OCMain::do_site_local_ipv6_discovery(const Napi::CallbackInfo& info) { return N_oc_do_site_local_ipv6_discovery(info); }
Napi::Value OCMain::do_site_local_ipv6_discovery_all(const Napi::CallbackInfo& info) { return N_oc_do_site_local_ipv6_discovery_all(info); }
Napi::Value OCMain::do_site_local_ipv6_multicast(const Napi::CallbackInfo& info) { return N_oc_do_site_local_ipv6_multicast(info); }
Napi::Value OCMain::free_server_endpoints(const Napi::CallbackInfo& info) { return N_oc_free_server_endpoints(info); }
Napi::Value OCMain::get_all_roles(const Napi::CallbackInfo& info) { return N_oc_get_all_roles(info); }
Napi::Value OCMain::get_con_res_announced(const Napi::CallbackInfo& info) { return N_oc_get_con_res_announced(info); }
#if defined(XXX)
Napi::Value OCMain::get_diagnostic_message(const Napi::CallbackInfo& info) { return N_oc_get_diagnostic_message(info); }
Napi::Value OCMain::get_request_payload_raw(const Napi::CallbackInfo& info) { return N_oc_get_request_payload_raw(info); }
Napi::Value OCMain::get_response_payload_raw(const Napi::CallbackInfo& info) { return N_oc_get_response_payload_raw(info); }
#endif
Napi::Value OCMain::ignore_request(const Napi::CallbackInfo& info) { return N_oc_ignore_request(info); }
Napi::Value OCMain::indicate_separate_response(const Napi::CallbackInfo& info) { return N_oc_indicate_separate_response(info); }
Napi::Value OCMain::init_platform(const Napi::CallbackInfo& info) { return N_oc_init_platform(info); }
Napi::Value OCMain::init_post(const Napi::CallbackInfo& info) { return N_oc_init_post(info); }
Napi::Value OCMain::init_put(const Napi::CallbackInfo& info) { return N_oc_init_put(info); }
Napi::Value OCMain::is_owned_device(const Napi::CallbackInfo& info) { return N_oc_is_owned_device(info); }
Napi::Value OCMain::link_add_link_param(const Napi::CallbackInfo& info) { return N_oc_link_add_link_param(info); }
Napi::Value OCMain::link_add_rel(const Napi::CallbackInfo& info) { return N_oc_link_add_rel(info); }
Napi::Value OCMain::main_init(const Napi::CallbackInfo& info) { return N_oc_main_init(info); }
Napi::Value OCMain::main_shutdown(const Napi::CallbackInfo& info) { return N_oc_main_shutdown(info); }
Napi::Value OCMain::new_collection(const Napi::CallbackInfo& info) { return N_oc_new_collection(info); }
Napi::Value OCMain::new_link(const Napi::CallbackInfo& info) { return N_oc_new_link(info); }
Napi::Value OCMain::new_resource(const Napi::CallbackInfo& info) { return N_oc_new_resource(info); }
Napi::Value OCMain::notify_observers(const Napi::CallbackInfo& info) { return N_oc_notify_observers(info); }
Napi::Value OCMain::process_baseline_interface(const Napi::CallbackInfo& info) { return N_oc_process_baseline_interface(info); }
Napi::Value OCMain::remove_delayed_callback(const Napi::CallbackInfo& info) { return N_oc_remove_delayed_callback(info); }
Napi::Value OCMain::remove_ownership_status_cb(const Napi::CallbackInfo& info) { return N_oc_remove_ownership_status_cb(info); }
Napi::Value OCMain::reset(const Napi::CallbackInfo& info) { return N_oc_reset(info); }
Napi::Value OCMain::reset_device(const Napi::CallbackInfo& info) { return N_oc_reset_device(info); }
Napi::Value OCMain::resource_bind_resource_interface(const Napi::CallbackInfo& info) { return N_oc_resource_bind_resource_interface(info); }
Napi::Value OCMain::resource_bind_resource_type(const Napi::CallbackInfo& info) { return N_oc_resource_bind_resource_type(info); }
Napi::Value OCMain::resource_make_public(const Napi::CallbackInfo& info) { return N_oc_resource_make_public(info); }
Napi::Value OCMain::resource_set_default_interface(const Napi::CallbackInfo& info) { return N_oc_resource_set_default_interface(info); }
Napi::Value OCMain::resource_set_discoverable(const Napi::CallbackInfo& info) { return N_oc_resource_set_discoverable(info); }
Napi::Value OCMain::resource_set_observable(const Napi::CallbackInfo& info) { return N_oc_resource_set_observable(info); }
Napi::Value OCMain::resource_set_periodic_observable(const Napi::CallbackInfo& info) { return N_oc_resource_set_periodic_observable(info); }
Napi::Value OCMain::resource_set_properties_cbs(const Napi::CallbackInfo& info) { return N_oc_resource_set_properties_cbs(info); }
Napi::Value OCMain::resource_set_request_handler(const Napi::CallbackInfo& info) { return N_oc_resource_set_request_handler(info); }
Napi::Value OCMain::ri_is_app_resource_valid(const Napi::CallbackInfo& info) { return N_oc_ri_is_app_resource_valid(info); }
Napi::Value OCMain::send_diagnostic_message(const Napi::CallbackInfo& info) { return N_oc_send_diagnostic_message(info); }
Napi::Value OCMain::send_ping(const Napi::CallbackInfo& info) { return N_oc_send_ping(info); }
Napi::Value OCMain::send_response(const Napi::CallbackInfo& info) { return N_oc_send_response(info); }
Napi::Value OCMain::send_response_raw(const Napi::CallbackInfo& info) { return N_oc_send_response_raw(info); }
Napi::Value OCMain::send_separate_response(const Napi::CallbackInfo& info) { return N_oc_send_separate_response(info); }
Napi::Value OCMain::set_con_res_announced(const Napi::CallbackInfo& info) { return N_oc_set_con_res_announced(info); }
Napi::Value OCMain::set_con_write_cb(const Napi::CallbackInfo& info) { return N_oc_set_con_write_cb(info); }
Napi::Value OCMain::set_delayed_callback(const Napi::CallbackInfo& info) { return N_oc_set_delayed_callback(info); }
Napi::Value OCMain::set_factory_presets_cb(const Napi::CallbackInfo& info) { return N_oc_set_factory_presets_cb(info); }
Napi::Value OCMain::set_random_pin_callback(const Napi::CallbackInfo& info) { return N_oc_set_random_pin_callback(info); }
Napi::Value OCMain::set_separate_response_buffer(const Napi::CallbackInfo& info) { return N_oc_set_separate_response_buffer(info); }
Napi::Value OCMain::stop_multicast(const Napi::CallbackInfo& info) { return N_oc_stop_multicast(info); }
Napi::Value OCMain::stop_observe(const Napi::CallbackInfo& info) { return N_oc_stop_observe(info); }

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
#if defined(XXX)
        OCMain::StaticMethod("get_diagnostic_message", &OCMain::get_diagnostic_message),
        OCMain::StaticMethod("get_request_payload_raw", &OCMain::get_request_payload_raw),
        OCMain::StaticMethod("get_response_payload_raw", &OCMain::get_response_payload_raw),
#endif
        OCMain::StaticMethod("ignore_request", &OCMain::ignore_request),
        OCMain::StaticMethod("indicate_separate_response", &OCMain::indicate_separate_response),
        OCMain::StaticMethod("init_platform", &OCMain::init_platform),
        OCMain::StaticMethod("init_post", &OCMain::init_post),
        OCMain::StaticMethod("init_put", &OCMain::init_put),
        OCMain::StaticMethod("is_owned_device", &OCMain::is_owned_device),
        OCMain::StaticMethod("link_add_link_param", &OCMain::link_add_link_param),
        OCMain::StaticMethod("link_add_rel", &OCMain::link_add_rel),
        OCMain::StaticMethod("main_init", &OCMain::main_init),
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


Napi::Object module_init(Napi::Env env, Napi::Object exports);

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("IotivityLite", IotivityLite::GetClass(env));
    exports.Set("OCMain", OCMain::GetClass(env));
    return module_init(env, exports);
}

NODE_API_MODULE(addon, Init)

