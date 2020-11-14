#include "iotivity_lite.h"
#include "structs.h"
#include "functions.h"
#include "helper.h"

using namespace std;
using namespace Napi;

Napi::Object module_init(Napi::Env env, Napi::Object exports);
Napi::Object Init(Napi::Env env, Napi::Object exports);
NODE_API_MODULE(addon, Init)

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("Clock", OCClock::GetClass(env));
    exports.Set("Cloud", OCCloud::GetClass(env));
    exports.Set("Collection", OCCollection::GetClass(env));
    exports.Set("Core", OCCore::GetClass(env));
    exports.Set("Cred", OCCred::GetClass(env));
    exports.Set("Endpoint", OCEndpoint::GetClass(env));
    exports.Set("EnumUtil", OCEnumUtil::GetClass(env));
    exports.Set("Introspection", OCIntrospection::GetClass(env));
    exports.Set("MemTrace", OCMemTrace::GetClass(env));
    exports.Set("Obt", OCObt::GetClass(env));
    exports.Set("Pki", OCPki::GetClass(env));
    exports.Set("Random", OCRandom::GetClass(env));
    exports.Set("Representation", OCRepresentation::GetClass(env));
    exports.Set("Resource", OCResource::GetClass(env));
    exports.Set("SWUpdate", OCSWUpdate::GetClass(env));
    exports.Set("Session", OCSession::GetClass(env));
    exports.Set("Storage", OCStorage::GetClass(env));
    exports.Set("Uuid", OCUuid::GetClass(env));
    return module_init(env, exports);
}
OCClock::OCClock(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCClock::GetClass(Napi::Env env) {
    return DefineClass(env, "OCClock", {
        StaticMethod("init", &OCClock::init),
        StaticMethod("time", &OCClock::time),
        StaticMethod("seconds", &OCClock::seconds),
        StaticMethod("wait", &OCClock::wait),
        StaticMethod("encode_time_refc3339", &OCClock::encode_time_refc3339),
        StaticMethod("parse_time_rfc3339", &OCClock::parse_time_rfc3339),
        StaticMethod("time_rfc3339", &OCClock::time_rfc3339),
    });
}
Napi::FunctionReference OCClock::constructor;


Value OCClock::init(const CallbackInfo& info) {
    (void)oc_clock_init();
    return info.Env().Undefined();
}

Value OCClock::time(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_clock_time());
}

Value OCClock::seconds(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_clock_seconds());
}

Value OCClock::wait(const CallbackInfo& info) {
    auto t = static_cast<uint64_t>(info[0].ToNumber().Int64Value());
    (void)oc_clock_wait(t);
    return info.Env().Undefined();
}

Value OCClock::encode_time_refc3339(const CallbackInfo& info) {
    auto time = static_cast<uint64_t>(info[0].ToNumber().Int64Value());
    auto out_buf_ = info[1].ToString().Utf8Value();
    auto out_buf = const_cast<char*>(out_buf_.c_str());
    auto out_buf_len = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_clock_encode_time_rfc3339(time, out_buf, out_buf_len));
}

Value OCClock::parse_time_rfc3339(const CallbackInfo& info) {
    auto in_buf_ = info[0].ToString().Utf8Value();
    auto in_buf = in_buf_.c_str();
    auto in_buf_len = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_clock_parse_time_rfc3339(in_buf, in_buf_len));
}

Value OCClock::time_rfc3339(const CallbackInfo& info) {
    auto out_buf_ = info[0].ToString().Utf8Value();
    auto out_buf = const_cast<char*>(out_buf_.c_str());
    auto out_buf_len = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_clock_time_rfc3339(out_buf, out_buf_len));
}

OCCloud::OCCloud(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCloud::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCloud", {
#if defined(OC_CLOUD)
        StaticMethod("get_context", &OCCloud::get_context),
#endif
#if defined(OC_CLOUD)
        StaticMethod("manager_start", &OCCloud::manager_start),
#endif
#if defined(OC_CLOUD)
        StaticMethod("manager_stop", &OCCloud::manager_stop),
#endif
#if defined(OC_CLOUD)
        StaticMethod("cloud_login", &OCCloud::cloud_login),
#endif
#if defined(OC_CLOUD)
        StaticMethod("cloud_logout", &OCCloud::cloud_logout),
#endif
#if defined(OC_CLOUD)
        StaticMethod("cloud_refresh_token", &OCCloud::cloud_refresh_token),
#endif
#if defined(OC_CLOUD)
        StaticMethod("get_token_expiry", &OCCloud::get_token_expiry),
#endif
#if defined(OC_CLOUD)
        StaticMethod("add_resource", &OCCloud::add_resource),
#endif
#if defined(OC_CLOUD)
        StaticMethod("delete_resource", &OCCloud::delete_resource),
#endif
#if defined(OC_CLOUD)
        StaticMethod("publish_resources", &OCCloud::publish_resources),
#endif
#if defined(OC_CLOUD)
        StaticMethod("discover_resources", &OCCloud::discover_resources),
#endif
#if defined(OC_CLOUD)
        StaticMethod("provision_conf_resource", &OCCloud::provision_conf_resource),
#endif
#if defined(OC_CLOUD)
        StaticMethod("cloud_register", &OCCloud::cloud_register),
#endif
#if defined(OC_CLOUD)
        StaticMethod("cloud_deregister", &OCCloud::cloud_deregister),
#endif
    });
}
Napi::FunctionReference OCCloud::constructor;


#if defined(OC_CLOUD)
Value OCCloud::get_context(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    shared_ptr<oc_cloud_context_t> sp(oc_cloud_get_context(device), nop_deleter);
    auto args = External<shared_ptr<oc_cloud_context_t>>::New(info.Env(), &sp);
    return OCCloudContext::constructor.New({args});
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::manager_start(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_cloud_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_cloud_manager_start(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::manager_stop(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_cloud_manager_stop(ctx));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::cloud_login(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_cloud_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_cloud_login(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::cloud_logout(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_cloud_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_cloud_logout(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::cloud_refresh_token(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_cloud_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_cloud_refresh_token(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::get_token_expiry(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_cloud_get_token_expiry(ctx));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::add_resource(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_cloud_add_resource(resource));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::delete_resource(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    (void)oc_cloud_delete_resource(resource);
    return info.Env().Undefined();
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::publish_resources(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_cloud_publish_resources(device));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::discover_resources(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_discovery_all_handler_t handler = nullptr;
    Function handler_ = info[1].As<Function>();
    void* user_data = info[2];
    return Number::New(info.Env(), oc_cloud_discover_resources(ctx, handler, user_data));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::provision_conf_resource(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    auto server_ = info[1].ToString().Utf8Value();
    auto server = server_.c_str();
    auto access_token_ = info[2].ToString().Utf8Value();
    auto access_token = access_token_.c_str();
    auto server_id_ = info[3].ToString().Utf8Value();
    auto server_id = server_id_.c_str();
    auto auth_provider_ = info[4].ToString().Utf8Value();
    auto auth_provider = auth_provider_.c_str();
    return Number::New(info.Env(), oc_cloud_provision_conf_resource(ctx, server, access_token, server_id, auth_provider));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::cloud_register(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_cloud_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_cloud_register(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Value OCCloud::cloud_deregister(const CallbackInfo& info) {
    auto& ctx = *OCCloudContext::Unwrap(info[0].ToObject());
    oc_cloud_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_cloud_deregister(ctx, cb, data));
}
#endif

OCCore::OCCore(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCCore::GetClass(Napi::Env env) {
    return DefineClass(env, "OCCore", {
        StaticMethod("init", &OCCore::init),
        StaticMethod("init_platform", &OCCore::init_platform),
        StaticMethod("shutdown", &OCCore::shutdown),
        StaticMethod("get_num_devices", &OCCore::get_num_devices),
        StaticMethod("get_device_id", &OCCore::get_device_id),
        StaticMethod("get_device_info", &OCCore::get_device_info),
        StaticMethod("get_platform_info", &OCCore::get_platform_info),
        StaticMethod("get_resource_by_uri", &OCCore::get_resource_by_uri),
        StaticMethod("filter_resource_by_rt", &OCCore::filter_resource_by_rt),
        StaticMethod("is_DCR", &OCCore::is_DCR),
        StaticMethod("set_latency", &OCCore::set_latency),
        StaticMethod("get_latency", &OCCore::get_latency),
        StaticMethod("add_new_device", &OCCore::add_new_device),
        StaticMethod("encode_interfaces_mask", &OCCore::encode_interfaces_mask),
        StaticMethod("get_resource_by_index", &OCCore::get_resource_by_index),
        StaticMethod("populate_resource", &OCCore::populate_resource),
    });
}
Napi::FunctionReference OCCore::constructor;


Value OCCore::init(const CallbackInfo& info) {
    (void)oc_core_init();
    return info.Env().Undefined();
}

Value OCCore::init_platform(const CallbackInfo& info) {
    auto mfg_name_ = info[0].ToString().Utf8Value();
    auto mfg_name = mfg_name_.c_str();
    oc_core_init_platform_cb_t init_cb = nullptr;
    Function init_cb_ = info[1].As<Function>();
    void* data = info[2];
    shared_ptr<oc_platform_info_t> sp(oc_core_init_platform(mfg_name, init_cb, data), nop_deleter);
    auto args = External<shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
    return OCPlatformInfo::constructor.New({args});
}

Value OCCore::shutdown(const CallbackInfo& info) {
    (void)oc_core_shutdown();
    return info.Env().Undefined();
}

Value OCCore::get_num_devices(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_core_get_num_devices());
}

Value OCCore::get_device_id(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    shared_ptr<oc_uuid_t> sp(oc_core_get_device_id(device), nop_deleter);
    auto args = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({args});
}

Value OCCore::get_device_info(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    shared_ptr<oc_device_info_t> sp(oc_core_get_device_info(device), nop_deleter);
    auto args = External<shared_ptr<oc_device_info_t>>::New(info.Env(), &sp);
    return OCDeviceInfo::constructor.New({args});
}

Value OCCore::get_platform_info(const CallbackInfo& info) {
    shared_ptr<oc_platform_info_t> sp(oc_core_get_platform_info(), nop_deleter);
    auto args = External<shared_ptr<oc_platform_info_t>>::New(info.Env(), &sp);
    return OCPlatformInfo::constructor.New({args});
}

Value OCCore::get_resource_by_uri(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto device = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    shared_ptr<oc_resource_t> sp(oc_core_get_resource_by_uri(uri, device), nop_deleter);
    auto args = External<shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
    return OCResource::constructor.New({args});
}

Value OCCore::filter_resource_by_rt(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    auto& request = *OCRequest::Unwrap(info[1].ToObject());
    return Boolean::New(info.Env(), oc_filter_resource_by_rt(resource, request));
}

Value OCCore::is_DCR(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    auto device = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    return Boolean::New(info.Env(), oc_core_is_DCR(resource, device));
}

Value OCCore::set_latency(const CallbackInfo& info) {
    auto latency = static_cast<int>(info[0].ToNumber());
    (void)oc_core_set_latency(latency);
    return info.Env().Undefined();
}

Value OCCore::get_latency(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_core_get_latency());
}

Value OCCore::add_new_device(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto rt_ = info[1].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto name_ = info[2].ToString().Utf8Value();
    auto name = name_.c_str();
    auto spec_version_ = info[3].ToString().Utf8Value();
    auto spec_version = spec_version_.c_str();
    auto data_model_version_ = info[4].ToString().Utf8Value();
    auto data_model_version = data_model_version_.c_str();
    oc_core_add_device_cb_t add_device_cb = nullptr;
    Function add_device_cb_ = info[5].As<Function>();
    void* data = info[6];
    shared_ptr<oc_device_info_t> sp(oc_core_add_new_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data), nop_deleter);
    auto args = External<shared_ptr<oc_device_info_t>>::New(info.Env(), &sp);
    return OCDeviceInfo::constructor.New({args});
}

Value OCCore::encode_interfaces_mask(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto iface_mask = static_cast<oc_interface_mask_t>(info[1].ToNumber().Uint32Value());
    (void)oc_core_encode_interfaces_mask(parent, iface_mask);
    return info.Env().Undefined();
}

Value OCCore::get_resource_by_index(const CallbackInfo& info) {
    auto type = static_cast<int>(info[0].ToNumber());
    auto device = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    shared_ptr<oc_resource_t> sp(oc_core_get_resource_by_index(type, device), nop_deleter);
    auto args = External<shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
    return OCResource::constructor.New({args});
}

Value OCCore::populate_resource(const CallbackInfo& info) {
    auto core_resource = static_cast<int>(info[0].ToNumber());
    auto device_index = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    auto uri_ = info[2].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto iface_mask = static_cast<oc_interface_mask_t>(info[3].ToNumber().Uint32Value());
    auto default_interface = static_cast<oc_interface_mask_t>(info[4].ToNumber().Uint32Value());
    auto properties = static_cast<int>(info[5].ToNumber());
    oc_request_callback_t get_cb = nullptr;
    Function get_cb_ = info[6].As<Function>();
    oc_request_callback_t put_cb = nullptr;
    Function put_cb_ = info[7].As<Function>();
    oc_request_callback_t post_cb = nullptr;
    Function post_cb_ = info[8].As<Function>();
    oc_request_callback_t delete_cb = nullptr;
    Function delete_cb_ = info[9].As<Function>();
    auto num_resource_types = static_cast<int>(info[10].ToNumber());
    (void)oc_core_populate_resource(core_resource, device_index, uri, iface_mask, default_interface, properties, get_cb, put_cb, post_cb, delete_cb, num_resource_types);
    return info.Env().Undefined();
}

OCEnumUtil::OCEnumUtil(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCEnumUtil::GetClass(Napi::Env env) {
    return DefineClass(env, "OCEnumUtil", {
        StaticMethod("enum_to_str", &OCEnumUtil::enum_to_str),
        StaticMethod("pos_desc_to_str", &OCEnumUtil::pos_desc_to_str),
    });
}
Napi::FunctionReference OCEnumUtil::constructor;


Value OCEnumUtil::enum_to_str(const CallbackInfo& info) {
    auto val = static_cast<oc_enum_t>(info[0].ToNumber().Uint32Value());
    return String::New(info.Env(), oc_enum_to_str(val));
}

Value OCEnumUtil::pos_desc_to_str(const CallbackInfo& info) {
    auto pos = static_cast<oc_pos_description_t>(info[0].ToNumber().Uint32Value());
    return String::New(info.Env(), oc_enum_pos_desc_to_str(pos));
}

OCIntrospection::OCIntrospection(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCIntrospection::GetClass(Napi::Env env) {
    return DefineClass(env, "OCIntrospection", {
#if defined(OC_IDD_API)
        StaticMethod("set_introspection_data", &OCIntrospection::set_introspection_data),
#endif
    });
}
Napi::FunctionReference OCIntrospection::constructor;


#if defined(OC_IDD_API)
Value OCIntrospection::set_introspection_data(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto IDD = reinterpret_cast<uint8_t*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto IDD_size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    (void)oc_set_introspection_data(device, IDD, IDD_size);
    return info.Env().Undefined();
}
#endif

OCMain::OCMain(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCMain::GetClass(Napi::Env env) {
    return DefineClass(env, "OCMain", {
        StaticMethod("add_collection", &OCMain::add_collection),
        StaticMethod("add_device", &OCMain::add_device),
#if defined(OC_SECURITY)
        StaticMethod("add_ownership_status_cb", &OCMain::add_ownership_status_cb),
#endif
        StaticMethod("add_resource", &OCMain::add_resource),
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("assert_all_roles", &OCMain::assert_all_roles),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("assert_role", &OCMain::assert_role),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("auto_assert_roles", &OCMain::auto_assert_roles),
#endif
        StaticMethod("close_session", &OCMain::close_session),
        StaticMethod("delete_link", &OCMain::delete_link),
        StaticMethod("delete_resource", &OCMain::delete_resource),
        StaticMethod("device_bind_resource_type", &OCMain::device_bind_resource_type),
        StaticMethod("do_delete", &OCMain::do_delete),
        StaticMethod("do_get", &OCMain::do_get),
        StaticMethod("do_ip_discovery", &OCMain::do_ip_discovery),
        StaticMethod("do_ip_discovery_all", &OCMain::do_ip_discovery_all),
        StaticMethod("do_ip_discovery_all_at_endpoint", &OCMain::do_ip_discovery_all_at_endpoint),
        StaticMethod("do_ip_discovery_at_endpoint", &OCMain::do_ip_discovery_at_endpoint),
        StaticMethod("do_ip_multicast", &OCMain::do_ip_multicast),
        StaticMethod("do_observe", &OCMain::do_observe),
        StaticMethod("do_post", &OCMain::do_post),
        StaticMethod("do_put", &OCMain::do_put),
        StaticMethod("do_realm_local_ipv6_discovery", &OCMain::do_realm_local_ipv6_discovery),
        StaticMethod("do_realm_local_ipv6_discovery_all", &OCMain::do_realm_local_ipv6_discovery_all),
        StaticMethod("do_realm_local_ipv6_multicast", &OCMain::do_realm_local_ipv6_multicast),
        StaticMethod("do_site_local_ipv6_discovery", &OCMain::do_site_local_ipv6_discovery),
        StaticMethod("do_site_local_ipv6_discovery_all", &OCMain::do_site_local_ipv6_discovery_all),
        StaticMethod("do_site_local_ipv6_multicast", &OCMain::do_site_local_ipv6_multicast),
        StaticMethod("free_server_endpoints", &OCMain::free_server_endpoints),
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("get_all_roles", &OCMain::get_all_roles),
#endif
        StaticMethod("get_con_res_announced", &OCMain::get_con_res_announced),
        StaticMethod("ignore_request", &OCMain::ignore_request),
        StaticMethod("indicate_separate_response", &OCMain::indicate_separate_response),
        StaticMethod("init_platform", &OCMain::init_platform),
        StaticMethod("init_post", &OCMain::init_post),
        StaticMethod("init_put", &OCMain::init_put),
#if defined(OC_SECURITY)
        StaticMethod("is_owned_device", &OCMain::is_owned_device),
#endif
        StaticMethod("link_add_link_param", &OCMain::link_add_link_param),
        StaticMethod("link_add_rel", &OCMain::link_add_rel),
        StaticMethod("main_init", &OCMain::main_init),
        StaticMethod("main_loop", &OCMain::main_loop),
        StaticMethod("main_shutdown", &OCMain::main_shutdown),
        StaticMethod("new_link", &OCMain::new_link),
        StaticMethod("remove_delayed_callback", &OCMain::remove_delayed_callback),
#if defined(OC_SECURITY)
        StaticMethod("remove_ownership_status_cb", &OCMain::remove_ownership_status_cb),
#endif
#if defined(OC_SECURITY)
        StaticMethod("reset", &OCMain::reset),
#endif
#if defined(OC_SECURITY)
        StaticMethod("reset_device", &OCMain::reset_device),
#endif
        StaticMethod("ri_is_app_resource_valid", &OCMain::ri_is_app_resource_valid),
        StaticMethod("send_diagnostic_message", &OCMain::send_diagnostic_message),
#if defined(OC_TCP)
        StaticMethod("send_ping", &OCMain::send_ping),
#endif
        StaticMethod("send_response", &OCMain::send_response),
        StaticMethod("send_response_raw", &OCMain::send_response_raw),
        StaticMethod("send_separate_response", &OCMain::send_separate_response),
        StaticMethod("set_con_res_announced", &OCMain::set_con_res_announced),
        StaticMethod("set_con_write_cb", &OCMain::set_con_write_cb),
        StaticMethod("set_delayed_callback", &OCMain::set_delayed_callback),
        StaticMethod("set_factory_presets_cb", &OCMain::set_factory_presets_cb),
#if defined(OC_SECURITY)
        StaticMethod("set_random_pin_callback", &OCMain::set_random_pin_callback),
#endif
        StaticMethod("set_separate_response_buffer", &OCMain::set_separate_response_buffer),
        StaticMethod("stop_multicast", &OCMain::stop_multicast),
        StaticMethod("stop_observe", &OCMain::stop_observe),
        StaticMethod("set_mtu_size", &OCMain::set_mtu_size),
        StaticMethod("get_mtu_size", &OCMain::get_mtu_size),
        StaticMethod("set_max_app_data_size", &OCMain::set_max_app_data_size),
        StaticMethod("get_max_app_data_size", &OCMain::get_max_app_data_size),
        StaticMethod("get_block_size", &OCMain::get_block_size),
        StaticMethod("add_network_interface_event_callback", &OCMain::add_network_interface_event_callback),
        StaticMethod("remove_network_interface_event_callback", &OCMain::remove_network_interface_event_callback),
        StaticMethod("add_session_event_callback", &OCMain::add_session_event_callback),
        StaticMethod("remove_session_event_callback", &OCMain::remove_session_event_callback),
        StaticMethod("base64_decode", &OCMain::base64_decode),
        StaticMethod("base64_encode", &OCMain::base64_encode),
        StaticMethod("dns_lookup", &OCMain::dns_lookup),
    });
}
Napi::FunctionReference OCMain::constructor;


Value OCMain::add_collection(const CallbackInfo& info) {
    auto& collection = *OCResource::Unwrap(info[0].ToObject());
    (void)oc_add_collection(collection);
    return info.Env().Undefined();
}

Value OCMain::add_device(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto rt_ = info[1].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto name_ = info[2].ToString().Utf8Value();
    auto name = name_.c_str();
    auto spec_version_ = info[3].ToString().Utf8Value();
    auto spec_version = spec_version_.c_str();
    auto data_model_version_ = info[4].ToString().Utf8Value();
    auto data_model_version = data_model_version_.c_str();
    auto add_device_cb = check_callback_func(info, 5, helper_oc_add_device_cb);
    const int O_FUNC = 5;
    auto data =  check_callback_context(info, O_FUNC, 6);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_add_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data));
}

#if defined(OC_SECURITY)
Value OCMain::add_ownership_status_cb(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_ownership_status_cb);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    (void)oc_add_ownership_status_cb(cb, user_data);
    return info.Env().Undefined();
}
#endif

Value OCMain::add_resource(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    return Boolean::New(info.Env(), oc_add_resource(resource));
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCMain::assert_all_roles(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    auto handler = check_callback_func(info, 1, helper_oc_response_handler);
    const int O_FUNC = 1;
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    (void)oc_assert_all_roles(endpoint, handler, user_data);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCMain::assert_role(const CallbackInfo& info) {
    auto role_ = info[0].ToString().Utf8Value();
    auto role = role_.c_str();
    auto authority_ = info[1].ToString().Utf8Value();
    auto authority = authority_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[2].ToObject());
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto user_data =  check_callback_context(info, O_FUNC, 4);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_assert_role(role, authority, endpoint, handler, user_data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCMain::auto_assert_roles(const CallbackInfo& info) {
    auto auto_assert = info[0].ToBoolean().Value();
    (void)oc_auto_assert_roles(auto_assert);
    return info.Env().Undefined();
}
#endif

Value OCMain::close_session(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    (void)oc_close_session(endpoint);
    return info.Env().Undefined();
}

Value OCMain::delete_link(const CallbackInfo& info) {
    auto& link = *OCLink::Unwrap(info[0].ToObject());
    (void)oc_delete_link(link);
    return info.Env().Undefined();
}

Value OCMain::delete_resource(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    return Boolean::New(info.Env(), oc_delete_resource(resource));
}

Value OCMain::device_bind_resource_type(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto type_ = info[1].ToString().Utf8Value();
    auto type = type_.c_str();
    (void)oc_device_bind_resource_type(device, type);
    return info.Env().Undefined();
}

Value OCMain::do_delete(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    const char* query = nullptr;
    if (info[2].IsString()) {
        auto query_ = info[2].ToString().Utf8Value();
        query = query_.c_str();
    }
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto qos = static_cast<oc_qos_t>(info[4].ToNumber().Uint32Value());
    auto user_data =  check_callback_context(info, O_FUNC, 5);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_delete(uri, endpoint, query, handler, qos, user_data));
}

Value OCMain::do_get(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    const char* query = nullptr;
    if (info[2].IsString()) {
        auto query_ = info[2].ToString().Utf8Value();
        query = query_.c_str();
    }
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto qos = static_cast<oc_qos_t>(info[4].ToNumber().Uint32Value());
    auto user_data =  check_callback_context(info, O_FUNC, 5);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_get(uri, endpoint, query, handler, qos, user_data));
}

Value OCMain::do_ip_discovery(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery(rt, handler, user_data));
}

Value OCMain::do_ip_discovery_all(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery_all(handler, user_data));
}

Value OCMain::do_ip_discovery_all_at_endpoint(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery_all_at_endpoint(handler, endpoint, user_data));
}

Value OCMain::do_ip_discovery_at_endpoint(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto& endpoint = *OCEndpoint::Unwrap(info[2].ToObject());
    auto user_data =  check_callback_context(info, O_FUNC, 3);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, user_data));
}

Value OCMain::do_ip_multicast(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto query_ = info[1].ToString().Utf8Value();
    auto query = query_.c_str();
    auto handler = check_callback_func(info, 2, helper_oc_response_handler);
    const int O_FUNC = 2;
    auto user_data =  check_callback_context(info, O_FUNC, 3);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_multicast(uri, query, handler, user_data));
}

Value OCMain::do_observe(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    const char* query = nullptr;
    if (info[2].IsString()) {
        auto query_ = info[2].ToString().Utf8Value();
        query = query_.c_str();
    }
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto qos = static_cast<oc_qos_t>(info[4].ToNumber().Uint32Value());
    auto user_data =  check_callback_context(info, O_FUNC, 5);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_observe(uri, endpoint, query, handler, qos, user_data));
}

Value OCMain::do_post(const CallbackInfo& info) {
    return Boolean::New(info.Env(), oc_do_post());
}

Value OCMain::do_put(const CallbackInfo& info) {
    return Boolean::New(info.Env(), oc_do_put());
}

Value OCMain::do_realm_local_ipv6_discovery(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery(rt, handler, user_data));
}

Value OCMain::do_realm_local_ipv6_discovery_all(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery_all(handler, user_data));
}

Value OCMain::do_realm_local_ipv6_multicast(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto query_ = info[1].ToString().Utf8Value();
    auto query = query_.c_str();
    auto handler = check_callback_func(info, 2, helper_oc_response_handler);
    const int O_FUNC = 2;
    auto user_data =  check_callback_context(info, O_FUNC, 3);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_realm_local_ipv6_multicast(uri, query, handler, user_data));
}

Value OCMain::do_site_local_ipv6_discovery(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery(rt, handler, user_data));
}

Value OCMain::do_site_local_ipv6_discovery_all(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery_all(handler, user_data));
}

Value OCMain::do_site_local_ipv6_multicast(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto query_ = info[1].ToString().Utf8Value();
    auto query = query_.c_str();
    auto handler = check_callback_func(info, 2, helper_oc_response_handler);
    const int O_FUNC = 2;
    auto user_data =  check_callback_context(info, O_FUNC, 3);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_do_site_local_ipv6_multicast(uri, query, handler, user_data));
}

Value OCMain::free_server_endpoints(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    (void)oc_free_server_endpoints(endpoint);
    return info.Env().Undefined();
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCMain::get_all_roles(const CallbackInfo& info) {
    shared_ptr<oc_role_t> sp(oc_get_all_roles(), nop_deleter);
    auto args = External<shared_ptr<oc_role_t>>::New(info.Env(), &sp);
    return OCRole::constructor.New({args});
}
#endif

Value OCMain::get_con_res_announced(const CallbackInfo& info) {
    return Boolean::New(info.Env(), oc_get_con_res_announced());
}

Value OCMain::ignore_request(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    (void)oc_ignore_request(request);
    return info.Env().Undefined();
}

Value OCMain::indicate_separate_response(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    auto& response = *OCSeparateResponse::Unwrap(info[1].ToObject());
    (void)oc_indicate_separate_response(request, response);
    return info.Env().Undefined();
}

Value OCMain::init_platform(const CallbackInfo& info) {
    auto mfg_name_ = info[0].ToString().Utf8Value();
    auto mfg_name = mfg_name_.c_str();
    auto init_platform_cb = check_callback_func(info, 1, helper_oc_init_platform_cb);
    const int O_FUNC = 1;
    auto data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_init_platform(mfg_name, init_platform_cb, data));
}

Value OCMain::init_post(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    const char* query = nullptr;
    if (info[2].IsString()) {
        auto query_ = info[2].ToString().Utf8Value();
        query = query_.c_str();
    }
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto qos = static_cast<oc_qos_t>(info[4].ToNumber().Uint32Value());
    auto user_data =  check_callback_context(info, O_FUNC, 5);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_init_post(uri, endpoint, query, handler, qos, user_data));
}

Value OCMain::init_put(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    const char* query = nullptr;
    if (info[2].IsString()) {
        std::string query_ = info[2].ToString().Utf8Value();
        query = query_.c_str();
    }
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto qos = static_cast<oc_qos_t>(info[4].ToNumber().Uint32Value());
    auto user_data =  check_callback_context(info, O_FUNC, 5);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_init_put(uri, endpoint, query, handler, qos, user_data));
}

#if defined(OC_SECURITY)
Value OCMain::is_owned_device(const CallbackInfo& info) {
    auto device_index = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    return Boolean::New(info.Env(), oc_is_owned_device(device_index));
}
#endif

Value OCMain::link_add_link_param(const CallbackInfo& info) {
    auto& link = *OCLink::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    auto value_ = info[2].ToString().Utf8Value();
    auto value = value_.c_str();
    (void)oc_link_add_link_param(link, key, value);
    return info.Env().Undefined();
}

Value OCMain::link_add_rel(const CallbackInfo& info) {
    auto& link = *OCLink::Unwrap(info[0].ToObject());
    auto rel_ = info[1].ToString().Utf8Value();
    auto rel = rel_.c_str();
    (void)oc_link_add_rel(link, rel);
    return info.Env().Undefined();
}

Value OCMain::main_init(const CallbackInfo& info) {
    auto& handler = *OCHandler::Unwrap(info[0].ToObject());
    struct main_context_t* mainctx = new main_context_t {
        Promise::Deferred::New(info.Env()),
                ThreadSafeFunction::New(info.Env(),
        Function::New(info.Env(), [](const CallbackInfo& info) {
            main_context->deferred.Resolve(info.Env().Undefined());
            delete main_context;
            main_context = nullptr;
        }), "main_loop_resolve", 0, 1)
    };
    handler.m_pvalue->signal_event_loop = helper_oc_handler_signal_event_loop;
    handler.m_pvalue->init = nullptr;
    handler.m_pvalue->register_resources = nullptr;
    handler.m_pvalue->requests_entry = nullptr;
    if(handler.init.Value().IsFunction() ) {
        mainctx->oc_handler_init_ref.Reset(handler.init.Value());
        handler.m_pvalue->init = helper_oc_handler_init;
    }
    else {
        TypeError::New(info.Env(), "init callback is not set.").ThrowAsJavaScriptException();
    }
    if(handler.register_resources.Value().IsFunction() ) {
        mainctx->oc_handler_register_resources_ref.Reset(handler.register_resources.Value());
        handler.m_pvalue->register_resources = helper_oc_handler_register_resources;
    }
    if(handler.requests_entry.Value().IsFunction() ) {
        mainctx->oc_handler_requests_entry_ref.Reset(handler.requests_entry.Value());
        handler.m_pvalue->requests_entry = helper_oc_handler_requests_entry;
    }

    try {
        mainctx->helper_poll_event_thread = thread(helper_poll_event_thread, mainctx);
        mainctx->helper_poll_event_thread.detach();
    }
    catch(system_error) {
        TypeError::New(info.Env(), "Fail to initialize poll_event thread.").ThrowAsJavaScriptException();
    }

    return Number::New(info.Env(), oc_main_init(handler));

}

Value OCMain::main_loop(const CallbackInfo& info) {
    return main_context->deferred.Promise();

}

Value OCMain::main_shutdown(const CallbackInfo& info) {
    terminate_main_loop();
    (void)oc_main_shutdown();
    return info.Env().Undefined();
}

Value OCMain::new_link(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    shared_ptr<oc_link_t> sp(oc_new_link(resource), nop_deleter);
    auto args = External<shared_ptr<oc_link_t>>::New(info.Env(), &sp);
    return OCLink::constructor.New({args});
}

Value OCMain::remove_delayed_callback(const CallbackInfo& info) {
    void* cb_data = info[0];
    oc_trigger_t callback = nullptr;
    Function callback_ = info[1].As<Function>();
    (void)oc_remove_delayed_callback(cb_data, callback);
    return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Value OCMain::remove_ownership_status_cb(const CallbackInfo& info) {
    oc_ownership_status_cb_t cb = nullptr;
    Function cb_ = info[0].As<Function>();
    void* user_data = info[1];
    (void)oc_remove_ownership_status_cb(cb, user_data);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCMain::reset(const CallbackInfo& info) {
    (void)oc_reset();
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCMain::reset_device(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    (void)oc_reset_device(device);
    return info.Env().Undefined();
}
#endif

Value OCMain::ri_is_app_resource_valid(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    return Boolean::New(info.Env(), oc_ri_is_app_resource_valid(resource));
}

Value OCMain::send_diagnostic_message(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    auto msg_ = info[1].ToString().Utf8Value();
    auto msg = msg_.c_str();
    auto msg_len = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    auto response_code = static_cast<oc_status_t>(info[3].ToNumber().Uint32Value());
    (void)oc_send_diagnostic_message(request, msg, msg_len, response_code);
    return info.Env().Undefined();
}

#if defined(OC_TCP)
Value OCMain::send_ping(const CallbackInfo& info) {
    auto custody = info[0].ToBoolean().Value();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    auto timeout_seconds = static_cast<uint16_t>(info[2].ToNumber().Uint32Value());
    auto handler = check_callback_func(info, 3, helper_oc_response_handler);
    const int O_FUNC = 3;
    auto user_data =  check_callback_context(info, O_FUNC, 4);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(user_data));
    return Boolean::New(info.Env(), oc_send_ping(custody, endpoint, timeout_seconds, handler, user_data));
}
#endif

Value OCMain::send_response(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    auto response_code = static_cast<oc_status_t>(info[1].ToNumber().Uint32Value());
    (void)oc_send_response(request, response_code);
    return info.Env().Undefined();
}

Value OCMain::send_response_raw(const CallbackInfo& info) {
    auto& request = *OCRequest::Unwrap(info[0].ToObject());
    auto payload = reinterpret_cast<const uint8_t*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    auto content_format = static_cast<oc_content_format_t>(info[3].ToNumber().Uint32Value());
    auto response_code = static_cast<oc_status_t>(info[4].ToNumber().Uint32Value());
    (void)oc_send_response_raw(request, payload, size, content_format, response_code);
    return info.Env().Undefined();
}

Value OCMain::send_separate_response(const CallbackInfo& info) {
    auto& handle = *OCSeparateResponse::Unwrap(info[0].ToObject());
    auto response_code = static_cast<oc_status_t>(info[1].ToNumber().Uint32Value());
    (void)oc_send_separate_response(handle, response_code);
    return info.Env().Undefined();
}

Value OCMain::set_con_res_announced(const CallbackInfo& info) {
    auto announce = info[0].ToBoolean().Value();
    (void)oc_set_con_res_announced(announce);
    return info.Env().Undefined();
}

Value OCMain::set_con_write_cb(const CallbackInfo& info) {
    oc_con_write_cb_t callback = nullptr;
    Function callback_ = info[0].As<Function>();
    (void)oc_set_con_write_cb(callback);
    return info.Env().Undefined();
}

Value OCMain::set_delayed_callback(const CallbackInfo& info) {
    auto callback = check_callback_func(info, 1, helper_oc_trigger);
    const int O_FUNC = 1;
    auto seconds = static_cast<uint16_t>(info[2].ToNumber().Uint32Value());
    auto cb_data =  check_callback_context(info, O_FUNC, 0);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(cb_data));
    (void)oc_set_delayed_callback(cb_data, callback, seconds);
    return info.Env().Undefined();

}

Value OCMain::set_factory_presets_cb(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_factory_presets_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    (void)oc_set_factory_presets_cb(cb, data);
    return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Value OCMain::set_random_pin_callback(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_random_pin_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    (void)oc_set_random_pin_callback(cb, data);
    return info.Env().Undefined();
}
#endif

Value OCMain::set_separate_response_buffer(const CallbackInfo& info) {
    auto& handle = *OCSeparateResponse::Unwrap(info[0].ToObject());
    (void)oc_set_separate_response_buffer(handle);
    return info.Env().Undefined();
}

Value OCMain::stop_multicast(const CallbackInfo& info) {
    auto& response = *OCClientResponse::Unwrap(info[0].ToObject());
    (void)oc_stop_multicast(response);
    return info.Env().Undefined();
}

Value OCMain::stop_observe(const CallbackInfo& info) {
    auto uri_ = info[0].ToString().Utf8Value();
    auto uri = uri_.c_str();
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    return Boolean::New(info.Env(), oc_stop_observe(uri, endpoint));
}

Value OCMain::set_mtu_size(const CallbackInfo& info) {
    auto mtu_size = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_set_mtu_size(mtu_size));
}

Value OCMain::get_mtu_size(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_get_mtu_size());
}

Value OCMain::set_max_app_data_size(const CallbackInfo& info) {
    auto size = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    (void)oc_set_max_app_data_size(size);
    return info.Env().Undefined();
}

Value OCMain::get_max_app_data_size(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_get_max_app_data_size());
}

Value OCMain::get_block_size(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_get_block_size());
}

Value OCMain::add_network_interface_event_callback(const CallbackInfo& info) {
    interface_event_handler_t cb = nullptr;
    Function cb_ = info[0].As<Function>();
    return Number::New(info.Env(), oc_add_network_interface_event_callback(cb));
}

Value OCMain::remove_network_interface_event_callback(const CallbackInfo& info) {
    interface_event_handler_t cb = nullptr;
    Function cb_ = info[0].As<Function>();
    return Number::New(info.Env(), oc_remove_network_interface_event_callback(cb));
}

Value OCMain::add_session_event_callback(const CallbackInfo& info) {
    session_event_handler_t cb = nullptr;
    Function cb_ = info[0].As<Function>();
    return Number::New(info.Env(), oc_add_session_event_callback(cb));
}

Value OCMain::remove_session_event_callback(const CallbackInfo& info) {
    session_event_handler_t cb = nullptr;
    Function cb_ = info[0].As<Function>();
    return Number::New(info.Env(), oc_remove_session_event_callback(cb));
}

Value OCMain::base64_decode(const CallbackInfo& info) {
    auto str = reinterpret_cast<uint8_t*>(info[0].As<TypedArray>().ArrayBuffer().Data());
    auto len = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_base64_decode(str, len));
}

Value OCMain::base64_encode(const CallbackInfo& info) {
    auto input = reinterpret_cast<const uint8_t*>(info[0].As<TypedArray>().ArrayBuffer().Data());
    auto input_len = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    auto output_buffer = reinterpret_cast<uint8_t*>(info[2].As<TypedArray>().ArrayBuffer().Data());
    auto output_buffer_len = static_cast<size_t>(info[3].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_base64_encode(input, input_len, output_buffer, output_buffer_len));
}

Value OCMain::dns_lookup(const CallbackInfo& info) {
    auto domain_ = info[0].ToString().Utf8Value();
    auto domain = domain_.c_str();
    auto& addr = *OCMmem::Unwrap(info[1].ToObject());
    auto flags = static_cast<enum transport_flags>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_dns_lookup(domain, addr, flags));
}

OCMemTrace::OCMemTrace(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCMemTrace::GetClass(Napi::Env env) {
    return DefineClass(env, "OCMemTrace", {
#if defined(OC_MEMORY_TRACE)
        StaticMethod("add_pace", &OCMemTrace::add_pace),
#endif
#if defined(OC_MEMORY_TRACE)
        StaticMethod("init", &OCMemTrace::init),
#endif
#if defined(OC_MEMORY_TRACE)
        StaticMethod("shutdown", &OCMemTrace::shutdown),
#endif
    });
}
Napi::FunctionReference OCMemTrace::constructor;


#if defined(OC_MEMORY_TRACE)
Value OCMemTrace::add_pace(const CallbackInfo& info) {
    auto func_ = info[0].ToString().Utf8Value();
    auto func = func_.c_str();
    auto size = static_cast<int>(info[1].ToNumber());
    auto type = static_cast<int>(info[2].ToNumber());
    void* address = info[3];
    (void)oc_mem_trace_add_pace(func, size, type, address);
    return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Value OCMemTrace::init(const CallbackInfo& info) {
    (void)oc_mem_trace_init();
    return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Value OCMemTrace::shutdown(const CallbackInfo& info) {
    (void)oc_mem_trace_shutdown();
    return info.Env().Undefined();
}
#endif

OCObt::OCObt(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCObt::GetClass(Napi::Env env) {
    return DefineClass(env, "OCObt", {
#if defined(OC_SECURITY)
        StaticMethod("ace_add_permission", &OCObt::ace_add_permission),
#endif
#if defined(OC_SECURITY)
        StaticMethod("ace_new_resource", &OCObt::ace_new_resource),
#endif
#if defined(OC_SECURITY)
        StaticMethod("ace_resource_set_href", &OCObt::ace_resource_set_href),
#endif
#if defined(OC_SECURITY)
        StaticMethod("ace_resource_set_wc", &OCObt::ace_resource_set_wc),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("add_roleid", &OCObt::add_roleid),
#endif
#if defined(OC_SECURITY)
        StaticMethod("delete_ace_by_aceid", &OCObt::delete_ace_by_aceid),
#endif
#if defined(OC_SECURITY)
        StaticMethod("delete_cred_by_credid", &OCObt::delete_cred_by_credid),
#endif
#if defined(OC_SECURITY)
        StaticMethod("delete_own_cred_by_credid", &OCObt::delete_own_cred_by_credid),
#endif
#if defined(OC_SECURITY)
        StaticMethod("device_hard_reset", &OCObt::device_hard_reset),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_all_resources", &OCObt::discover_all_resources),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_owned_devices", &OCObt::discover_owned_devices),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_owned_devices_realm_local_ipv6", &OCObt::discover_owned_devices_realm_local_ipv6),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_owned_devices_site_local_ipv6", &OCObt::discover_owned_devices_site_local_ipv6),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_unowned_devices", &OCObt::discover_unowned_devices),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_unowned_devices_realm_local_ipv6", &OCObt::discover_unowned_devices_realm_local_ipv6),
#endif
#if defined(OC_SECURITY)
        StaticMethod("discover_unowned_devices_site_local_ipv6", &OCObt::discover_unowned_devices_site_local_ipv6),
#endif
#if defined(OC_SECURITY)
        StaticMethod("free_ace", &OCObt::free_ace),
#endif
#if defined(OC_SECURITY)
        StaticMethod("free_acl", &OCObt::free_acl),
#endif
#if defined(OC_SECURITY)
        StaticMethod("free_creds", &OCObt::free_creds),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("free_roleid", &OCObt::free_roleid),
#endif
#if defined(OC_SECURITY)
        StaticMethod("init", &OCObt::init),
#endif
#if defined(OC_SECURITY)
        StaticMethod("new_ace_for_connection", &OCObt::new_ace_for_connection),
#endif
#if defined(OC_SECURITY)
        StaticMethod("new_ace_for_role", &OCObt::new_ace_for_role),
#endif
#if defined(OC_SECURITY)
        StaticMethod("new_ace_for_subject", &OCObt::new_ace_for_subject),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("perform_cert_otm", &OCObt::perform_cert_otm),
#endif
#if defined(OC_SECURITY)
        StaticMethod("perform_just_works_otm", &OCObt::perform_just_works_otm),
#endif
#if defined(OC_SECURITY)
        StaticMethod("perform_random_pin_otm", &OCObt::perform_random_pin_otm),
#endif
#if defined(OC_SECURITY)
        StaticMethod("provision_ace", &OCObt::provision_ace),
#endif
#if defined(OC_SECURITY)
        StaticMethod("provision_auth_wildcard_ace", &OCObt::provision_auth_wildcard_ace),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("provision_identity_certificate", &OCObt::provision_identity_certificate),
#endif
#if defined(OC_SECURITY)
        StaticMethod("provision_pairwise_credentials", &OCObt::provision_pairwise_credentials),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("provision_role_certificate", &OCObt::provision_role_certificate),
#endif
#if defined(OC_SECURITY)
        StaticMethod("provision_role_wildcard_ace", &OCObt::provision_role_wildcard_ace),
#endif
#if defined(OC_SECURITY)
        StaticMethod("request_random_pin", &OCObt::request_random_pin),
#endif
#if defined(OC_SECURITY)
        StaticMethod("retrieve_acl", &OCObt::retrieve_acl),
#endif
#if defined(OC_SECURITY)
        StaticMethod("retrieve_creds", &OCObt::retrieve_creds),
#endif
#if defined(OC_SECURITY)
        StaticMethod("retrieve_own_creds", &OCObt::retrieve_own_creds),
#endif
#if defined(OC_SECURITY)
        StaticMethod("set_sd_info", &OCObt::set_sd_info),
#endif
#if defined(OC_SECURITY)
        StaticMethod("shutdown", &OCObt::shutdown),
#endif
    });
}
Napi::FunctionReference OCObt::constructor;


#if defined(OC_SECURITY)
Value OCObt::ace_add_permission(const CallbackInfo& info) {
    auto& ace = *OCSecurityAce::Unwrap(info[0].ToObject());
    auto permission = static_cast<oc_ace_permissions_t>(info[1].ToNumber().Uint32Value());
    (void)oc_obt_ace_add_permission(ace, permission);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCObt::ace_new_resource(const CallbackInfo& info) {
    auto& ace = *OCSecurityAce::Unwrap(info[0].ToObject());
    shared_ptr<oc_ace_res_t> sp(oc_obt_ace_new_resource(ace), nop_deleter);
    auto args = External<shared_ptr<oc_ace_res_t>>::New(info.Env(), &sp);
    return OCAceResource::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Value OCObt::ace_resource_set_href(const CallbackInfo& info) {
    auto& resource = *OCAceResource::Unwrap(info[0].ToObject());
    auto href_ = info[1].ToString().Utf8Value();
    auto href = href_.c_str();
    (void)oc_obt_ace_resource_set_href(resource, href);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCObt::ace_resource_set_wc(const CallbackInfo& info) {
    auto& resource = *OCAceResource::Unwrap(info[0].ToObject());
    auto wc = static_cast<oc_ace_wildcard_t>(info[1].ToNumber().Uint32Value());
    (void)oc_obt_ace_resource_set_wc(resource, wc);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCObt::add_roleid(const CallbackInfo& info) {
    auto& roles = *OCRole::Unwrap(info[0].ToObject());
    auto role_ = info[1].ToString().Utf8Value();
    auto role = role_.c_str();
    auto authority_ = info[2].ToString().Utf8Value();
    auto authority = authority_.c_str();
    shared_ptr<oc_role_t> sp(oc_obt_add_roleid(roles, role, authority), nop_deleter);
    auto args = External<shared_ptr<oc_role_t>>::New(info.Env(), &sp);
    return OCRole::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Value OCObt::delete_ace_by_aceid(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    auto aceid = static_cast<int>(info[1].ToNumber());
    oc_obt_status_cb_t cb = nullptr;
    Function cb_ = info[2].As<Function>();
    void* data = info[3];
    return Number::New(info.Env(), oc_obt_delete_ace_by_aceid(uuid, aceid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::delete_cred_by_credid(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    auto credid = static_cast<int>(info[1].ToNumber());
    oc_obt_status_cb_t cb = nullptr;
    Function cb_ = info[2].As<Function>();
    void* data = info[3];
    return Number::New(info.Env(), oc_obt_delete_cred_by_credid(uuid, credid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::delete_own_cred_by_credid(const CallbackInfo& info) {
    auto credid = static_cast<int>(info[0].ToNumber());
    return Number::New(info.Env(), oc_obt_delete_own_cred_by_credid(credid));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::device_hard_reset(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_device_hard_reset(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_all_resources(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_discovery_all_handler_t handler = nullptr;
    Function handler_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_discover_all_resources(uuid, handler, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_owned_devices(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_obt_discover_owned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_owned_devices_realm_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_obt_discover_owned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_owned_devices_site_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_obt_discover_owned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_unowned_devices(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_obt_discover_unowned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_unowned_devices_realm_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_obt_discover_unowned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_unowned_devices_site_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<SafeCallbackHelper>(data));
    return Number::New(info.Env(), oc_obt_discover_unowned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::free_ace(const CallbackInfo& info) {
    auto& ace = *OCSecurityAce::Unwrap(info[0].ToObject());
    (void)oc_obt_free_ace(ace);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCObt::free_acl(const CallbackInfo& info) {
    auto& acl = *OCSecurityAcl::Unwrap(info[0].ToObject());
    (void)oc_obt_free_acl(acl);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCObt::free_creds(const CallbackInfo& info) {
    auto& creds = *OCCreds::Unwrap(info[0].ToObject());
    (void)oc_obt_free_creds(creds);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCObt::free_roleid(const CallbackInfo& info) {
    auto& roles = *OCRole::Unwrap(info[0].ToObject());
    (void)oc_obt_free_roleid(roles);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCObt::init(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_obt_init());
}
#endif

#if defined(OC_SECURITY)
Value OCObt::new_ace_for_connection(const CallbackInfo& info) {
    auto conn = static_cast<oc_ace_connection_type_t>(info[0].ToNumber().Uint32Value());
    shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_connection(conn), nop_deleter);
    auto args = External<shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
    return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Value OCObt::new_ace_for_role(const CallbackInfo& info) {
    auto role_ = info[0].ToString().Utf8Value();
    auto role = role_.c_str();
    auto authority_ = info[1].ToString().Utf8Value();
    auto authority = authority_.c_str();
    shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_role(role, authority), nop_deleter);
    auto args = External<shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
    return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Value OCObt::new_ace_for_subject(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    shared_ptr<oc_sec_ace_t> sp(oc_obt_new_ace_for_subject(uuid), nop_deleter);
    auto args = External<shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
    return OCSecurityAce::constructor.New({args});
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCObt::perform_cert_otm(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_perform_cert_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::perform_just_works_otm(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_perform_just_works_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::perform_random_pin_otm(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    auto pin = reinterpret_cast<const unsigned char*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto pin_len = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[3].As<Function>();
    void* data = info[4];
    return Number::New(info.Env(), oc_obt_perform_random_pin_otm(uuid, pin, pin_len, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::provision_ace(const CallbackInfo& info) {
    auto& subject = *OCUuid::Unwrap(info[0].ToObject());
    auto& ace = *OCSecurityAce::Unwrap(info[1].ToObject());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[2].As<Function>();
    void* data = info[3];
    return Number::New(info.Env(), oc_obt_provision_ace(subject, ace, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::provision_auth_wildcard_ace(const CallbackInfo& info) {
    auto& subject = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_provision_auth_wildcard_ace(subject, cb, data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCObt::provision_identity_certificate(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_status_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_provision_identity_certificate(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::provision_pairwise_credentials(const CallbackInfo& info) {
    auto& uuid1 = *OCUuid::Unwrap(info[0].ToObject());
    auto& uuid2 = *OCUuid::Unwrap(info[1].ToObject());
    oc_obt_status_cb_t cb = nullptr;
    Function cb_ = info[2].As<Function>();
    void* data = info[3];
    return Number::New(info.Env(), oc_obt_provision_pairwise_credentials(uuid1, uuid2, cb, data));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCObt::provision_role_certificate(const CallbackInfo& info) {
    auto& roles = *OCRole::Unwrap(info[0].ToObject());
    auto& uuid = *OCUuid::Unwrap(info[1].ToObject());
    oc_obt_status_cb_t cb = nullptr;
    Function cb_ = info[2].As<Function>();
    void* data = info[3];
    return Number::New(info.Env(), oc_obt_provision_role_certificate(roles, uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::provision_role_wildcard_ace(const CallbackInfo& info) {
    auto& subject = *OCUuid::Unwrap(info[0].ToObject());
    auto role_ = info[1].ToString().Utf8Value();
    auto role = role_.c_str();
    auto authority_ = info[2].ToString().Utf8Value();
    auto authority = authority_.c_str();
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[3].As<Function>();
    void* data = info[4];
    return Number::New(info.Env(), oc_obt_provision_role_wildcard_ace(subject, role, authority, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::request_random_pin(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_device_status_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_request_random_pin(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::retrieve_acl(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_acl_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_retrieve_acl(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::retrieve_creds(const CallbackInfo& info) {
    auto& subject = *OCUuid::Unwrap(info[0].ToObject());
    oc_obt_creds_cb_t cb = nullptr;
    Function cb_ = info[1].As<Function>();
    void* data = info[2];
    return Number::New(info.Env(), oc_obt_retrieve_creds(subject, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::retrieve_own_creds(const CallbackInfo& info) {
    shared_ptr<oc_sec_creds_t> sp(oc_obt_retrieve_own_creds(), nop_deleter);
    auto args = External<shared_ptr<oc_sec_creds_t>>::New(info.Env(), &sp);
    return OCCreds::constructor.New({args});
}
#endif

#if defined(OC_SECURITY)
Value OCObt::set_sd_info(const CallbackInfo& info) {
    auto name_ = info[0].ToString().Utf8Value();
    auto name = const_cast<char*>(name_.c_str());
    auto priv = info[1].ToBoolean().Value();
    (void)oc_obt_set_sd_info(name, priv);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Value OCObt::shutdown(const CallbackInfo& info) {
    (void)oc_obt_shutdown();
    return info.Env().Undefined();
}
#endif

OCPki::OCPki(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCPki::GetClass(Napi::Env env) {
    return DefineClass(env, "OCPki", {
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("add_mfg_cert", &OCPki::add_mfg_cert),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("add_mfg_trust_anchor", &OCPki::add_mfg_trust_anchor),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("add_mfg_intermediate_cert", &OCPki::add_mfg_intermediate_cert),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticMethod("add_trust_anchor", &OCPki::add_trust_anchor),
#endif
#if defined(OC_SECURITY)
        StaticMethod("set_security_profile", &OCPki::set_security_profile),
#endif
    });
}
Napi::FunctionReference OCPki::constructor;


#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCPki::add_mfg_cert(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto cert = reinterpret_cast<const unsigned char*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto cert_size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    auto key = reinterpret_cast<const unsigned char*>(info[3].As<TypedArray>().ArrayBuffer().Data());
    auto key_size = static_cast<size_t>(info[4].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_pki_add_mfg_cert(device, cert, cert_size, key, key_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCPki::add_mfg_trust_anchor(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto cert = reinterpret_cast<const unsigned char*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto cert_size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_pki_add_mfg_trust_anchor(device, cert, cert_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCPki::add_mfg_intermediate_cert(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto credid = static_cast<int>(info[1].ToNumber());
    auto cert = reinterpret_cast<const unsigned char*>(info[2].As<TypedArray>().ArrayBuffer().Data());
    auto cert_size = static_cast<size_t>(info[3].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_pki_add_mfg_intermediate_cert(device, credid, cert, cert_size));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCPki::add_trust_anchor(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto cert = reinterpret_cast<const unsigned char*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto cert_size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_pki_add_trust_anchor(device, cert, cert_size));
}
#endif

#if defined(OC_SECURITY)
Value OCPki::set_security_profile(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto supported_profiles = static_cast<oc_sp_types_t>(info[1].ToNumber().Uint32Value());
    auto current_profile = static_cast<oc_sp_types_t>(info[2].ToNumber().Uint32Value());
    auto mfg_credid = static_cast<int>(info[3].ToNumber());
    (void)oc_pki_set_security_profile(device, supported_profiles, current_profile, mfg_credid);
    return info.Env().Undefined();
}
#endif

OCRandom::OCRandom(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCRandom::GetClass(Napi::Env env) {
    return DefineClass(env, "OCRandom", {
        StaticMethod("init", &OCRandom::init),
        StaticMethod("destroy", &OCRandom::destroy),
        StaticMethod("random_value", &OCRandom::random_value),
    });
}
Napi::FunctionReference OCRandom::constructor;


Value OCRandom::init(const CallbackInfo& info) {
    (void)oc_random_init();
    return info.Env().Undefined();
}

Value OCRandom::destroy(const CallbackInfo& info) {
    (void)oc_random_destroy();
    return info.Env().Undefined();
}

Value OCRandom::random_value(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_random_value());
}

OCSWUpdate::OCSWUpdate(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCSWUpdate::GetClass(Napi::Env env) {
    return DefineClass(env, "OCSWUpdate", {
#if defined(OC_SOFTWARE_UPDATE)
        StaticMethod("notify_downloaded", &OCSWUpdate::notify_downloaded),
#endif
#if defined(OC_SOFTWARE_UPDATE)
        StaticMethod("notify_upgrading", &OCSWUpdate::notify_upgrading),
#endif
#if defined(OC_SOFTWARE_UPDATE)
        StaticMethod("notify_done", &OCSWUpdate::notify_done),
#endif
#if defined(OC_SOFTWARE_UPDATE)
        StaticMethod("notify_new_version_available", &OCSWUpdate::notify_new_version_available),
#endif
#if defined(OC_SOFTWARE_UPDATE)
        StaticMethod("set_impl", &OCSWUpdate::set_impl),
#endif
    });
}
Napi::FunctionReference OCSWUpdate::constructor;


#if defined(OC_SOFTWARE_UPDATE)
Value OCSWUpdate::notify_downloaded(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto version_ = info[1].ToString().Utf8Value();
    auto version = version_.c_str();
    auto result = static_cast<oc_swupdate_result_t>(info[2].ToNumber().Uint32Value());
    (void)oc_swupdate_notify_downloaded(device, version, result);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Value OCSWUpdate::notify_upgrading(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto version_ = info[1].ToString().Utf8Value();
    auto version = version_.c_str();
    auto timestamp = static_cast<uint64_t>(info[2].ToNumber().Int64Value());
    auto result = static_cast<oc_swupdate_result_t>(info[3].ToNumber().Uint32Value());
    (void)oc_swupdate_notify_upgrading(device, version, timestamp, result);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Value OCSWUpdate::notify_done(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto result = static_cast<oc_swupdate_result_t>(info[1].ToNumber().Uint32Value());
    (void)oc_swupdate_notify_done(device, result);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Value OCSWUpdate::notify_new_version_available(const CallbackInfo& info) {
    auto device = static_cast<size_t>(info[0].ToNumber().Uint32Value());
    auto version_ = info[1].ToString().Utf8Value();
    auto version = version_.c_str();
    auto result = static_cast<oc_swupdate_result_t>(info[2].ToNumber().Uint32Value());
    (void)oc_swupdate_notify_new_version_available(device, version, result);
    return info.Env().Undefined();
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Value OCSWUpdate::set_impl(const CallbackInfo& info) {
    auto& swupdate_impl = *OCSoftwareUpdateHandler::Unwrap(info[0].ToObject());
    main_context->oc_swupdate_cb_validate_purl_ref.Reset(swupdate_impl.validate_purl.Value());
    main_context->oc_swupdate_cb_check_new_version_ref.Reset(swupdate_impl.check_new_version.Value());
    main_context->oc_swupdate_cb_download_update_ref.Reset(swupdate_impl.download_update.Value());
    main_context->oc_swupdate_cb_perform_upgrade_ref.Reset(swupdate_impl.perform_upgrade.Value());
    swupdate_impl.m_pvalue->validate_purl = oc_swupdate_cb_validate_purl_helper;
    swupdate_impl.m_pvalue->check_new_version = oc_swupdate_cb_check_new_version_helper;
    swupdate_impl.m_pvalue->download_update = oc_swupdate_cb_download_update_helper;
    swupdate_impl.m_pvalue->perform_upgrade = oc_swupdate_cb_perform_upgrade_helper;
    (void)oc_swupdate_set_impl(swupdate_impl);
    return info.Env().Undefined();
}
#endif

OCSession::OCSession(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCSession::GetClass(Napi::Env env) {
    return DefineClass(env, "OCSession", {
#if defined(OC_TCP)
        StaticMethod("start_event", &OCSession::start_event),
#endif
#if defined(OC_TCP)
        StaticMethod("end_event", &OCSession::end_event),
#endif
#if defined(OC_TCP)
        StaticMethod("set_event_delay", &OCSession::set_event_delay),
#endif
    });
}
Napi::FunctionReference OCSession::constructor;


#if defined(OC_TCP)
Value OCSession::start_event(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    (void)oc_session_start_event(endpoint);
    return info.Env().Undefined();
}
#endif

#if defined(OC_TCP)
Value OCSession::end_event(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info[0].ToObject());
    (void)oc_session_end_event(endpoint);
    return info.Env().Undefined();
}
#endif

#if defined(OC_TCP)
Value OCSession::set_event_delay(const CallbackInfo& info) {
    auto secs = static_cast<int>(info[0].ToNumber());
    (void)oc_session_events_set_event_delay(secs);
    return info.Env().Undefined();
}
#endif

OCStorage::OCStorage(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function OCStorage::GetClass(Napi::Env env) {
    return DefineClass(env, "OCStorage", {
        StaticMethod("config", &OCStorage::config),
        StaticMethod("read", &OCStorage::read),
        StaticMethod("write", &OCStorage::write),
    });
}
Napi::FunctionReference OCStorage::constructor;


Value OCStorage::config(const CallbackInfo& info) {
    auto store_ = info[0].ToString().Utf8Value();
    auto store = store_.c_str();
    return Number::New(info.Env(), oc_storage_config(store));
}

Value OCStorage::read(const CallbackInfo& info) {
    auto store_ = info[0].ToString().Utf8Value();
    auto store = store_.c_str();
    auto buf = reinterpret_cast<uint8_t*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_storage_read(store, buf, size));
}

Value OCStorage::write(const CallbackInfo& info) {
    auto store_ = info[0].ToString().Utf8Value();
    auto store = store_.c_str();
    auto buf = reinterpret_cast<uint8_t*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto size = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    return Number::New(info.Env(), oc_storage_write(store, buf, size));
}

