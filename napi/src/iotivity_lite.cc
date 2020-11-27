#include "iotivity_lite.h"
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_add_device(uri, rt, name, spec_version, data_model_version, add_device_cb, data));
}

#if defined(OC_SECURITY)
Value OCMain::add_ownership_status_cb(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_ownership_status_cb);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_get(uri, endpoint, query, handler, qos, user_data));
}

Value OCMain::do_ip_discovery(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery(rt, handler, user_data));
}

Value OCMain::do_ip_discovery_all(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery_all(handler, user_data));
}

Value OCMain::do_ip_discovery_all_at_endpoint(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_ip_discovery_all_at_endpoint(handler, endpoint, user_data));
}

Value OCMain::do_ip_discovery_at_endpoint(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto& endpoint = *OCEndpoint::Unwrap(info[2].ToObject());
    auto user_data =  check_callback_context(info, O_FUNC, 3);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_realm_local_ipv6_discovery(rt, handler, user_data));
}

Value OCMain::do_realm_local_ipv6_discovery_all(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_realm_local_ipv6_multicast(uri, query, handler, user_data));
}

Value OCMain::do_site_local_ipv6_discovery(const CallbackInfo& info) {
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    auto handler = check_callback_func(info, 1, helper_oc_discovery_handler);
    const int O_FUNC = 1;
    auto user_data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
    return Boolean::New(info.Env(), oc_do_site_local_ipv6_discovery(rt, handler, user_data));
}

Value OCMain::do_site_local_ipv6_discovery_all(const CallbackInfo& info) {
    auto handler = check_callback_func(info, 0, helper_oc_discovery_all_handler);
    const int O_FUNC = 0;
    auto user_data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(user_data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(cb_data));
    (void)oc_set_delayed_callback(cb_data, callback, seconds);
    return info.Env().Undefined();

}

Value OCMain::set_factory_presets_cb(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_factory_presets_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    (void)oc_set_factory_presets_cb(cb, data);
    return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Value OCMain::set_random_pin_callback(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_random_pin_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
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
    auto cb = check_callback_func(info, 1, helper_oc_obt_device_status_cb);
    const int O_FUNC = 1;
    auto data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
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
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_discover_owned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_owned_devices_realm_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_discover_owned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_owned_devices_site_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_discover_owned_devices_site_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_unowned_devices(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_discover_unowned_devices(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_unowned_devices_realm_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_discover_unowned_devices_realm_local_ipv6(cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::discover_unowned_devices_site_local_ipv6(const CallbackInfo& info) {
    auto cb = check_callback_func(info, 0, helper_oc_obt_discovery_cb);
    const int O_FUNC = 0;
    auto data =  check_callback_context(info, O_FUNC, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
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
    auto cb = check_callback_func(info, 1, helper_oc_obt_device_status_cb);
    const int O_FUNC = 1;
    auto data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_perform_cert_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::perform_just_works_otm(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    auto cb = check_callback_func(info, 1, helper_oc_obt_device_status_cb);
    const int O_FUNC = 1;
    auto data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_perform_just_works_otm(uuid, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::perform_random_pin_otm(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    auto pin = reinterpret_cast<const unsigned char*>(info[1].As<TypedArray>().ArrayBuffer().Data());
    auto pin_len = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    auto cb = check_callback_func(info, 3, helper_oc_obt_device_status_cb);
    const int O_FUNC = 3;
    auto data =  check_callback_context(info, O_FUNC, 4);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_perform_random_pin_otm(uuid, pin, pin_len, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::provision_ace(const CallbackInfo& info) {
    auto& subject = *OCUuid::Unwrap(info[0].ToObject());
    auto& ace = *OCSecurityAce::Unwrap(info[1].ToObject());
    auto cb = check_callback_func(info, 2, helper_oc_obt_device_status_cb);
    const int O_FUNC = 2;
    auto data =  check_callback_context(info, O_FUNC, 3);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_provision_ace(subject, ace, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::provision_auth_wildcard_ace(const CallbackInfo& info) {
    auto& subject = *OCUuid::Unwrap(info[0].ToObject());
    auto cb = check_callback_func(info, 1, helper_oc_obt_device_status_cb);
    const int O_FUNC = 1;
    auto data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
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
    auto cb = check_callback_func(info, 3, helper_oc_obt_device_status_cb);
    const int O_FUNC = 3;
    auto data =  check_callback_context(info, O_FUNC, 4);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
    return Number::New(info.Env(), oc_obt_provision_role_wildcard_ace(subject, role, authority, cb, data));
}
#endif

#if defined(OC_SECURITY)
Value OCObt::request_random_pin(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info[0].ToObject());
    auto cb = check_callback_func(info, 1, helper_oc_obt_device_status_cb);
    const int O_FUNC = 1;
    auto data =  check_callback_context(info, O_FUNC, 2);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(data));
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

Napi::Object module_init(Napi::Env env, Napi::Object exports) {
    exports.Set("add_collection", Napi::Function::New(env, OCMain::add_collection));
    exports.Set("add_device", Napi::Function::New(env, OCMain::add_device));
#if defined(OC_SECURITY)
    exports.Set("add_ownership_status_cb", Napi::Function::New(env, OCMain::add_ownership_status_cb));
#endif
    exports.Set("add_resource", Napi::Function::New(env, OCMain::add_resource));
#if defined(OC_SECURITY) && defined(OC_PKI)
    exports.Set("assert_all_roles", Napi::Function::New(env, OCMain::assert_all_roles));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    exports.Set("assert_role", Napi::Function::New(env, OCMain::assert_role));
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    exports.Set("auto_assert_roles", Napi::Function::New(env, OCMain::auto_assert_roles));
#endif
    exports.Set("close_session", Napi::Function::New(env, OCMain::close_session));
    exports.Set("delete_link", Napi::Function::New(env, OCMain::delete_link));
    exports.Set("delete_resource", Napi::Function::New(env, OCMain::delete_resource));
    exports.Set("device_bind_resource_type", Napi::Function::New(env, OCMain::device_bind_resource_type));
    exports.Set("do_delete", Napi::Function::New(env, OCMain::do_delete));
    exports.Set("do_get", Napi::Function::New(env, OCMain::do_get));
    exports.Set("do_ip_discovery", Napi::Function::New(env, OCMain::do_ip_discovery));
    exports.Set("do_ip_discovery_all", Napi::Function::New(env, OCMain::do_ip_discovery_all));
    exports.Set("do_ip_discovery_all_at_endpoint", Napi::Function::New(env, OCMain::do_ip_discovery_all_at_endpoint));
    exports.Set("do_ip_discovery_at_endpoint", Napi::Function::New(env, OCMain::do_ip_discovery_at_endpoint));
    exports.Set("do_ip_multicast", Napi::Function::New(env, OCMain::do_ip_multicast));
    exports.Set("do_observe", Napi::Function::New(env, OCMain::do_observe));
    exports.Set("do_post", Napi::Function::New(env, OCMain::do_post));
    exports.Set("do_put", Napi::Function::New(env, OCMain::do_put));
    exports.Set("do_realm_local_ipv6_discovery", Napi::Function::New(env, OCMain::do_realm_local_ipv6_discovery));
    exports.Set("do_realm_local_ipv6_discovery_all", Napi::Function::New(env, OCMain::do_realm_local_ipv6_discovery_all));
    exports.Set("do_realm_local_ipv6_multicast", Napi::Function::New(env, OCMain::do_realm_local_ipv6_multicast));
    exports.Set("do_site_local_ipv6_discovery", Napi::Function::New(env, OCMain::do_site_local_ipv6_discovery));
    exports.Set("do_site_local_ipv6_discovery_all", Napi::Function::New(env, OCMain::do_site_local_ipv6_discovery_all));
    exports.Set("do_site_local_ipv6_multicast", Napi::Function::New(env, OCMain::do_site_local_ipv6_multicast));
    exports.Set("free_server_endpoints", Napi::Function::New(env, OCMain::free_server_endpoints));
#if defined(OC_SECURITY) && defined(OC_PKI)
    exports.Set("get_all_roles", Napi::Function::New(env, OCMain::get_all_roles));
#endif
    exports.Set("get_con_res_announced", Napi::Function::New(env, OCMain::get_con_res_announced));
    exports.Set("ignore_request", Napi::Function::New(env, OCMain::ignore_request));
    exports.Set("indicate_separate_response", Napi::Function::New(env, OCMain::indicate_separate_response));
    exports.Set("init_platform", Napi::Function::New(env, OCMain::init_platform));
    exports.Set("init_post", Napi::Function::New(env, OCMain::init_post));
    exports.Set("init_put", Napi::Function::New(env, OCMain::init_put));
#if defined(OC_SECURITY)
    exports.Set("is_owned_device", Napi::Function::New(env, OCMain::is_owned_device));
#endif
    exports.Set("link_add_link_param", Napi::Function::New(env, OCMain::link_add_link_param));
    exports.Set("link_add_rel", Napi::Function::New(env, OCMain::link_add_rel));
    exports.Set("main_init", Napi::Function::New(env, OCMain::main_init));
    exports.Set("main_loop", Napi::Function::New(env, OCMain::main_loop));
    exports.Set("main_shutdown", Napi::Function::New(env, OCMain::main_shutdown));
    exports.Set("new_link", Napi::Function::New(env, OCMain::new_link));
    exports.Set("remove_delayed_callback", Napi::Function::New(env, OCMain::remove_delayed_callback));
#if defined(OC_SECURITY)
    exports.Set("remove_ownership_status_cb", Napi::Function::New(env, OCMain::remove_ownership_status_cb));
#endif
#if defined(OC_SECURITY)
    exports.Set("reset", Napi::Function::New(env, OCMain::reset));
#endif
#if defined(OC_SECURITY)
    exports.Set("reset_device", Napi::Function::New(env, OCMain::reset_device));
#endif
    exports.Set("ri_is_app_resource_valid", Napi::Function::New(env, OCMain::ri_is_app_resource_valid));
    exports.Set("send_diagnostic_message", Napi::Function::New(env, OCMain::send_diagnostic_message));
#if defined(OC_TCP)
    exports.Set("send_ping", Napi::Function::New(env, OCMain::send_ping));
#endif
    exports.Set("send_response", Napi::Function::New(env, OCMain::send_response));
    exports.Set("send_response_raw", Napi::Function::New(env, OCMain::send_response_raw));
    exports.Set("send_separate_response", Napi::Function::New(env, OCMain::send_separate_response));
    exports.Set("set_con_res_announced", Napi::Function::New(env, OCMain::set_con_res_announced));
    exports.Set("set_con_write_cb", Napi::Function::New(env, OCMain::set_con_write_cb));
    exports.Set("set_delayed_callback", Napi::Function::New(env, OCMain::set_delayed_callback));
    exports.Set("set_factory_presets_cb", Napi::Function::New(env, OCMain::set_factory_presets_cb));
#if defined(OC_SECURITY)
    exports.Set("set_random_pin_callback", Napi::Function::New(env, OCMain::set_random_pin_callback));
#endif
    exports.Set("set_separate_response_buffer", Napi::Function::New(env, OCMain::set_separate_response_buffer));
    exports.Set("stop_multicast", Napi::Function::New(env, OCMain::stop_multicast));
    exports.Set("stop_observe", Napi::Function::New(env, OCMain::stop_observe));
    exports.Set("set_mtu_size", Napi::Function::New(env, OCMain::set_mtu_size));
    exports.Set("get_mtu_size", Napi::Function::New(env, OCMain::get_mtu_size));
    exports.Set("set_max_app_data_size", Napi::Function::New(env, OCMain::set_max_app_data_size));
    exports.Set("get_max_app_data_size", Napi::Function::New(env, OCMain::get_max_app_data_size));
    exports.Set("get_block_size", Napi::Function::New(env, OCMain::get_block_size));
    exports.Set("add_network_interface_event_callback", Napi::Function::New(env, OCMain::add_network_interface_event_callback));
    exports.Set("remove_network_interface_event_callback", Napi::Function::New(env, OCMain::remove_network_interface_event_callback));
    exports.Set("add_session_event_callback", Napi::Function::New(env, OCMain::add_session_event_callback));
    exports.Set("remove_session_event_callback", Napi::Function::New(env, OCMain::remove_session_event_callback));
    exports.Set("base64_decode", Napi::Function::New(env, OCMain::base64_decode));
    exports.Set("base64_encode", Napi::Function::New(env, OCMain::base64_encode));
    exports.Set("dns_lookup", Napi::Function::New(env, OCMain::dns_lookup));
    exports.Set("CborEncoder", OCCborEncoder::GetClass(env));
    exports.Set("AceResourceIterator", OCAceResourceIterator::GetClass(env));
    exports.Set("AceResource", OCAceResource::GetClass(env));
    exports.Set("AceSubject", OCAceSubject::GetClass(env));
    exports.Set("Array", OCArray::GetClass(env));
    exports.Set("ClientCallback", OCClientCallback::GetClass(env));
    exports.Set("ClientHandler", OCClientHandler::GetClass(env));
    exports.Set("ClientResponse", OCClientResponse::GetClass(env));
    exports.Set("CloudContextIterator", OCCloudContextIterator::GetClass(env));
    exports.Set("CloudContext", OCCloudContext::GetClass(env));
    exports.Set("CloudStore", OCCloudStore::GetClass(env));
    exports.Set("CollectionIterator", OCCollectionIterator::GetClass(env));
    exports.Set("Collection", OCCollection::GetClass(env));
    exports.Set("CredData", OCCredData::GetClass(env));
    exports.Set("DeviceInfo", OCDeviceInfo::GetClass(env));
    exports.Set("EndpointIterator", OCEndpointIterator::GetClass(env));
    exports.Set("Endpoint", OCEndpoint::GetClass(env));
    exports.Set("DevAddr", DevAddr::GetClass(env));
    exports.Set("EventCallbackIterator", OCEventCallbackIterator::GetClass(env));
    exports.Set("EventCallback", OCEventCallback::GetClass(env));
    exports.Set("Handler", OCHandler::GetClass(env));
    exports.Set("IPv4Addr", OCIPv4Addr::GetClass(env));
    exports.Set("IPv6Addr", OCIPv6Addr::GetClass(env));
    exports.Set("LEAddr", OCLEAddr::GetClass(env));
    exports.Set("LinkIterator", OCLinkIterator::GetClass(env));
    exports.Set("LinkParamsIterator", OCLinkParamsIterator::GetClass(env));
    exports.Set("LinkParams", OCLinkParams::GetClass(env));
    exports.Set("Link", OCLink::GetClass(env));
    exports.Set("Memb", OCMemb::GetClass(env));
    exports.Set("MessageIterator", OCMessageIterator::GetClass(env));
    exports.Set("Message", OCMessage::GetClass(env));
    exports.Set("Mmem", OCMmem::GetClass(env));
    exports.Set("NetworkInterfaceCb", OCNetworkInterfaceCb::GetClass(env));
    exports.Set("PlatformInfo", OCPlatformInfo::GetClass(env));
    exports.Set("PropertiesCb", OCPropertiesCb::GetClass(env));
    exports.Set("RepresentationIterator", OCRepresentationIterator::GetClass(env));
    exports.Set("Representation", OCRepresentation::GetClass(env));
    exports.Set("Value", OCValue::GetClass(env));
    exports.Set("RequestHandler", OCRequestHandler::GetClass(env));
    exports.Set("Request", OCRequest::GetClass(env));
    exports.Set("Resource", OCResource::GetClass(env));
    exports.Set("ResponseBuffer", OCResponseBuffer::GetClass(env));
    exports.Set("Response", OCResponse::GetClass(env));
    exports.Set("RoleIterator", OCRoleIterator::GetClass(env));
    exports.Set("Role", OCRole::GetClass(env));
    exports.Set("ResourceTypeIterator", OCResourceTypeIterator::GetClass(env));
    exports.Set("ResourceType", OCResourceType::GetClass(env));
    exports.Set("SecurityAceIterator", OCSecurityAceIterator::GetClass(env));
    exports.Set("SecurityAce", OCSecurityAce::GetClass(env));
    exports.Set("SecurityAcl", OCSecurityAcl::GetClass(env));
    exports.Set("Cred", OCCred::GetClass(env));
    exports.Set("Creds", OCCreds::GetClass(env));
    exports.Set("SeparateResponse", OCSeparateResponse::GetClass(env));
    exports.Set("SessionEventCb", OCSessionEventCb::GetClass(env));
    exports.Set("SessionEventCbIterator", OCSessionEventCbIterator::GetClass(env));
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
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ACE_NO_WC", &OCAceWildcard::get_OC_ACE_NO_WC));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ACE_WC_ALL", &OCAceWildcard::get_OC_ACE_WC_ALL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ACE_WC_ALL_PUBLIC", &OCAceWildcard::get_OC_ACE_WC_ALL_PUBLIC));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ACE_WC_ALL_SECURED", &OCAceWildcard::get_OC_ACE_WC_ALL_SECURED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_ATOM_XML", &OCContentFormat::get_APPLICATION_ATOM_XML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_CBOR", &OCContentFormat::get_APPLICATION_CBOR));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_EXI", &OCContentFormat::get_APPLICATION_EXI));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_FASTINFOSET", &OCContentFormat::get_APPLICATION_FASTINFOSET));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_JSON", &OCContentFormat::get_APPLICATION_JSON));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_LINK_FORMAT", &OCContentFormat::get_APPLICATION_LINK_FORMAT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_OCTET_STREAM", &OCContentFormat::get_APPLICATION_OCTET_STREAM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_RDF_XML", &OCContentFormat::get_APPLICATION_RDF_XML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_SOAP_FASTINFOSET", &OCContentFormat::get_APPLICATION_SOAP_FASTINFOSET));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_SOAP_XML", &OCContentFormat::get_APPLICATION_SOAP_XML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_VND_OCF_CBOR", &OCContentFormat::get_APPLICATION_VND_OCF_CBOR));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_XML", &OCContentFormat::get_APPLICATION_XML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_XMPP_XML", &OCContentFormat::get_APPLICATION_XMPP_XML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("APPLICATION_X_OBIX_BINARY", &OCContentFormat::get_APPLICATION_X_OBIX_BINARY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("AUDIO_RAW", &OCContentFormat::get_AUDIO_RAW));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("BLOCKWISE_CLIENT", &OCBlockwiseRole::get_OC_BLOCKWISE_CLIENT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("BLOCKWISE_SERVER", &OCBlockwiseRole::get_OC_BLOCKWISE_SERVER));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_DEREGISTERED", &OCCloudStatusMask::get_OC_CLOUD_DEREGISTERED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_ERROR_CONNECT", &OCCloudError::get_CLOUD_ERROR_CONNECT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_ERROR_REFRESH_ACCESS_TOKEN", &OCCloudError::get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_ERROR_RESPONSE", &OCCloudError::get_CLOUD_ERROR_RESPONSE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_FAILURE", &OCCloudStatusMask::get_OC_CLOUD_FAILURE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_INITIALIZED", &OCCloudStatusMask::get_OC_CLOUD_INITIALIZED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_LOGGED_IN", &OCCloudStatusMask::get_OC_CLOUD_LOGGED_IN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_LOGGED_OUT", &OCCloudStatusMask::get_OC_CLOUD_LOGGED_OUT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_OK", &OCCloudError::get_CLOUD_OK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_REFRESHED_TOKEN", &OCCloudStatusMask::get_OC_CLOUD_REFRESHED_TOKEN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_REGISTERED", &OCCloudStatusMask::get_OC_CLOUD_REGISTERED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CLOUD_TOKEN_EXPIRY", &OCCloudStatusMask::get_OC_CLOUD_TOKEN_EXPIRY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CONN_ANON_CLEAR", &OCAceConnectionType::get_OC_CONN_ANON_CLEAR));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CONN_AUTH_CRYPT", &OCAceConnectionType::get_OC_CONN_AUTH_CRYPT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CONTINUE_DISCOVERY", &OCDiscoveryFlags::get_OC_CONTINUE_DISCOVERY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CPS_FAILED", &OCCloudPrivisoningStatus::get_OC_CPS_FAILED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CPS_READYTOREGISTER", &OCCloudPrivisoningStatus::get_OC_CPS_READYTOREGISTER));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CPS_REGISTERED", &OCCloudPrivisoningStatus::get_OC_CPS_REGISTERED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CPS_REGISTERING", &OCCloudPrivisoningStatus::get_OC_CPS_REGISTERING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CPS_UNINITIALIZED", &OCCloudPrivisoningStatus::get_OC_CPS_UNINITIALIZED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDTYPE_CERT", &OCCredType::get_OC_CREDTYPE_CERT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDTYPE_NULL", &OCCredType::get_OC_CREDTYPE_NULL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDTYPE_PSK", &OCCredType::get_OC_CREDTYPE_PSK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDUSAGE_IDENTITY_CERT", &OCCredUsage::get_OC_CREDUSAGE_IDENTITY_CERT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDUSAGE_MFG_CERT", &OCCredUsage::get_OC_CREDUSAGE_MFG_CERT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDUSAGE_MFG_TRUSTCA", &OCCredUsage::get_OC_CREDUSAGE_MFG_TRUSTCA));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDUSAGE_NULL", &OCCredUsage::get_OC_CREDUSAGE_NULL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDUSAGE_ROLE_CERT", &OCCredUsage::get_OC_CREDUSAGE_ROLE_CERT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CREDUSAGE_TRUSTCA", &OCCredUsage::get_OC_CREDUSAGE_TRUSTCA));
#if defined(OC_TCP)
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CSM_DONE", &tcpCsmState::get_CSM_DONE));
#endif
#if defined(OC_TCP)
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CSM_ERROR", &tcpCsmState::get_CSM_ERROR));
#endif
#if defined(OC_TCP)
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CSM_NONE", &tcpCsmState::get_CSM_NONE));
#endif
#if defined(OC_TCP)
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("CSM_SENT", &tcpCsmState::get_CSM_SENT));
#endif
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("DELETE", &OCMethod::get_OC_DELETE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("DISCOVERABLE", &OCResourcePropertiesMask::get_OC_DISCOVERABLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("DISCOVERY", &OCTransportFlags::get_DISCOVERY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENCODING_BASE64", &OCEncoding::get_OC_ENCODING_BASE64));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENCODING_HANDLE", &OCEncoding::get_OC_ENCODING_HANDLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENCODING_PEM", &OCEncoding::get_OC_ENCODING_PEM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENCODING_RAW", &OCEncoding::get_OC_ENCODING_RAW));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENCODING_UNSUPPORTED", &OCEncoding::get_OC_ENCODING_UNSUPPORTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ABORTED", &OCEnum::get_OC_ENUM_ABORTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ACTIVE", &OCEnum::get_OC_ENUM_ACTIVE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_AI", &OCEnum::get_OC_ENUM_AI));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_AIRDRY", &OCEnum::get_OC_ENUM_AIRDRY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ARMEDAWAY", &OCEnum::get_OC_ENUM_ARMEDAWAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ARMEDINSTANT", &OCEnum::get_OC_ENUM_ARMEDINSTANT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ARMEDMAXIMUM", &OCEnum::get_OC_ENUM_ARMEDMAXIMUM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ARMEDNIGHTSTAY", &OCEnum::get_OC_ENUM_ARMEDNIGHTSTAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ARMEDSTAY", &OCEnum::get_OC_ENUM_ARMEDSTAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_AROMA", &OCEnum::get_OC_ENUM_AROMA));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_AUTO", &OCEnum::get_OC_ENUM_AUTO));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_BOILING", &OCEnum::get_OC_ENUM_BOILING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_BREWING", &OCEnum::get_OC_ENUM_BREWING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_CANCELLED", &OCEnum::get_OC_ENUM_CANCELLED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_CIRCULATING", &OCEnum::get_OC_ENUM_CIRCULATING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_CLEANING", &OCEnum::get_OC_ENUM_CLEANING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_CLOTHES", &OCEnum::get_OC_ENUM_CLOTHES));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_COMPLETED", &OCEnum::get_OC_ENUM_COMPLETED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_COOL", &OCEnum::get_OC_ENUM_COOL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_DELICATE", &OCEnum::get_OC_ENUM_DELICATE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_DISABLED", &OCEnum::get_OC_ENUM_DISABLED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_DOWN", &OCEnum::get_OC_ENUM_DOWN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_DRY", &OCEnum::get_OC_ENUM_DRY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_DUAL", &OCEnum::get_OC_ENUM_DUAL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ENABLED", &OCEnum::get_OC_ENUM_ENABLED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_EXTENDED", &OCEnum::get_OC_ENUM_EXTENDED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_FAN", &OCEnum::get_OC_ENUM_FAN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_FAST", &OCEnum::get_OC_ENUM_FAST));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_FILTERMATERIAL", &OCEnum::get_OC_ENUM_FILTERMATERIAL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_FOCUSED", &OCEnum::get_OC_ENUM_FOCUSED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_GRINDING", &OCEnum::get_OC_ENUM_GRINDING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_HEATING", &OCEnum::get_OC_ENUM_HEATING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_HEAVY", &OCEnum::get_OC_ENUM_HEAVY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_IDLE", &OCEnum::get_OC_ENUM_IDLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_INK", &OCEnum::get_OC_ENUM_INK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_INKBLACK", &OCEnum::get_OC_ENUM_INKBLACK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_INKCYAN", &OCEnum::get_OC_ENUM_INKCYAN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_INKMAGENTA", &OCEnum::get_OC_ENUM_INKMAGENTA));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_INKTRICOLOUR", &OCEnum::get_OC_ENUM_INKTRICOLOUR));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_INKYELLOW", &OCEnum::get_OC_ENUM_INKYELLOW));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_KEEPWARM", &OCEnum::get_OC_ENUM_KEEPWARM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_NORMAL", &OCEnum::get_OC_ENUM_NORMAL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_NOTSUPPORTED", &OCEnum::get_OC_ENUM_NOTSUPPORTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PAUSE", &OCEnum::get_OC_ENUM_PAUSE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PENDING", &OCEnum::get_OC_ENUM_PENDING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PENDINGHELD", &OCEnum::get_OC_ENUM_PENDINGHELD));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PERMAPRESS", &OCEnum::get_OC_ENUM_PERMAPRESS));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PREWASH", &OCEnum::get_OC_ENUM_PREWASH));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PROCESSING", &OCEnum::get_OC_ENUM_PROCESSING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_PURE", &OCEnum::get_OC_ENUM_PURE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_QUICK", &OCEnum::get_OC_ENUM_QUICK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_QUIET", &OCEnum::get_OC_ENUM_QUIET));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_RINSE", &OCEnum::get_OC_ENUM_RINSE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_SECTORED", &OCEnum::get_OC_ENUM_SECTORED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_SILENT", &OCEnum::get_OC_ENUM_SILENT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_SLEEP", &OCEnum::get_OC_ENUM_SLEEP));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_SMART", &OCEnum::get_OC_ENUM_SMART));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_SPIN", &OCEnum::get_OC_ENUM_SPIN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_SPOT", &OCEnum::get_OC_ENUM_SPOT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_STEAM", &OCEnum::get_OC_ENUM_STEAM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_STOPPED", &OCEnum::get_OC_ENUM_STOPPED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_TESTING", &OCEnum::get_OC_ENUM_TESTING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_TONER", &OCEnum::get_OC_ENUM_TONER));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_TONERBLACK", &OCEnum::get_OC_ENUM_TONERBLACK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_TONERCYAN", &OCEnum::get_OC_ENUM_TONERCYAN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_TONERMAGENTA", &OCEnum::get_OC_ENUM_TONERMAGENTA));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_TONERYELLOW", &OCEnum::get_OC_ENUM_TONERYELLOW));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_WARM", &OCEnum::get_OC_ENUM_WARM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_WASH", &OCEnum::get_OC_ENUM_WASH));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_WET", &OCEnum::get_OC_ENUM_WET));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_WIND", &OCEnum::get_OC_ENUM_WIND));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_WRINKLEPREVENT", &OCEnum::get_OC_ENUM_WRINKLEPREVENT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("ENUM_ZIGZAG", &OCEnum::get_OC_ENUM_ZIGZAG));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("EVENT_CONTINUE", &OCEventCallbackResult::get_OC_EVENT_CONTINUE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("EVENT_DONE", &OCEventCallbackResult::get_OC_EVENT_DONE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("GATT", &OCTransportFlags::get_GATT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("GET", &OCMethod::get_OC_GET));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("HIGH_QOS", &OCQos::get_HIGH_QOS));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_A", &OCInterfaceMask::get_OC_IF_A));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_B", &OCInterfaceMask::get_OC_IF_B));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_BASELINE", &OCInterfaceMask::get_OC_IF_BASELINE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_CREATE", &OCInterfaceMask::get_OC_IF_CREATE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_LL", &OCInterfaceMask::get_OC_IF_LL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_R", &OCInterfaceMask::get_OC_IF_R));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_RW", &OCInterfaceMask::get_OC_IF_RW));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IF_S", &OCInterfaceMask::get_OC_IF_S));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IGNORE", &OCStatus::get_OC_IGNORE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IMAGE_GIF", &OCContentFormat::get_IMAGE_GIF));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IMAGE_JPEG", &OCContentFormat::get_IMAGE_JPEG));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IMAGE_PNG", &OCContentFormat::get_IMAGE_PNG));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IMAGE_TIFF", &OCContentFormat::get_IMAGE_TIFF));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IPV4", &OCTransportFlags::get_IPV4));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("IPV6", &OCTransportFlags::get_IPV6));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("LOW_QOS", &OCQos::get_LOW_QOS));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("MULTICAST", &OCTransportFlags::get_MULTICAST));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("NETWORK_INTERFACE_DOWN", &OCInterfaceEvent::get_NETWORK_INTERFACE_DOWN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("NETWORK_INTERFACE_UP", &OCInterfaceEvent::get_NETWORK_INTERFACE_UP));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OBSERVABLE", &OCResourcePropertiesMask::get_OC_OBSERVABLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_COAPCLOUDCONF", &OCCoreResource::get_OCF_COAPCLOUDCONF));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_CON", &OCCoreResource::get_OCF_CON));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_D", &OCCoreResource::get_OCF_D));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_INTROSPECTION_DATA", &OCCoreResource::get_OCF_INTROSPECTION_DATA));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_INTROSPECTION_WK", &OCCoreResource::get_OCF_INTROSPECTION_WK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_MNT", &OCCoreResource::get_OCF_MNT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_P", &OCCoreResource::get_OCF_P));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_RES", &OCCoreResource::get_OCF_RES));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_ACL", &OCCoreResource::get_OCF_SEC_ACL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_AEL", &OCCoreResource::get_OCF_SEC_AEL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_CRED", &OCCoreResource::get_OCF_SEC_CRED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_CSR", &OCCoreResource::get_OCF_SEC_CSR));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_DOXM", &OCCoreResource::get_OCF_SEC_DOXM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_PSTAT", &OCCoreResource::get_OCF_SEC_PSTAT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_ROLES", &OCCoreResource::get_OCF_SEC_ROLES));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_SDI", &OCCoreResource::get_OCF_SEC_SDI));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SEC_SP", &OCCoreResource::get_OCF_SEC_SP));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_SW_UPDATE", &OCCoreResource::get_OCF_SW_UPDATE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OCF_VER_1_0_0", &OCFVersion::get_OCF_VER_1_0_0));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("OIC_VER_1_1_0", &OCFVersion::get_OIC_VER_1_1_0));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERIODIC", &OCResourcePropertiesMask::get_OC_PERIODIC));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERM_CREATE", &OCAcePermissionsMask::get_OC_PERM_CREATE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERM_DELETE", &OCAcePermissionsMask::get_OC_PERM_DELETE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERM_NONE", &OCAcePermissionsMask::get_OC_PERM_NONE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERM_NOTIFY", &OCAcePermissionsMask::get_OC_PERM_NOTIFY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERM_RETRIEVE", &OCAcePermissionsMask::get_OC_PERM_RETRIEVE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PERM_UPDATE", &OCAcePermissionsMask::get_OC_PERM_UPDATE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PING_TIMEOUT", &OCStatus::get_OC_PING_TIMEOUT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POST", &OCMethod::get_OC_POST));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_BOTTOM", &OCPositionDescription::get_OC_POS_BOTTOM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_BOTTOMCENTRE", &OCPositionDescription::get_OC_POS_BOTTOMCENTRE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_BOTTOMLEFT", &OCPositionDescription::get_OC_POS_BOTTOMLEFT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_BOTTOMRIGHT", &OCPositionDescription::get_OC_POS_BOTTOMRIGHT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_CENTRE", &OCPositionDescription::get_OC_POS_CENTRE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_CENTRELEFT", &OCPositionDescription::get_OC_POS_CENTRELEFT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_CENTRERIGHT", &OCPositionDescription::get_OC_POS_CENTRERIGHT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_LEFT", &OCPositionDescription::get_OC_POS_LEFT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_RIGHT", &OCPositionDescription::get_OC_POS_RIGHT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_TOP", &OCPositionDescription::get_OC_POS_TOP));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_TOPCENTRE", &OCPositionDescription::get_OC_POS_TOPCENTRE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_TOPLEFT", &OCPositionDescription::get_OC_POS_TOPLEFT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_TOPRIGHT", &OCPositionDescription::get_OC_POS_TOPRIGHT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("POS_UNKNOWN", &OCPositionDescription::get_OC_POS_UNKNOWN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("PUT", &OCMethod::get_OC_PUT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_ARRAY", &OCRepValueType::get_OC_REP_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_BOOL", &OCRepValueType::get_OC_REP_BOOL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_BOOL_ARRAY", &OCRepValueType::get_OC_REP_BOOL_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_BYTE_STRING", &OCRepValueType::get_OC_REP_BYTE_STRING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_BYTE_STRING_ARRAY", &OCRepValueType::get_OC_REP_BYTE_STRING_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_DOUBLE", &OCRepValueType::get_OC_REP_DOUBLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_DOUBLE_ARRAY", &OCRepValueType::get_OC_REP_DOUBLE_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_INT", &OCRepValueType::get_OC_REP_INT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_INT_ARRAY", &OCRepValueType::get_OC_REP_INT_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_NIL", &OCRepValueType::get_OC_REP_NIL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_OBJECT", &OCRepValueType::get_OC_REP_OBJECT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_OBJECT_ARRAY", &OCRepValueType::get_OC_REP_OBJECT_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_STRING", &OCRepValueType::get_OC_REP_STRING));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("REP_STRING_ARRAY", &OCRepValueType::get_OC_REP_STRING_ARRAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SECURE", &OCResourcePropertiesMask::get_OC_SECURE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SECURED", &OCTransportFlags::get_SECURED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SESSION_CONNECTED", &OCSessionState::get_OC_SESSION_CONNECTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SESSION_DISCONNECTED", &OCSessionState::get_OC_SESSION_DISCONNECTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SP_BASELINE", &OCSpTypesMask::get_OC_SP_BASELINE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SP_BLACK", &OCSpTypesMask::get_OC_SP_BLACK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SP_BLUE", &OCSpTypesMask::get_OC_SP_BLUE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SP_PURPLE", &OCSpTypesMask::get_OC_SP_PURPLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_BAD_GATEWAY", &OCStatus::get_OC_STATUS_BAD_GATEWAY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_BAD_OPTION", &OCStatus::get_OC_STATUS_BAD_OPTION));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_BAD_REQUEST", &OCStatus::get_OC_STATUS_BAD_REQUEST));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_CHANGED", &OCStatus::get_OC_STATUS_CHANGED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_CREATED", &OCStatus::get_OC_STATUS_CREATED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_DELETED", &OCStatus::get_OC_STATUS_DELETED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_FORBIDDEN", &OCStatus::get_OC_STATUS_FORBIDDEN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_GATEWAY_TIMEOUT", &OCStatus::get_OC_STATUS_GATEWAY_TIMEOUT));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_INTERNAL_SERVER_ERROR", &OCStatus::get_OC_STATUS_INTERNAL_SERVER_ERROR));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_METHOD_NOT_ALLOWED", &OCStatus::get_OC_STATUS_METHOD_NOT_ALLOWED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_NOT_ACCEPTABLE", &OCStatus::get_OC_STATUS_NOT_ACCEPTABLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_NOT_FOUND", &OCStatus::get_OC_STATUS_NOT_FOUND));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_NOT_IMPLEMENTED", &OCStatus::get_OC_STATUS_NOT_IMPLEMENTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_NOT_MODIFIED", &OCStatus::get_OC_STATUS_NOT_MODIFIED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_OK", &OCStatus::get_OC_STATUS_OK));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_PROXYING_NOT_SUPPORTED", &OCStatus::get_OC_STATUS_PROXYING_NOT_SUPPORTED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_REQUEST_ENTITY_TOO_LARGE", &OCStatus::get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_SERVICE_UNAVAILABLE", &OCStatus::get_OC_STATUS_SERVICE_UNAVAILABLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_UNAUTHORIZED", &OCStatus::get_OC_STATUS_UNAUTHORIZED));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STATUS_UNSUPPORTED_MEDIA_TYPE", &OCStatus::get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("STOP_DISCOVERY", &OCDiscoveryFlags::get_OC_STOP_DISCOVERY));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SUBJECT_CONN", &OCAceSubjectType::get_OC_SUBJECT_CONN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SUBJECT_ROLE", &OCAceSubjectType::get_OC_SUBJECT_ROLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SUBJECT_UUID", &OCAceSubjectType::get_OC_SUBJECT_UUID));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_CONN_FAIL", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_IDLE", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_IDLE));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_INVALID_URL", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_LESS_FLASH", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_LESS_RAM", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_SUCCESS", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SUCCESS));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_SVV_FAIL", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("SWUPDATE_RESULT_UPGRADE_FAIL", &OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("TCP", &OCTransportFlags::get_TCP));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("TEXT_CSV", &OCContentFormat::get_TEXT_CSV));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("TEXT_HTML", &OCContentFormat::get_TEXT_HTML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("TEXT_PLAIN", &OCContentFormat::get_TEXT_PLAIN));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("TEXT_XML", &OCContentFormat::get_TEXT_XML));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("VIDEO_RAW", &OCContentFormat::get_VIDEO_RAW));
    exports.DefineProperty(Napi::PropertyDescriptor::Accessor("__NUM_OC_STATUS_CODES__", &OCStatus::get___NUM_OC_STATUS_CODES__));
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
    exports.Set("oc_abort", Napi::Function::New(env, N_oc_abort));
    exports.Set("oc_exit", Napi::Function::New(env, N_oc_exit));
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
    exports.Set("oc_check_if_collection", Napi::Function::New(env, N_oc_check_if_collection));
#if defined(OC_COLLECTIONS_IF_CREATE)
    exports.Set("oc_collections_free_rt_factories", Napi::Function::New(env, N_oc_collections_free_rt_factories));
#endif
    exports.Set("oc_handle_collection_request", Napi::Function::New(env, N_oc_handle_collection_request));
#if defined(OC_TCP)
    exports.Set("oc_connectivity_end_session", Napi::Function::New(env, N_oc_connectivity_end_session));
#endif
    exports.Set("oc_connectivity_get_endpoints", Napi::Function::New(env, N_oc_connectivity_get_endpoints));
    exports.Set("oc_connectivity_init", Napi::Function::New(env, N_oc_connectivity_init));
    exports.Set("oc_connectivity_shutdown", Napi::Function::New(env, N_oc_connectivity_shutdown));
    exports.Set("oc_send_buffer", Napi::Function::New(env, N_oc_send_buffer));
    exports.Set("oc_send_discovery_request", Napi::Function::New(env, N_oc_send_discovery_request));
    exports.Set("oc_store_uri", Napi::Function::New(env, N_oc_store_uri));
    exports.Set("oc_create_discovery_resource", Napi::Function::New(env, N_oc_create_discovery_resource));
    exports.Set("oc_concat_strings", Napi::Function::New(env, N_oc_concat_strings));
    exports.Set("oc_join_string_array", Napi::Function::New(env, N_oc_join_string_array));
    exports.Set("oc_memb_init", Napi::Function::New(env, N_oc_memb_init));
    exports.Set("oc_memb_inmemb", Napi::Function::New(env, N_oc_memb_inmemb));
    exports.Set("oc_memb_numfree", Napi::Function::New(env, N_oc_memb_numfree));
    exports.Set("oc_memb_set_buffers_avail_cb", Napi::Function::New(env, N_oc_memb_set_buffers_avail_cb));
    exports.Set("oc_mmem_init", Napi::Function::New(env, N_oc_mmem_init));
    exports.Set("oc_network_event", Napi::Function::New(env, N_oc_network_event));
    exports.Set("oc_network_interface_event", Napi::Function::New(env, N_oc_network_interface_event));
    exports.Set("oc_network_event_handler_mutex_destroy", Napi::Function::New(env, N_oc_network_event_handler_mutex_destroy));
    exports.Set("oc_network_event_handler_mutex_init", Napi::Function::New(env, N_oc_network_event_handler_mutex_init));
    exports.Set("oc_network_event_handler_mutex_lock", Napi::Function::New(env, N_oc_network_event_handler_mutex_lock));
    exports.Set("oc_network_event_handler_mutex_unlock", Napi::Function::New(env, N_oc_network_event_handler_mutex_unlock));
    exports.Set("oc_status_code", Napi::Function::New(env, N_oc_status_code));
    return exports;
}




Napi::FunctionReference OCAceResource::constructor;

Napi::Function OCAceResource::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAceResource", {
        InstanceAccessor("href", &OCAceResource::get_href, &OCAceResource::set_href),
        InstanceAccessor("interfaces", &OCAceResource::get_interfaces, &OCAceResource::set_interfaces),
        InstanceAccessor("types", &OCAceResource::get_types, &OCAceResource::set_types),
        InstanceAccessor("wildcard", &OCAceResource::get_wildcard, &OCAceResource::set_wildcard),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCAceResource::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAceResource::~OCAceResource()
{
}
OCAceResource::OCAceResource(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ace_res_t>(new oc_ace_res_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ace_res_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCAceResource::get_href(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->href, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCAceResource::set_href(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->href = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCAceResource::get_interfaces(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->interfaces);
}

void OCAceResource::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCAceResource::get_types(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_string_array_t> sp(&m_pvalue->types, nop_deleter);
    auto accessor = External<shared_ptr<oc_string_array_t>>::New(info.Env(), &sp);
    return OCStringArray::constructor.New({accessor});
}

void OCAceResource::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->types = *(*(value.As<External<shared_ptr<oc_string_array_t>>>().Data()));
}

Napi::Value OCAceResource::get_wildcard(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->wildcard);
}

void OCAceResource::set_wildcard(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->wildcard = static_cast<oc_ace_wildcard_t>(value.ToNumber().Uint32Value());
}




Napi::FunctionReference OCClientCallback::constructor;

Napi::Function OCClientCallback::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCClientCallback", {
        InstanceAccessor("discovery", &OCClientCallback::get_discovery, &OCClientCallback::set_discovery),
        InstanceAccessor("endpoint", &OCClientCallback::get_endpoint, &OCClientCallback::set_endpoint),
        InstanceAccessor("handler", &OCClientCallback::get_handler, &OCClientCallback::set_handler),
        InstanceAccessor("method", &OCClientCallback::get_method, &OCClientCallback::set_method),
        InstanceAccessor("mid", &OCClientCallback::get_mid, &OCClientCallback::set_mid),
        InstanceAccessor("multicast", &OCClientCallback::get_multicast, &OCClientCallback::set_multicast),
        InstanceAccessor("observe_seq", &OCClientCallback::get_observe_seq, &OCClientCallback::set_observe_seq),
        InstanceAccessor("qos", &OCClientCallback::get_qos, &OCClientCallback::set_qos),
        InstanceAccessor("query", &OCClientCallback::get_query, &OCClientCallback::set_query),
        InstanceAccessor("ref_count", &OCClientCallback::get_ref_count, &OCClientCallback::set_ref_count),
        InstanceAccessor("separate", &OCClientCallback::get_separate, &OCClientCallback::set_separate),
        InstanceAccessor("stop_multicast_receive", &OCClientCallback::get_stop_multicast_receive, &OCClientCallback::set_stop_multicast_receive),
        InstanceAccessor("timestamp", &OCClientCallback::get_timestamp, &OCClientCallback::set_timestamp),
        InstanceAccessor("token", &OCClientCallback::get_token, &OCClientCallback::set_token),
        InstanceAccessor("token_len", &OCClientCallback::get_token_len, &OCClientCallback::set_token_len),
        InstanceAccessor("uri", &OCClientCallback::get_uri, &OCClientCallback::set_uri),
        InstanceAccessor("user_data", &OCClientCallback::get_user_data, &OCClientCallback::set_user_data),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCClientCallback::~OCClientCallback()
{
}
OCClientCallback::OCClientCallback(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_client_cb_t>(new oc_client_cb_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_client_cb_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCClientCallback::get_discovery(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->discovery);
}

void OCClientCallback::set_discovery(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->discovery = value.ToBoolean().Value();
}

Napi::Value OCClientCallback::get_endpoint(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

void OCClientCallback::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->endpoint = *(*(value.As<External<shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value OCClientCallback::get_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_client_handler_t> sp(&m_pvalue->handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_client_handler_t>>::New(info.Env(), &sp);
    return OCClientHandler::constructor.New({accessor});
}

void OCClientCallback::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->handler = *(*(value.As<External<shared_ptr<oc_client_handler_t>>>().Data()));
}

Napi::Value OCClientCallback::get_method(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->method);
}

void OCClientCallback::set_method(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->method = static_cast<oc_method_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_mid(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->mid);
}

void OCClientCallback::set_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->mid = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_multicast(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->multicast);
}

void OCClientCallback::set_multicast(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->multicast = value.ToBoolean().Value();
}

Napi::Value OCClientCallback::get_observe_seq(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->observe_seq);
}

void OCClientCallback::set_observe_seq(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->observe_seq = value.ToNumber().Int32Value();
}

Napi::Value OCClientCallback::get_qos(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->qos);
}

void OCClientCallback::set_qos(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->qos = static_cast<oc_qos_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_query(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->query, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCClientCallback::set_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->query = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCClientCallback::get_ref_count(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->ref_count);
}

void OCClientCallback::set_ref_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->ref_count = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_separate(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->separate);
}

void OCClientCallback::set_separate(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->separate = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_stop_multicast_receive(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->stop_multicast_receive);
}

void OCClientCallback::set_stop_multicast_receive(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->stop_multicast_receive = value.ToBoolean().Value();
}

Napi::Value OCClientCallback::get_timestamp(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->timestamp);
}

void OCClientCallback::set_timestamp(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->timestamp = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_token(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);
}

void OCClientCallback::set_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) {
        m_pvalue->token[i] = reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data())[i];
    }
}

Napi::Value OCClientCallback::get_token_len(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->token_len);
}

void OCClientCallback::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->token_len = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientCallback::get_uri(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->uri, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCClientCallback::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->uri = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCClientCallback::get_user_data(const Napi::CallbackInfo& info)
{
    return user_data_ref.Get("user_data");
}

void OCClientCallback::set_user_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{

    Napi::Object obj = Napi::Object::New(info.Env());
    obj.Set("user_data", value);
    user_data_ref = Napi::Persistent(obj);
}

Napi::FunctionReference OCClientHandler::constructor;

Napi::Function OCClientHandler::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCClientHandler", {
        InstanceAccessor("discovery", &OCClientHandler::get_discovery, &OCClientHandler::set_discovery),
        InstanceAccessor("discovery_all", &OCClientHandler::get_discovery_all, &OCClientHandler::set_discovery_all),
        InstanceAccessor("response", &OCClientHandler::get_response, &OCClientHandler::set_response),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCClientHandler::~OCClientHandler()
{
}
OCClientHandler::OCClientHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_client_handler_t>(new oc_client_handler_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_client_handler_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCClientHandler::get_discovery(const Napi::CallbackInfo& info)
{
    return discovery_function;
}

void OCClientHandler::set_discovery(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    discovery_function = value;
}

Napi::Value OCClientHandler::get_discovery_all(const Napi::CallbackInfo& info)
{
    return discovery_all_function;
}

void OCClientHandler::set_discovery_all(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    discovery_all_function = value;
}

Napi::Value OCClientHandler::get_response(const Napi::CallbackInfo& info)
{
    return response_function;
}

void OCClientHandler::set_response(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    response_function = value;
}

Napi::FunctionReference OCClientResponse::constructor;

Napi::Function OCClientResponse::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCClientResponse", {
        InstanceAccessor("_payload", &OCClientResponse::get__payload, &OCClientResponse::set__payload),
        InstanceAccessor("_payload_len", &OCClientResponse::get__payload_len, &OCClientResponse::set__payload_len),
        InstanceAccessor("code", &OCClientResponse::get_code, &OCClientResponse::set_code),
        InstanceAccessor("content_format", &OCClientResponse::get_content_format, &OCClientResponse::set_content_format),
        InstanceAccessor("endpoint", &OCClientResponse::get_endpoint, &OCClientResponse::set_endpoint),
        InstanceAccessor("observe_option", &OCClientResponse::get_observe_option, &OCClientResponse::set_observe_option),
        InstanceAccessor("payload", &OCClientResponse::get_payload, &OCClientResponse::set_payload),
        InstanceAccessor("user_data", &OCClientResponse::get_user_data, &OCClientResponse::set_user_data),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCClientResponse::~OCClientResponse()
{
}
OCClientResponse::OCClientResponse(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_client_response_t>(new oc_client_response_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_client_response_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCClientResponse::get__payload(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(m_pvalue->_payload), m_pvalue->_payload_len);
}

void OCClientResponse::set__payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->_payload =    reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data()); //TODO
    m_pvalue->_payload_len = value.As<TypedArray>().ArrayBuffer().ByteLength();
}

Napi::Value OCClientResponse::get__payload_len(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->_payload_len);
}

void OCClientResponse::set__payload_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->_payload_len = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientResponse::get_code(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->code);
}

void OCClientResponse::set_code(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->code = static_cast<oc_status_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientResponse::get_content_format(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->content_format);
}

void OCClientResponse::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->content_format = static_cast<oc_content_format_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCClientResponse::get_endpoint(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t*> sp(&m_pvalue->endpoint, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t*>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

void OCClientResponse::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->endpoint = *(*(value.As<External<shared_ptr<oc_endpoint_t*>>>().Data()));
}

Napi::Value OCClientResponse::get_observe_option(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->observe_option);
}

void OCClientResponse::set_observe_option(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->observe_option = static_cast<int>(value.ToNumber());
}

Napi::Value OCClientResponse::get_payload(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_rep_t*> sp(&m_pvalue->payload, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_t*>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({accessor});
}

void OCClientResponse::set_payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->payload = *(*(value.As<External<shared_ptr<oc_rep_t*>>>().Data()));
}

Napi::Value OCClientResponse::get_user_data(const Napi::CallbackInfo& info)
{
    return user_data_ref.Get("user_data");
}

void OCClientResponse::set_user_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{

    Napi::Object obj = Napi::Object::New(info.Env());
    obj.Set("user_data", value);
    user_data_ref = Napi::Persistent(obj);
}

Napi::FunctionReference OCCloudContext::constructor;

Napi::Function OCCloudContext::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCloudContext", {
        InstanceAccessor("callback", &OCCloudContext::get_callback, &OCCloudContext::set_callback),
        InstanceAccessor("cloud_conf", &OCCloudContext::get_cloud_conf, &OCCloudContext::set_cloud_conf),
        InstanceAccessor("cloud_ep", &OCCloudContext::get_cloud_ep, &OCCloudContext::set_cloud_ep),
        InstanceAccessor("cloud_ep_state", &OCCloudContext::get_cloud_ep_state, &OCCloudContext::set_cloud_ep_state),
        InstanceAccessor("cloud_manager", &OCCloudContext::get_cloud_manager, &OCCloudContext::set_cloud_manager),
        InstanceAccessor("device", &OCCloudContext::get_device, &OCCloudContext::set_device),
        InstanceAccessor("expires_in", &OCCloudContext::get_expires_in, &OCCloudContext::set_expires_in),
        InstanceAccessor("last_error", &OCCloudContext::get_last_error, &OCCloudContext::set_last_error),
        InstanceAccessor("rd_delete_all", &OCCloudContext::get_rd_delete_all, &OCCloudContext::set_rd_delete_all),
        InstanceAccessor("rd_delete_resources", &OCCloudContext::get_rd_delete_resources, &OCCloudContext::set_rd_delete_resources),
        InstanceAccessor("rd_publish_resources", &OCCloudContext::get_rd_publish_resources, &OCCloudContext::set_rd_publish_resources),
        InstanceAccessor("rd_published_resources", &OCCloudContext::get_rd_published_resources, &OCCloudContext::set_rd_published_resources),
        InstanceAccessor("retry_count", &OCCloudContext::get_retry_count, &OCCloudContext::set_retry_count),
        InstanceAccessor("retry_refresh_token_count", &OCCloudContext::get_retry_refresh_token_count, &OCCloudContext::set_retry_refresh_token_count),
        InstanceAccessor("store", &OCCloudContext::get_store, &OCCloudContext::set_store),
        InstanceAccessor("user_data", &OCCloudContext::get_user_data, &OCCloudContext::set_user_data),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCCloudContext::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCloudContext::~OCCloudContext()
{
}
OCCloudContext::OCCloudContext(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_cloud_context_t>(new oc_cloud_context_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_cloud_context_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCloudContext::get_callback(const Napi::CallbackInfo& info)
{
    return callback_function;
}

void OCCloudContext::set_callback(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    callback_function = value;
}

Napi::Value OCCloudContext::get_cloud_conf(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_resource_t*> sp(&m_pvalue->cloud_conf, nop_deleter);
    auto accessor = External<shared_ptr<oc_resource_t*>>::New(info.Env(), &sp);
    return OCResource::constructor.New({accessor});
}

void OCCloudContext::set_cloud_conf(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->cloud_conf = *(*(value.As<External<shared_ptr<oc_resource_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_cloud_ep(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t*> sp(&m_pvalue->cloud_ep, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t*>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

void OCCloudContext::set_cloud_ep(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->cloud_ep = *(*(value.As<External<shared_ptr<oc_endpoint_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_cloud_ep_state(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->cloud_ep_state);
}

void OCCloudContext::set_cloud_ep_state(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->cloud_ep_state = static_cast<oc_session_state_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudContext::get_cloud_manager(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->cloud_manager);
}

void OCCloudContext::set_cloud_manager(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->cloud_manager = value.ToBoolean().Value();
}

Napi::Value OCCloudContext::get_device(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->device);
}

void OCCloudContext::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->device = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudContext::get_expires_in(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->expires_in);
}

void OCCloudContext::set_expires_in(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->expires_in = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudContext::get_last_error(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->last_error);
}

void OCCloudContext::set_last_error(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->last_error = static_cast<oc_cloud_error_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudContext::get_rd_delete_all(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->rd_delete_all);
}

void OCCloudContext::set_rd_delete_all(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rd_delete_all = value.ToBoolean().Value();
}

Napi::Value OCCloudContext::get_rd_delete_resources(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_link_t*> sp(&m_pvalue->rd_delete_resources, nop_deleter);
    auto accessor = External<shared_ptr<oc_link_t*>>::New(info.Env(), &sp);
    return OCLink::constructor.New({accessor});
}

void OCCloudContext::set_rd_delete_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rd_delete_resources = *(*(value.As<External<shared_ptr<oc_link_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_rd_publish_resources(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_link_t*> sp(&m_pvalue->rd_publish_resources, nop_deleter);
    auto accessor = External<shared_ptr<oc_link_t*>>::New(info.Env(), &sp);
    return OCLink::constructor.New({accessor});
}

void OCCloudContext::set_rd_publish_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rd_publish_resources = *(*(value.As<External<shared_ptr<oc_link_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_rd_published_resources(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_link_t*> sp(&m_pvalue->rd_published_resources, nop_deleter);
    auto accessor = External<shared_ptr<oc_link_t*>>::New(info.Env(), &sp);
    return OCLink::constructor.New({accessor});
}

void OCCloudContext::set_rd_published_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rd_published_resources = *(*(value.As<External<shared_ptr<oc_link_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_retry_count(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->retry_count);
}

void OCCloudContext::set_retry_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->retry_count = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudContext::get_retry_refresh_token_count(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->retry_refresh_token_count);
}

void OCCloudContext::set_retry_refresh_token_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->retry_refresh_token_count = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudContext::get_store(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_cloud_store_t> sp(&m_pvalue->store, nop_deleter);
    auto accessor = External<shared_ptr<oc_cloud_store_t>>::New(info.Env(), &sp);
    return OCCloudStore::constructor.New({accessor});
}

void OCCloudContext::set_store(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->store = *(*(value.As<External<shared_ptr<oc_cloud_store_t>>>().Data()));
}

Napi::Value OCCloudContext::get_user_data(const Napi::CallbackInfo& info)
{
    return callback_data;
}

void OCCloudContext::set_user_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    callback_data = value;
}

Napi::FunctionReference OCCloudStore::constructor;

Napi::Function OCCloudStore::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCloudStore", {
        InstanceAccessor("access_token", &OCCloudStore::get_access_token, &OCCloudStore::set_access_token),
        InstanceAccessor("auth_provider", &OCCloudStore::get_auth_provider, &OCCloudStore::set_auth_provider),
        InstanceAccessor("ci_server", &OCCloudStore::get_ci_server, &OCCloudStore::set_ci_server),
        InstanceAccessor("cps", &OCCloudStore::get_cps, &OCCloudStore::set_cps),
        InstanceAccessor("device", &OCCloudStore::get_device, &OCCloudStore::set_device),
        InstanceAccessor("refresh_token", &OCCloudStore::get_refresh_token, &OCCloudStore::set_refresh_token),
        InstanceAccessor("sid", &OCCloudStore::get_sid, &OCCloudStore::set_sid),
        InstanceAccessor("status", &OCCloudStore::get_status, &OCCloudStore::set_status),
        InstanceAccessor("uid", &OCCloudStore::get_uid, &OCCloudStore::set_uid),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCloudStore::~OCCloudStore()
{
}
OCCloudStore::OCCloudStore(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_cloud_store_t>(new oc_cloud_store_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_cloud_store_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCloudStore::get_access_token(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->access_token, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_access_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->access_token = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_auth_provider(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->auth_provider, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_auth_provider(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->auth_provider = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_ci_server(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->ci_server, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_ci_server(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->ci_server = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_cps(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->cps);
}

void OCCloudStore::set_cps(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->cps = static_cast<oc_cps_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudStore::get_device(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->device);
}

void OCCloudStore::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->device = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudStore::get_refresh_token(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->refresh_token, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_refresh_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->refresh_token = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_sid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->sid, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_sid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->sid = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_status(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->status);
}

void OCCloudStore::set_status(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->status = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCloudStore::get_uid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->uid, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_uid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->uid = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCCollection::constructor;

Napi::Function OCCollection::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCollection", {
        InstanceAccessor("default_interface", &OCCollection::get_default_interface, &OCCollection::set_default_interface),
        InstanceAccessor("delete_handler", &OCCollection::get_delete_handler, &OCCollection::set_delete_handler),
        InstanceAccessor("device", &OCCollection::get_device, &OCCollection::set_device),
        InstanceAccessor("get_handler", &OCCollection::get_get_handler, &OCCollection::set_get_handler),
        InstanceAccessor("get_properties", &OCCollection::get_get_properties, &OCCollection::set_get_properties),
        InstanceAccessor("interfaces", &OCCollection::get_interfaces, &OCCollection::set_interfaces),
        InstanceAccessor("name", &OCCollection::get_name, &OCCollection::set_name),
        InstanceAccessor("num_links", &OCCollection::get_num_links, &OCCollection::set_num_links),
        InstanceAccessor("num_observers", &OCCollection::get_num_observers, &OCCollection::set_num_observers),
        InstanceAccessor("post_handler", &OCCollection::get_post_handler, &OCCollection::set_post_handler),
        InstanceAccessor("properties", &OCCollection::get_properties, &OCCollection::set_properties),
        InstanceAccessor("put_handler", &OCCollection::get_put_handler, &OCCollection::set_put_handler),
        InstanceAccessor("set_properties", &OCCollection::get_set_properties, &OCCollection::set_set_properties),
        InstanceAccessor("tag_pos_desc", &OCCollection::get_tag_pos_desc, &OCCollection::set_tag_pos_desc),
        InstanceAccessor("tag_pos_func", &OCCollection::get_tag_pos_func, &OCCollection::set_tag_pos_func),
        InstanceAccessor("tag_pos_rel", &OCCollection::get_tag_pos_rel, &OCCollection::set_tag_pos_rel),
        InstanceAccessor("types", &OCCollection::get_types, &OCCollection::set_types),
        InstanceAccessor("uri", &OCCollection::get_uri, &OCCollection::set_uri),
        InstanceMethod("add_link", &OCCollection::add_link),
        InstanceMethod("add_mandatory_rt", &OCCollection::add_mandatory_rt),
        InstanceMethod("add_supported_rt", &OCCollection::add_supported_rt),
        StaticMethod("get_collections", &OCCollection::get_collections),
        InstanceMethod("get_links", &OCCollection::get_links),
        InstanceMethod("remove_link", &OCCollection::remove_link),
        StaticMethod("add", &OCCollection::add),
        StaticMethod("alloc", &OCCollection::alloc),
        StaticMethod("free", &OCCollection::free),
        StaticMethod("get_all", &OCCollection::get_all),
        StaticMethod("get_next_collection_with_link", &OCCollection::get_next_collection_with_link),
        StaticMethod("get_collection_by_uri", &OCCollection::get_collection_by_uri),
        StaticMethod("get_link_by_uri", &OCCollection::get_link_by_uri),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCCollection::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCollection::~OCCollection()
{
}

OCCollection::OCCollection(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        /* TODO
        m_pvalue = shared_ptr<oc_collection_s>(
          reinterpret_cast<oc_collection_s*>(oc_new_collection()),
          [](oc_collection_s* x){ oc_delete_collection( reinterpret_cast<oc_collection_s*>(x) );} );
        */
    }
    else if (info.Length() == 1 && info[0].IsExternal()) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_collection_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCollection::get_default_interface(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->default_interface);
}

void OCCollection::set_default_interface(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->default_interface = static_cast<oc_interface_mask_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_delete_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->delete_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCCollection::set_delete_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->delete_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_device(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->device);
}

void OCCollection::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->device = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_get_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->get_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCCollection::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->get_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_get_properties(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties, nop_deleter);
    auto accessor = External<shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
    return OCPropertiesCb::constructor.New({accessor});
}

void OCCollection::set_get_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->get_properties = *(*(value.As<External<shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCCollection::get_interfaces(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->interfaces);
}

void OCCollection::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_name(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->name, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCollection::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->name = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCollection::get_num_links(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->num_links);
}

void OCCollection::set_num_links(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->num_links = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_num_observers(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->num_observers);
}

void OCCollection::set_num_observers(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->num_observers = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_post_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->post_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCCollection::set_post_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->post_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_properties(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->properties);
}

void OCCollection::set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->properties = static_cast<oc_resource_properties_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_put_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->put_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCCollection::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->put_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_set_properties(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties, nop_deleter);
    auto accessor = External<shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
    return OCPropertiesCb::constructor.New({accessor});
}

void OCCollection::set_set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->set_properties = *(*(value.As<External<shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCCollection::get_tag_pos_desc(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->tag_pos_desc);
}

void OCCollection::set_tag_pos_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->tag_pos_desc = static_cast<oc_pos_description_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_tag_pos_func(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->tag_pos_func);
}

void OCCollection::set_tag_pos_func(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->tag_pos_func = static_cast<oc_enum_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCCollection::get_tag_pos_rel(const Napi::CallbackInfo& info)
{
    auto array = Float64Array::New(info.Env(), 3);
    array[0] = m_pvalue->tag_pos_rel[0];
    array[1] = m_pvalue->tag_pos_rel[1];
    array[2] = m_pvalue->tag_pos_rel[2];
    return array;
}

void OCCollection::set_tag_pos_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->tag_pos_rel[0] = value.As<Float64Array>()[0];
    m_pvalue->tag_pos_rel[1] = value.As<Float64Array>()[1];
    m_pvalue->tag_pos_rel[2] = value.As<Float64Array>()[2];
}

Napi::Value OCCollection::get_types(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_string_array_t> sp(&m_pvalue->types, nop_deleter);
    auto accessor = External<shared_ptr<oc_string_array_t>>::New(info.Env(), &sp);
    return OCStringArray::constructor.New({accessor});
}

void OCCollection::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->types = *(*(value.As<External<shared_ptr<oc_string_array_t>>>().Data()));
}

Napi::Value OCCollection::get_uri(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->uri, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCollection::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->uri = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Value OCCollection::add_link(const CallbackInfo& info) {
    OCCollection& collection = *OCCollection::Unwrap(info.This().ToObject());
    auto& link = *OCLink::Unwrap(info[0].ToObject());
    (void)oc_collection_add_link(collection, link);
    return info.Env().Undefined();
}

Value OCCollection::add_mandatory_rt(const CallbackInfo& info) {
    OCCollection& collection = *OCCollection::Unwrap(info.This().ToObject());
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    return Boolean::New(info.Env(), oc_collection_add_mandatory_rt(collection, rt));
}

Value OCCollection::add_supported_rt(const CallbackInfo& info) {
    OCCollection& collection = *OCCollection::Unwrap(info.This().ToObject());
    auto rt_ = info[0].ToString().Utf8Value();
    auto rt = rt_.c_str();
    return Boolean::New(info.Env(), oc_collection_add_supported_rt(collection, rt));
}

Value OCCollection::get_collections(const CallbackInfo& info) {
    shared_ptr<oc_resource_t> sp(oc_collection_get_collections(), nop_deleter);
    auto args = External<shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
    return OCResource::constructor.New({args});
}

Value OCCollection::get_links(const CallbackInfo& info) {
    OCCollection& collection = *OCCollection::Unwrap(info.This().ToObject());
    shared_ptr<oc_link_t> sp(oc_collection_get_links(collection), nop_deleter);
    auto args = External<shared_ptr<oc_link_t>>::New(info.Env(), &sp);
    return OCLink::constructor.New({args});
}

Value OCCollection::remove_link(const CallbackInfo& info) {
    OCCollection& collection = *OCCollection::Unwrap(info.This().ToObject());
    auto& link = *OCLink::Unwrap(info[0].ToObject());
    (void)oc_collection_remove_link(collection, link);
    return info.Env().Undefined();
}

Value OCCollection::add(const CallbackInfo& info) {
    auto& collection = *OCCollection::Unwrap(info[0].ToObject());
    (void)oc_collection_add(collection);
    return info.Env().Undefined();
}

Value OCCollection::alloc(const CallbackInfo& info) {
    shared_ptr<oc_collection_t> sp(oc_collection_alloc(), nop_deleter);
    auto args = External<shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({args});
}

Value OCCollection::free(const CallbackInfo& info) {
    auto& collection = *OCCollection::Unwrap(info[0].ToObject());
    (void)oc_collection_free(collection);
    return info.Env().Undefined();
}

Value OCCollection::get_all(const CallbackInfo& info) {
    shared_ptr<oc_collection_t> sp(oc_collection_get_all(), nop_deleter);
    auto args = External<shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({args});
}

Value OCCollection::get_next_collection_with_link(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info[0].ToObject());
    auto& start = *OCCollection::Unwrap(info[1].ToObject());
    shared_ptr<oc_collection_t> sp(oc_get_next_collection_with_link(resource, start), nop_deleter);
    auto args = External<shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({args});
}

Value OCCollection::get_collection_by_uri(const CallbackInfo& info) {
    auto uri_path_ = info[0].ToString().Utf8Value();
    auto uri_path = uri_path_.c_str();
    auto uri_path_len = static_cast<size_t>(info[1].ToNumber().Uint32Value());
    auto device = static_cast<size_t>(info[2].ToNumber().Uint32Value());
    shared_ptr<oc_collection_t> sp(oc_get_collection_by_uri(uri_path, uri_path_len, device), nop_deleter);
    auto args = External<shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({args});
}

Value OCCollection::get_link_by_uri(const CallbackInfo& info) {
    auto& collection = *OCCollection::Unwrap(info[0].ToObject());
    auto uri_path_ = info[1].ToString().Utf8Value();
    auto uri_path = uri_path_.c_str();
    auto uri_path_len = static_cast<int>(info[2].ToNumber());
    shared_ptr<oc_link_t> sp(oc_get_link_by_uri(collection, uri_path, uri_path_len), nop_deleter);
    auto args = External<shared_ptr<oc_link_t>>::New(info.Env(), &sp);
    return OCLink::constructor.New({args});
}


Napi::FunctionReference OCCredData::constructor;

Napi::Function OCCredData::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCredData", {
        InstanceAccessor("data", &OCCredData::get_data, &OCCredData::set_data),
        InstanceAccessor("encoding", &OCCredData::get_encoding, &OCCredData::set_encoding),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCredData::~OCCredData()
{
}
OCCredData::OCCredData(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_cred_data_t>(new oc_cred_data_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_cred_data_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCredData::get_data(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->data, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCCredData::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->data = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCredData::get_encoding(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->encoding);
}

void OCCredData::set_encoding(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->encoding = static_cast<oc_sec_encoding_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCDeviceInfo::constructor;

Napi::Function OCDeviceInfo::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCDeviceInfo", {
        InstanceAccessor("add_device_cb", &OCDeviceInfo::get_add_device_cb, &OCDeviceInfo::set_add_device_cb),
        InstanceAccessor("data", &OCDeviceInfo::get_data, &OCDeviceInfo::set_data),
        InstanceAccessor("di", &OCDeviceInfo::get_di, &OCDeviceInfo::set_di),
        InstanceAccessor("dmv", &OCDeviceInfo::get_dmv, &OCDeviceInfo::set_dmv),
        InstanceAccessor("icv", &OCDeviceInfo::get_icv, &OCDeviceInfo::set_icv),
        InstanceAccessor("name", &OCDeviceInfo::get_name, &OCDeviceInfo::set_name),
        InstanceAccessor("piid", &OCDeviceInfo::get_piid, &OCDeviceInfo::set_piid),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCDeviceInfo::~OCDeviceInfo()
{
}
OCDeviceInfo::OCDeviceInfo(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_device_info_t>(new oc_device_info_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_device_info_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCDeviceInfo::get_add_device_cb(const Napi::CallbackInfo& info)
{
    return add_device_cb_function;
}

void OCDeviceInfo::set_add_device_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    add_device_cb_function = value;
}

Napi::Value OCDeviceInfo::get_data(const Napi::CallbackInfo& info)
{
    return add_device_cb_data;
}

void OCDeviceInfo::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    add_device_cb_data = value;
}

Napi::Value OCDeviceInfo::get_di(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->di, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCDeviceInfo::set_di(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->di = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Value OCDeviceInfo::get_dmv(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->dmv, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCDeviceInfo::set_dmv(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->dmv = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_icv(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->icv, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCDeviceInfo::set_icv(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->icv = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_name(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->name, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCDeviceInfo::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->name = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_piid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->piid, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCDeviceInfo::set_piid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->piid = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCEndpoint::constructor;

Napi::Function OCEndpoint::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEndpoint", {
        InstanceAccessor("addr", &OCEndpoint::get_addr, &OCEndpoint::set_addr),
        InstanceAccessor("addr_local", &OCEndpoint::get_addr_local, &OCEndpoint::set_addr_local),
        InstanceAccessor("device", &OCEndpoint::get_device, &OCEndpoint::set_device),
        InstanceAccessor("di", &OCEndpoint::get_di, &OCEndpoint::set_di),
        InstanceAccessor("flags", &OCEndpoint::get_flags, &OCEndpoint::set_flags),
        InstanceAccessor("interface_index", &OCEndpoint::get_interface_index, &OCEndpoint::set_interface_index),
        InstanceAccessor("priority", &OCEndpoint::get_priority, &OCEndpoint::set_priority),
        InstanceAccessor("version", &OCEndpoint::get_version, &OCEndpoint::set_version),
        InstanceMethod("toString", &OCEndpoint::toString),
        InstanceMethod("compare", &OCEndpoint::compare),
        InstanceMethod("copy", &OCEndpoint::copy),
        InstanceMethod("list_copy", &OCEndpoint::list_copy),
        StaticMethod("string_to_endpoint", &OCEndpoint::string_to_endpoint),
        InstanceMethod("endpoint_string_parse_path", &OCEndpoint::endpoint_string_parse_path),
        InstanceMethod("ipv6_endpoint_is_link_local", &OCEndpoint::ipv6_endpoint_is_link_local),
        InstanceMethod("compare_address", &OCEndpoint::compare_address),
        StaticMethod("set_local_address", &OCEndpoint::set_local_address),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCEndpoint::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEndpoint::~OCEndpoint()
{
}
OCEndpoint::OCEndpoint(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_endpoint_t>(new oc_endpoint_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_endpoint_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCEndpoint::get_addr(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t::dev_addr> sp(&m_pvalue->addr, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t::dev_addr>>::New(info.Env(), &sp);
    return DevAddr::constructor.New({accessor});
}

void OCEndpoint::set_addr(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->addr = *(*(value.As<External<shared_ptr<oc_endpoint_t::dev_addr>>>().Data()));
}

Napi::Value OCEndpoint::get_addr_local(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t::dev_addr> sp(&m_pvalue->addr_local, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t::dev_addr>>::New(info.Env(), &sp);
    return DevAddr::constructor.New({accessor});
}

void OCEndpoint::set_addr_local(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->addr_local = *(*(value.As<External<shared_ptr<oc_endpoint_t::dev_addr>>>().Data()));
}

Napi::Value OCEndpoint::get_device(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->device);
}

void OCEndpoint::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->device = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCEndpoint::get_di(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->di, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCEndpoint::set_di(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    oc_endpoint_set_di(m_pvalue.get(), value.As<External<shared_ptr<oc_uuid_t>>>().Data()->get() );
}

Napi::Value OCEndpoint::get_flags(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->flags);
}

void OCEndpoint::set_flags(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->flags = static_cast<transport_flags>(value.ToNumber().Uint32Value());
}

Napi::Value OCEndpoint::get_interface_index(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->interface_index);
}

void OCEndpoint::set_interface_index(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->interface_index = static_cast<int>(value.ToNumber());
}

Napi::Value OCEndpoint::get_priority(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->priority);
}

void OCEndpoint::set_priority(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->priority = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCEndpoint::get_version(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->version);
}

void OCEndpoint::set_version(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->version = static_cast<ocf_version_t>(value.ToNumber().Uint32Value());
}

Value OCEndpoint::toString(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info.This().ToObject());
    oc_string_t endpoint_str;
    int ret = oc_endpoint_to_string(endpoint, &endpoint_str);
    if(ret) {
        TypeError::New(info.Env(), "oc_endpoint_to_string failed.").ThrowAsJavaScriptException();
    }
    return String::New(info.Env(), oc_string(endpoint_str));

}

Value OCEndpoint::compare(const CallbackInfo& info) {
    auto& ep1 = *OCEndpoint::Unwrap(info.This().ToObject());
    auto& ep2 = *OCEndpoint::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_endpoint_compare(ep1, ep2));
}

Value OCEndpoint::copy(const CallbackInfo& info) {
    oc_endpoint_t* dst = nullptr;
    auto& src = *OCEndpoint::Unwrap(info[0].ToObject());
    (void)oc_endpoint_copy(dst, src);
    shared_ptr<oc_endpoint_t> sp(dst, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

Value OCEndpoint::list_copy(const CallbackInfo& info) {
    OCEndpoint& src = *OCEndpoint::Unwrap(info.This().ToObject());
    oc_endpoint_t* dst = nullptr;
    oc_endpoint_list_copy(&dst, src);
    shared_ptr<oc_endpoint_t> sp(dst /* TODO */);
    auto accessor = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

Value OCEndpoint::string_to_endpoint(const CallbackInfo& info) {
    auto& endpoint_str = *OCMmem::Unwrap(info[0].ToObject());
    auto& endpoint = *OCEndpoint::Unwrap(info[1].ToObject());
    auto& uri = *OCMmem::Unwrap(info[2].ToObject());
    return Number::New(info.Env(), oc_string_to_endpoint(endpoint_str, endpoint, uri));
}

Value OCEndpoint::endpoint_string_parse_path(const CallbackInfo& info) {
    auto& endpoint_str = *OCMmem::Unwrap(info.This().ToObject());
    auto& path = *OCMmem::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_endpoint_string_parse_path(endpoint_str, path));
}

Value OCEndpoint::ipv6_endpoint_is_link_local(const CallbackInfo& info) {
    auto& endpoint = *OCEndpoint::Unwrap(info.This().ToObject());
    return Number::New(info.Env(), oc_ipv6_endpoint_is_link_local(endpoint));
}

Value OCEndpoint::compare_address(const CallbackInfo& info) {
    auto& ep1 = *OCEndpoint::Unwrap(info.This().ToObject());
    auto& ep2 = *OCEndpoint::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_endpoint_compare_address(ep1, ep2));
}

Value OCEndpoint::set_local_address(const CallbackInfo& info) {
    auto& ep = *OCEndpoint::Unwrap(info[0].ToObject());
    auto interface_index = static_cast<int>(info[1].ToNumber());
    (void)oc_endpoint_set_local_address(ep, interface_index);
    return info.Env().Undefined();
}



Napi::FunctionReference OCEventCallback::constructor;

Napi::Function OCEventCallback::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEventCallback", {
        InstanceAccessor("callback", &OCEventCallback::get_callback, &OCEventCallback::set_callback),
        InstanceAccessor("data", &OCEventCallback::get_data, &OCEventCallback::set_data),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCEventCallback::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEventCallback::~OCEventCallback()
{
}
OCEventCallback::OCEventCallback(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_event_callback_s>(new oc_event_callback_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_event_callback_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCEventCallback::get_callback(const Napi::CallbackInfo& info)
{
    return callback_function;
}

void OCEventCallback::set_callback(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    callback_function = value;
}

Napi::Value OCEventCallback::get_data(const Napi::CallbackInfo& info)
{
    return callback_data;
}

void OCEventCallback::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    callback_data = value;
}

Napi::FunctionReference OCHandler::constructor;

Napi::Function OCHandler::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCHandler", {
        InstanceAccessor("init", &OCHandler::get_init, &OCHandler::set_init),
#if defined(OC_SERVER)
        InstanceAccessor("register_resources", &OCHandler::get_register_resources, &OCHandler::set_register_resources),
#endif
#if defined(OC_CLIENT)
        InstanceAccessor("requests_entry", &OCHandler::get_requests_entry, &OCHandler::set_requests_entry),
#endif

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCHandler::~OCHandler()
{
}
OCHandler::OCHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_handler_t>(new oc_handler_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_handler_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCHandler::get_init(const Napi::CallbackInfo& info)
{
    return init.Value();
}

void OCHandler::set_init(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    init.Reset(value.As<Function>());

}

#if defined(OC_SERVER)
Napi::Value OCHandler::get_register_resources(const Napi::CallbackInfo& info)
{
    return register_resources.Value();
}

void OCHandler::set_register_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    register_resources.Reset(value.As<Function>());

}
#endif

#if defined(OC_CLIENT)
Napi::Value OCHandler::get_requests_entry(const Napi::CallbackInfo& info)
{
    return requests_entry.Value();

}

void OCHandler::set_requests_entry(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    requests_entry.Reset(value.As<Function>());

}
#endif

Napi::FunctionReference OCIPv4Addr::constructor;

Napi::Function OCIPv4Addr::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCIPv4Addr", {
        InstanceAccessor("address", &OCIPv4Addr::get_address, &OCIPv4Addr::set_address),
        InstanceAccessor("port", &OCIPv4Addr::get_port, &OCIPv4Addr::set_port),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCIPv4Addr::~OCIPv4Addr()
{
}
OCIPv4Addr::OCIPv4Addr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ipv4_addr_t>(new oc_ipv4_addr_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ipv4_addr_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCIPv4Addr::get_address(const Napi::CallbackInfo& info)
{
    auto array = Uint8Array::New(info.Env(), 4);
    array[0] = m_pvalue->address[0];
    array[1] = m_pvalue->address[1];
    array[2] = m_pvalue->address[2];
    array[3] = m_pvalue->address[3];
    return array;
}

void OCIPv4Addr::set_address(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->address[0] = value.As<Uint8Array>()[0];
    m_pvalue->address[1] = value.As<Uint8Array>()[1];
    m_pvalue->address[2] = value.As<Uint8Array>()[2];
    m_pvalue->address[3] = value.As<Uint8Array>()[3];
}

Napi::Value OCIPv4Addr::get_port(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->port);
}

void OCIPv4Addr::set_port(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->port = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCIPv6Addr::constructor;

Napi::Function OCIPv6Addr::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCIPv6Addr", {
        InstanceAccessor("address", &OCIPv6Addr::get_address, &OCIPv6Addr::set_address),
        InstanceAccessor("port", &OCIPv6Addr::get_port, &OCIPv6Addr::set_port),
        InstanceAccessor("scope", &OCIPv6Addr::get_scope, &OCIPv6Addr::set_scope),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCIPv6Addr::~OCIPv6Addr()
{
}
OCIPv6Addr::OCIPv6Addr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ipv6_addr_t>(new oc_ipv6_addr_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ipv6_addr_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCIPv6Addr::get_address(const Napi::CallbackInfo& info)
{
    auto array = Uint16Array::New(info.Env(), 8);
    array[0] = m_pvalue->address[0];
    array[1] = m_pvalue->address[1];
    array[2] = m_pvalue->address[2];
    array[3] = m_pvalue->address[3];
    array[4] = m_pvalue->address[4];
    array[5] = m_pvalue->address[5];
    array[6] = m_pvalue->address[6];
    array[7] = m_pvalue->address[7];
    return array;
}

void OCIPv6Addr::set_address(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->address[0] = value.As<Uint16Array>()[0];
    m_pvalue->address[1] = value.As<Uint16Array>()[1];
    m_pvalue->address[2] = value.As<Uint16Array>()[2];
    m_pvalue->address[3] = value.As<Uint16Array>()[3];
    m_pvalue->address[4] = value.As<Uint16Array>()[4];
    m_pvalue->address[5] = value.As<Uint16Array>()[5];
    m_pvalue->address[6] = value.As<Uint16Array>()[6];
    m_pvalue->address[7] = value.As<Uint16Array>()[7];
}

Napi::Value OCIPv6Addr::get_port(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->port);
}

void OCIPv6Addr::set_port(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->port = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCIPv6Addr::get_scope(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->scope);
}

void OCIPv6Addr::set_scope(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->scope = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCLEAddr::constructor;

Napi::Function OCLEAddr::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCLEAddr", {
        InstanceAccessor("address", &OCLEAddr::get_address, &OCLEAddr::set_address),
        InstanceAccessor("type", &OCLEAddr::get_type, &OCLEAddr::set_type),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCLEAddr::~OCLEAddr()
{
}
OCLEAddr::OCLEAddr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_le_addr_t>(new oc_le_addr_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_le_addr_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCLEAddr::get_address(const Napi::CallbackInfo& info)
{
    auto array = Uint8Array::New(info.Env(), 6);
    array[0] = m_pvalue->address[0];
    array[1] = m_pvalue->address[1];
    array[2] = m_pvalue->address[2];
    array[3] = m_pvalue->address[3];
    array[4] = m_pvalue->address[4];
    array[5] = m_pvalue->address[5];
    return array;
}

void OCLEAddr::set_address(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->address[0] = value.As<Uint8Array>()[0];
    m_pvalue->address[1] = value.As<Uint8Array>()[1];
    m_pvalue->address[2] = value.As<Uint8Array>()[2];
    m_pvalue->address[3] = value.As<Uint8Array>()[3];
    m_pvalue->address[4] = value.As<Uint8Array>()[4];
    m_pvalue->address[5] = value.As<Uint8Array>()[5];
}

Napi::Value OCLEAddr::get_type(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->type);
}

void OCLEAddr::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->type = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCLinkParams::constructor;

Napi::Function OCLinkParams::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCLinkParams", {
        InstanceAccessor("key", &OCLinkParams::get_key, &OCLinkParams::set_key),
        InstanceAccessor("value", &OCLinkParams::get_value, &OCLinkParams::set_value),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCLinkParams::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCLinkParams::~OCLinkParams()
{
}
OCLinkParams::OCLinkParams(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_link_params_t>(new oc_link_params_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_link_params_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCLinkParams::get_key(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->key, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCLinkParams::set_key(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->key = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCLinkParams::get_value(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->value, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCLinkParams::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->value = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCLink::constructor;

Napi::Function OCLink::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCLink", {
        InstanceAccessor("ins", &OCLink::get_ins, &OCLink::set_ins),
        InstanceAccessor("interfaces", &OCLink::get_interfaces, &OCLink::set_interfaces),
        InstanceAccessor("rel", &OCLink::get_rel, &OCLink::set_rel),
        InstanceAccessor("resource", &OCLink::get_resource, &OCLink::set_resource),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCLink::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCLink::~OCLink()
{
}
OCLink::OCLink(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_link_s>(new oc_link_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_link_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCLink::get_ins(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->ins);
}

void OCLink::set_ins(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->ins = value.ToNumber().Int64Value();
}

Napi::Value OCLink::get_interfaces(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->interfaces);
}

void OCLink::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{

    auto& link = *OCLink::Unwrap(info.This().ToObject());
    oc_link_set_interfaces(link, static_cast<oc_interface_mask_t>(value.ToNumber().Uint32Value()));
}

Napi::Value OCLink::get_rel(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_string_array_t> sp(&m_pvalue->rel, nop_deleter);
    auto accessor = External<shared_ptr<oc_string_array_t>>::New(info.Env(), &sp);
    return OCStringArray::constructor.New({accessor});
}

void OCLink::set_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rel = *(*(value.As<External<shared_ptr<oc_string_array_t>>>().Data()));
}

Napi::Value OCLink::get_resource(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_resource_t*> sp(&m_pvalue->resource, nop_deleter);
    auto accessor = External<shared_ptr<oc_resource_t*>>::New(info.Env(), &sp);
    return OCResource::constructor.New({accessor});
}

void OCLink::set_resource(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->resource = *(*(value.As<External<shared_ptr<oc_resource_t*>>>().Data()));
}

Napi::FunctionReference OCMemb::constructor;

Napi::Function OCMemb::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCMemb", {
        InstanceAccessor("count", &OCMemb::get_count, &OCMemb::set_count),
        InstanceAccessor("num", &OCMemb::get_num, &OCMemb::set_num),
        InstanceAccessor("size", &OCMemb::get_size, &OCMemb::set_size),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCMemb::~OCMemb()
{
}
OCMemb::OCMemb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_memb>(new oc_memb());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_memb>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCMemb::get_count(const Napi::CallbackInfo& info)
{
    return Buffer<char>::New(info.Env(), m_pvalue->count, m_pvalue->num);
}

void OCMemb::set_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    for(uint32_t i=0; i<m_pvalue->num; i++) {
        m_pvalue->count[i] = reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data())[i];
    }
}

Napi::Value OCMemb::get_num(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->num);
}

void OCMemb::set_num(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->num = static_cast<unsigned short>(value.ToNumber().Uint32Value());
}

Napi::Value OCMemb::get_size(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->size);
}

void OCMemb::set_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->size = static_cast<unsigned short>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCMessage::constructor;

Napi::Function OCMessage::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCMessage", {
        InstanceAccessor("data", &OCMessage::get_data, &OCMessage::set_data),
#if defined(OC_SECURITY)
        InstanceAccessor("encrypted", &OCMessage::get_encrypted, &OCMessage::set_encrypted),
#endif
        InstanceAccessor("endpoint", &OCMessage::get_endpoint, &OCMessage::set_endpoint),
        InstanceAccessor("length", &OCMessage::get_length, &OCMessage::set_length),
        InstanceAccessor("pool", &OCMessage::get_pool, &OCMessage::set_pool),
#if defined(OC_TCP)
        InstanceAccessor("read_offset", &OCMessage::get_read_offset, &OCMessage::set_read_offset),
#endif
        InstanceAccessor("ref_count", &OCMessage::get_ref_count, &OCMessage::set_ref_count),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCMessage::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCMessage::~OCMessage()
{
}
OCMessage::OCMessage(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_message_s>(new oc_message_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_message_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCMessage::get_data(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), m_pvalue->data, OC_PDU_SIZE);
}

void OCMessage::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    for(uint32_t i=0; i<value.As<TypedArray>().ArrayBuffer().ByteLength(); i++) {
        m_pvalue->data[i] = reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data())[i];
    }
}

#if defined(OC_SECURITY)
Napi::Value OCMessage::get_encrypted(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->encrypted);
}

void OCMessage::set_encrypted(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->encrypted = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}
#endif

Napi::Value OCMessage::get_endpoint(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

void OCMessage::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->endpoint = *(*(value.As<External<shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value OCMessage::get_length(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->length);
}

void OCMessage::set_length(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->length = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCMessage::get_pool(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_memb*> sp(&m_pvalue->pool, nop_deleter);
    auto accessor = External<shared_ptr<oc_memb*>>::New(info.Env(), &sp);
    return OCMemb::constructor.New({accessor});
}

void OCMessage::set_pool(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->pool = *(*(value.As<External<shared_ptr<oc_memb*>>>().Data()));
}

#if defined(OC_TCP)
Napi::Value OCMessage::get_read_offset(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->read_offset);
}

void OCMessage::set_read_offset(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->read_offset = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}
#endif

Napi::Value OCMessage::get_ref_count(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->ref_count);
}

void OCMessage::set_ref_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->ref_count = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCMmem::constructor;

Napi::Function OCMmem::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCMmem", {
        InstanceAccessor("size", &OCMmem::get_size, &OCMmem::set_size),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCMmem::~OCMmem()
{
}
OCMmem::OCMmem(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_mmem>(new oc_mmem());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_mmem>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCMmem::get_size(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->size);
}

void OCMmem::set_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->size = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCNetworkInterfaceCb::constructor;

Napi::Function OCNetworkInterfaceCb::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCNetworkInterfaceCb", {
        InstanceAccessor("handler", &OCNetworkInterfaceCb::get_handler, &OCNetworkInterfaceCb::set_handler),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCNetworkInterfaceCb::~OCNetworkInterfaceCb()
{
}
OCNetworkInterfaceCb::OCNetworkInterfaceCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_network_interface_cb>(new oc_network_interface_cb());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_network_interface_cb>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCNetworkInterfaceCb::get_handler(const Napi::CallbackInfo& info)
{
    return handler_function;
}

void OCNetworkInterfaceCb::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    handler_function = value;
}

Napi::FunctionReference OCPlatformInfo::constructor;

Napi::Function OCPlatformInfo::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCPlatformInfo", {
        InstanceAccessor("data", &OCPlatformInfo::get_data, &OCPlatformInfo::set_data),
        InstanceAccessor("init_platform_cb", &OCPlatformInfo::get_init_platform_cb, &OCPlatformInfo::set_init_platform_cb),
        InstanceAccessor("mfg_name", &OCPlatformInfo::get_mfg_name, &OCPlatformInfo::set_mfg_name),
        InstanceAccessor("pi", &OCPlatformInfo::get_pi, &OCPlatformInfo::set_pi),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCPlatformInfo::~OCPlatformInfo()
{
}
OCPlatformInfo::OCPlatformInfo(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_platform_info_t>(new oc_platform_info_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_platform_info_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCPlatformInfo::get_data(const Napi::CallbackInfo& info)
{
    return init_platform_cb_data;
}

void OCPlatformInfo::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    init_platform_cb_data = value;
}

Napi::Value OCPlatformInfo::get_init_platform_cb(const Napi::CallbackInfo& info)
{
    return init_platform_cb_function;
}

void OCPlatformInfo::set_init_platform_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    init_platform_cb_function = value;
}

Napi::Value OCPlatformInfo::get_mfg_name(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->mfg_name, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCPlatformInfo::set_mfg_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->mfg_name = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCPlatformInfo::get_pi(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->pi, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCPlatformInfo::set_pi(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->pi = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}


Napi::FunctionReference OCPropertiesCb::constructor;

Napi::Function OCPropertiesCb::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCPropertiesCb", {

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCPropertiesCb::~OCPropertiesCb()
{
}
OCPropertiesCb::OCPropertiesCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_properties_cb_t>(new oc_properties_cb_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_properties_cb_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}

Napi::FunctionReference OCRepresentation::constructor;

Napi::Function OCRepresentation::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRepresentation", {
        InstanceAccessor("name", &OCRepresentation::get_name, &OCRepresentation::set_name),
        InstanceAccessor("type", &OCRepresentation::get_type, &OCRepresentation::set_type),
        InstanceAccessor("value", &OCRepresentation::get_value, &OCRepresentation::set_value),
        InstanceMethod("get_bool", &OCRepresentation::get_bool),
        InstanceMethod("get_bool_array", &OCRepresentation::get_bool_array),
        InstanceMethod("get_byte_string", &OCRepresentation::get_byte_string),
        InstanceMethod("get_byte_string_array", &OCRepresentation::get_byte_string_array),
        InstanceMethod("get_cbor_errno", &OCRepresentation::get_cbor_errno),
        InstanceMethod("get_double", &OCRepresentation::get_double),
        InstanceMethod("get_double_array", &OCRepresentation::get_double_array),
        InstanceMethod("get_object", &OCRepresentation::get_object),
        InstanceMethod("get_object_array", &OCRepresentation::get_object_array),
        InstanceMethod("get_string", &OCRepresentation::get_string),
        InstanceMethod("get_string_array", &OCRepresentation::get_string_array),
        InstanceMethod("get_int", &OCRepresentation::get_int),
        InstanceMethod("get_int_array", &OCRepresentation::get_int_array),
        InstanceMethod("toString", &OCRepresentation::toString),
        StaticMethod("parse", &OCRepresentation::parse),
        StaticMethod("set_pool", &OCRepresentation::set_pool),
        StaticMethod("get_encoded_payload_size", &OCRepresentation::get_encoded_payload_size),
        StaticMethod("get_encoder_buf", &OCRepresentation::get_encoder_buf),
        StaticMethod("add_boolean", &OCRepresentation::add_boolean),
        StaticMethod("add_byte_string", &OCRepresentation::add_byte_string),
        StaticMethod("add_double", &OCRepresentation::add_double),
        StaticMethod("add_text_string", &OCRepresentation::add_text_string),
        StaticMethod("clear_cbor_errno", &OCRepresentation::clear_cbor_errno),
        StaticMethod("close_array", &OCRepresentation::close_array),
        StaticMethod("close_object", &OCRepresentation::close_object),
        StaticMethod("delete_buffer", &OCRepresentation::delete_buffer),
        StaticMethod("end_array", &OCRepresentation::end_array),
        StaticMethod("end_links_array", &OCRepresentation::end_links_array),
        StaticMethod("end_object", &OCRepresentation::end_object),
        StaticMethod("end_root_object", &OCRepresentation::end_root_object),
        StaticMethod("get_rep_from_root_object", &OCRepresentation::get_rep_from_root_object),
        StaticMethod("new_buffer", &OCRepresentation::new_buffer),
        StaticMethod("object_array_start_item", &OCRepresentation::object_array_start_item),
        StaticMethod("object_array_end_item", &OCRepresentation::object_array_end_item),
        StaticMethod("oc_array_to_bool_array", &OCRepresentation::oc_array_to_bool_array),
        StaticMethod("oc_array_to_double_array", &OCRepresentation::oc_array_to_double_array),
        StaticMethod("oc_array_to_int_array", &OCRepresentation::oc_array_to_int_array),
        StaticMethod("oc_array_to_string_array", &OCRepresentation::oc_array_to_string_array),
        StaticMethod("open_array", &OCRepresentation::open_array),
        StaticMethod("open_object", &OCRepresentation::open_object),
        StaticMethod("set_boolean", &OCRepresentation::set_boolean),
        StaticMethod("set_bool_array", &OCRepresentation::set_bool_array),
        StaticMethod("set_byte_string", &OCRepresentation::set_byte_string),
        StaticMethod("set_double", &OCRepresentation::set_double),
        StaticMethod("set_double_array", &OCRepresentation::set_double_array),
        StaticMethod("set_key", &OCRepresentation::set_key),
        StaticMethod("set_long", &OCRepresentation::set_long),
        StaticMethod("set_long_array", &OCRepresentation::set_long_array),
        StaticMethod("set_string_array", &OCRepresentation::set_string_array),
        StaticMethod("set_text_string", &OCRepresentation::set_text_string),
        StaticMethod("set_uint", &OCRepresentation::set_uint),
        StaticMethod("start_array", &OCRepresentation::start_array),
        StaticMethod("start_links_array", &OCRepresentation::start_links_array),
        StaticMethod("start_object", &OCRepresentation::start_object),
        StaticMethod("start_root_object", &OCRepresentation::start_root_object),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCRepresentation::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRepresentation::~OCRepresentation()
{
}

OCRepresentation::OCRepresentation(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        //TODO m_pvalue = shared_ptr<oc_rep_s>( oc_rep_new(), oc_free_rep);
    }
    else if (info.Length() == 1 && info[0].IsExternal()) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_rep_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCRepresentation::get_name(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->name, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCRepresentation::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->name = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCRepresentation::get_type(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->type);
}

void OCRepresentation::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->type = static_cast<oc_rep_value_type_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCRepresentation::get_value(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_rep_s::oc_rep_value> sp(&m_pvalue->value, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_s::oc_rep_value>>::New(info.Env(), &sp);
    return OCValue::constructor.New({accessor});
}

void OCRepresentation::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->value = *(*(value.As<External<shared_ptr<oc_rep_s::oc_rep_value>>>().Data()));
}

Value OCRepresentation::get_bool(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    bool ret;
    bool success = oc_rep_get_bool(rep, key, &ret);
    if(!success) {
        return info.Env().Undefined();
    }
    return Boolean::New(info.Env(), ret);
}

Value OCRepresentation::get_bool_array(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();
// 1 value, bool**
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
    return Boolean::New(info.Env(), 0);
}

Value OCRepresentation::get_byte_string(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();
// 1 value, char**
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
    return Boolean::New(info.Env(), 0);
}

Value OCRepresentation::get_byte_string_array(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();
    auto& value = *OCStringArray::Unwrap(info[1].ToObject());
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
    return Boolean::New(info.Env(), oc_rep_get_byte_string_array(rep, key, value, size));
}

Value OCRepresentation::get_cbor_errno(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_rep_get_cbor_errno());
}

Value OCRepresentation::get_double(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    double ret;
    bool success = oc_rep_get_double(rep, key, &ret);
    if(!success) {
        return info.Env().Undefined();
    }
    return Number::New(info.Env(), ret);
}

Value OCRepresentation::get_double_array(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    double* ret;
    size_t sz;
    bool success = oc_rep_get_double_array(rep, key, &ret, &sz);
    if(!success) {
        return info.Env().Undefined();
    }
    auto array = Float64Array::New(info.Env(), sz);
    for (uint32_t i = 0; i < sz; i++) {
        array[i] = ret[i];
    }
    return array;
}

Value OCRepresentation::get_object(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    oc_rep_t* ret;
    bool success = oc_rep_get_object(rep, key, &ret);
    if (!success) {
        return info.Env().Undefined();
    }

    shared_ptr<oc_rep_t> sp(ret, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_t>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({ accessor });
}

Value OCRepresentation::get_object_array(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();
// 1 value, oc_rep_t**
    return Boolean::New(info.Env(), 0);
}

Value OCRepresentation::get_string(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    char* ret;
    size_t sz;
    bool success = oc_rep_get_string(rep, key, &ret, &sz);
    if(!success) {
        return info.Env().Undefined();
    }
    return String::New(info.Env(), ret, sz);
}

Value OCRepresentation::get_string_array(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();
    auto& value = *OCStringArray::Unwrap(info[1].ToObject());
    auto size = reinterpret_cast<size_t*>(info[2].As<Uint32Array>().Data());
    return Boolean::New(info.Env(), oc_rep_get_string_array(rep, key, value, size));
}

Value OCRepresentation::get_int(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    int64_t ret;
    bool success = oc_rep_get_int(rep, key, &ret);
    if(!success) {
        return info.Env().Undefined();
    }
    return Number::New(info.Env(), ret);
}

Value OCRepresentation::get_int_array(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());
    auto key_ = info[0].ToString().Utf8Value();
    auto key = key_.c_str();

    int64_t* ret;
    size_t sz;
    bool success = oc_rep_get_int_array(rep, key, &ret, &sz);
    if(!success) {
        return info.Env().Undefined();
    }
    auto array = TypedArrayOf<int64_t>::New(info.Env(), sz, napi_bigint64_array);
    for (uint32_t i = 0; i < sz; i++) {
        array[i] = ret[i];
    }
    return array;
}

Value OCRepresentation::toString(const CallbackInfo& info) {
    auto& rep = *OCRepresentation::Unwrap(info.This().ToObject());

    bool pretty_print = (info.Length() >= 1) ? info[0].ToBoolean().Value() : false;

    size_t buf_size = 0;
    size_t print_size = 0;
    char* buf = nullptr;
    do {
        if (buf) delete[] buf;
        buf_size += 1024;
        buf = new char[buf_size];
        print_size = oc_rep_to_json(rep, buf, buf_size, pretty_print);
    } while (buf_size == print_size);

    auto ret = String::New(info.Env(), buf, print_size);
    delete[] buf;
    return ret;

}

Value OCRepresentation::parse(const CallbackInfo& info) {
    auto payload = reinterpret_cast<const uint8_t*>(info[0].As<TypedArray>().ArrayBuffer().Data());
    int payload_size = info[0].As<TypedArray>().ArrayBuffer().ByteLength();

    oc_rep_t* ret;
    int err = oc_parse_rep(payload, payload_size, &ret);

    if (err) {
        return info.Env().Undefined();
    }
    shared_ptr<oc_rep_t> sp(ret, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_t>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({ accessor });
}

Value OCRepresentation::set_pool(const CallbackInfo& info) {
    auto& rep_objects_pool = *OCMemb::Unwrap(info[0].ToObject());
    (void)oc_rep_set_pool(rep_objects_pool);
    return info.Env().Undefined();
}

Value OCRepresentation::get_encoded_payload_size(const CallbackInfo& info) {
    return Number::New(info.Env(), oc_rep_get_encoded_payload_size());
}

Value OCRepresentation::get_encoder_buf(const CallbackInfo& info) {
    return Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(oc_rep_get_encoder_buf()), oc_rep_get_encoded_payload_size() );
}

Value OCRepresentation::add_boolean(const CallbackInfo& info) {
    auto& arrayObject = *OCCborEncoder::Unwrap(info[0].ToObject());
// 1 value, const bool
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::add_byte_string(const CallbackInfo& info) {
    auto& arrayObject = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto value = reinterpret_cast<const unsigned char*>(info[1].As<TypedArray>().ArrayBuffer().Data());
// 2 length, const size_t
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::add_double(const CallbackInfo& info) {
    auto& arrayObject = *OCCborEncoder::Unwrap(info[0].ToObject());
// 1 value, const double
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::add_text_string(const CallbackInfo& info) {
    auto& arrayObject = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto value_ = info[1].ToString().Utf8Value();
    auto value = value_.c_str();
    (void)helper_rep_add_text_string(arrayObject, value);
    return info.Env().Undefined();
}

Value OCRepresentation::clear_cbor_errno(const CallbackInfo& info) {
    (void)helper_rep_clear_cbor_errno();
    return info.Env().Undefined();
}

Value OCRepresentation::close_array(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto& arrayObject = *OCCborEncoder::Unwrap(info[1].ToObject());
    (void)helper_rep_close_array(object, arrayObject);
    return info.Env().Undefined();
}

Value OCRepresentation::close_object(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto& object = *OCCborEncoder::Unwrap(info[1].ToObject());
    (void)helper_rep_close_object(parent, object);
    return info.Env().Undefined();
}

Value OCRepresentation::delete_buffer(const CallbackInfo& info) {
    (void)helper_rep_delete_buffer();
    return info.Env().Undefined();
}

Value OCRepresentation::end_array(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto& arrayObject = *OCCborEncoder::Unwrap(info[1].ToObject());
    (void)helper_rep_end_array(parent, arrayObject);
    return info.Env().Undefined();
}

Value OCRepresentation::end_links_array(const CallbackInfo& info) {
    (void)helper_rep_end_links_array();
    return info.Env().Undefined();
}

Value OCRepresentation::end_object(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto& object = *OCCborEncoder::Unwrap(info[1].ToObject());
    (void)helper_rep_end_object(parent, object);
    return info.Env().Undefined();
}

Value OCRepresentation::end_root_object(const CallbackInfo& info) {
    (void)helper_rep_end_root_object();
    return info.Env().Undefined();
}

Value OCRepresentation::get_rep_from_root_object(const CallbackInfo& info) {
    shared_ptr<oc_rep_t> sp(helper_rep_get_rep_from_root_object(), nop_deleter);
    auto args = External<shared_ptr<oc_rep_t>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({args});
}

Value OCRepresentation::new_buffer(const CallbackInfo& info) {
    auto size = static_cast<int>(info[0].ToNumber());
    (void)helper_rep_new_buffer(size);
    return info.Env().Undefined();
}

Value OCRepresentation::object_array_start_item(const CallbackInfo& info) {
    auto& arrayObject = *OCCborEncoder::Unwrap(info[0].ToObject());
    shared_ptr<CborEncoder> sp(helper_rep_object_array_start_item(arrayObject), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}

Value OCRepresentation::object_array_end_item(const CallbackInfo& info) {
    auto& parentArrayObject = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto& arrayObject = *OCCborEncoder::Unwrap(info[1].ToObject());
    (void)helper_rep_object_array_end_item(parentArrayObject, arrayObject);
    return info.Env().Undefined();
}

Value OCRepresentation::oc_array_to_bool_array(const CallbackInfo& info) {
    auto& array = *OCArray::Unwrap(info[0].ToObject());
    return Buffer<bool>::New(info.Env(), oc_bool_array(*static_cast<oc_array_t*>(array)), oc_bool_array_size(*(oc_array_t*)array));
}

Value OCRepresentation::oc_array_to_double_array(const CallbackInfo& info) {
    auto& array = *OCArray::Unwrap(info[0].ToObject());
    return Buffer<double>::New(info.Env(), oc_double_array(*static_cast<oc_array_t*>(array)), oc_double_array_size(*(oc_array_t*)array));
}

Value OCRepresentation::oc_array_to_int_array(const CallbackInfo& info) {
    auto& array = *OCArray::Unwrap(info[0].ToObject());
    return Buffer<int64_t>::New(info.Env(), oc_int_array(*static_cast<oc_array_t*>(array)), oc_int_array_size(*(oc_array_t*)array));
}

Value OCRepresentation::oc_array_to_string_array(const CallbackInfo& info) {
    auto& array = *OCArray::Unwrap(info[0].ToObject());
    size_t sz = oc_string_array_get_allocated_size(*(oc_array_t*)array);
    oc_string_array_t* strarray = reinterpret_cast<oc_string_array_t*>((oc_array_t*)array);
    auto buf = Array::New(info.Env(), sz);
    for(uint32_t i=0; i<sz; i++) {
        auto str = String::New(info.Env(), oc_string_array_get_item(*strarray, i));
        buf[i] = str;
    }
    return buf;
}

Value OCRepresentation::open_array(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    shared_ptr<CborEncoder> sp(helper_rep_open_array(parent, key), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}

Value OCRepresentation::open_object(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    shared_ptr<CborEncoder> sp(helper_rep_open_object(parent, key), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}

Value OCRepresentation::set_boolean(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    auto value = info[2].ToBoolean().Value();
    (void)helper_rep_set_boolean(object, key, value);
    return info.Env().Undefined();
}

Value OCRepresentation::set_bool_array(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 values, bool*
    auto length = static_cast<int>(info[3].ToNumber());
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::set_byte_string(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    auto value = reinterpret_cast<const unsigned char*>(info[2].As<TypedArray>().ArrayBuffer().Data());
    auto length = static_cast<size_t>(info[3].ToNumber().Uint32Value());
    (void)helper_rep_set_byte_string(object, key, value, length);
    return info.Env().Undefined();
}

Value OCRepresentation::set_double(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    auto value = info[2].ToNumber().DoubleValue();
    (void)helper_rep_set_double(object, key, value);
    return info.Env().Undefined();
}

Value OCRepresentation::set_double_array(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 values, double*
    auto length = static_cast<int>(info[3].ToNumber());
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::set_key(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    (void)helper_rep_set_key(parent, key);
    return info.Env().Undefined();
}

Value OCRepresentation::set_long(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    auto value = static_cast<int64_t>(info[2].ToNumber());
    (void)helper_rep_set_long(object, key, value);
    return info.Env().Undefined();
}

Value OCRepresentation::set_long_array(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 values, int64_t*
    auto length = static_cast<int>(info[3].ToNumber());
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::set_string_array(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 values, oc_string_array_t
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::set_text_string(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
    auto value_ = info[2].ToString().Utf8Value();
    auto value = value_.c_str();
    (void)helper_rep_set_text_string(object, key, value);
    return info.Env().Undefined();
}

Value OCRepresentation::set_uint(const CallbackInfo& info) {
    auto& object = *OCCborEncoder::Unwrap(info[0].ToObject());
    auto key_ = info[1].ToString().Utf8Value();
    auto key = key_.c_str();
// 2 value, unsigned int
    (void)0;
    return info.Env().Undefined();
}

Value OCRepresentation::start_array(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    shared_ptr<CborEncoder> sp(helper_rep_start_array(parent), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}

Value OCRepresentation::start_links_array(const CallbackInfo& info) {
    shared_ptr<CborEncoder> sp(helper_rep_start_links_array(), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}

Value OCRepresentation::start_object(const CallbackInfo& info) {
    auto& parent = *OCCborEncoder::Unwrap(info[0].ToObject());
    shared_ptr<CborEncoder> sp(helper_rep_start_object(parent), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}

Value OCRepresentation::start_root_object(const CallbackInfo& info) {
    shared_ptr<CborEncoder> sp(helper_rep_start_root_object(), nop_deleter);
    auto args = External<shared_ptr<CborEncoder>>::New(info.Env(), &sp);
    return OCCborEncoder::constructor.New({args});
}


Napi::FunctionReference OCRequestHandler::constructor;

Napi::Function OCRequestHandler::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRequestHandler", {
        InstanceAccessor("cb", &OCRequestHandler::get_cb, &OCRequestHandler::set_cb),
        InstanceAccessor("user_data", &OCRequestHandler::get_user_data, &OCRequestHandler::set_user_data),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRequestHandler::~OCRequestHandler()
{
}
OCRequestHandler::OCRequestHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_request_handler_s>(new oc_request_handler_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_request_handler_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCRequestHandler::get_cb(const Napi::CallbackInfo& info)
{
    return cb_function;
}

void OCRequestHandler::set_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    cb_function = value;
}

Napi::Value OCRequestHandler::get_user_data(const Napi::CallbackInfo& info)
{
    return cb_data;
}

void OCRequestHandler::set_user_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    cb_data = value;
}

Napi::FunctionReference OCRequest::constructor;

Napi::Function OCRequest::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRequest", {
        InstanceAccessor("_payload", &OCRequest::get__payload, &OCRequest::set__payload),
        InstanceAccessor("_payload_len", &OCRequest::get__payload_len, &OCRequest::set__payload_len),
        InstanceAccessor("content_format", &OCRequest::get_content_format, &OCRequest::set_content_format),
        InstanceAccessor("origin", &OCRequest::get_origin, &OCRequest::set_origin),
        InstanceAccessor("query", &OCRequest::get_query, &OCRequest::set_query),
        InstanceAccessor("query_len", &OCRequest::get_query_len, &OCRequest::set_query_len),
        InstanceAccessor("request_payload", &OCRequest::get_request_payload, &OCRequest::set_request_payload),
        InstanceAccessor("resource", &OCRequest::get_resource, &OCRequest::set_resource),
        InstanceAccessor("response", &OCRequest::get_response, &OCRequest::set_response),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRequest::~OCRequest()
{
}
OCRequest::OCRequest(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_request_t>(new oc_request_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_request_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCRequest::get__payload(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(m_pvalue->_payload), m_pvalue->_payload_len);
}

void OCRequest::set__payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->_payload=     reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data()); //TODO
}

Napi::Value OCRequest::get__payload_len(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->_payload_len);
}

void OCRequest::set__payload_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->_payload_len = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCRequest::get_content_format(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->content_format);
}

void OCRequest::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->content_format = static_cast<oc_content_format_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCRequest::get_origin(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_endpoint_t*> sp(&m_pvalue->origin, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t*>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({accessor});
}

void OCRequest::set_origin(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->origin = *(*(value.As<External<shared_ptr<oc_endpoint_t*>>>().Data()));
}

Napi::Value OCRequest::get_query(const Napi::CallbackInfo& info)
{
    return Buffer<char>::New(info.Env(), const_cast<char*>(m_pvalue->query), m_pvalue->query_len);
}

void OCRequest::set_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->query=     reinterpret_cast<const char*>(value.As<TypedArray>().ArrayBuffer().Data()); //TODO
}

Napi::Value OCRequest::get_query_len(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->query_len);
}

void OCRequest::set_query_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->query_len = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCRequest::get_request_payload(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_rep_t*> sp(&m_pvalue->request_payload, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_t*>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({accessor});
}

void OCRequest::set_request_payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->request_payload = *(*(value.As<External<shared_ptr<oc_rep_t*>>>().Data()));
}

Napi::Value OCRequest::get_resource(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_resource_t*> sp(&m_pvalue->resource, nop_deleter);
    auto accessor = External<shared_ptr<oc_resource_t*>>::New(info.Env(), &sp);
    return OCResource::constructor.New({accessor});
}

void OCRequest::set_resource(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->resource = *(*(value.As<External<shared_ptr<oc_resource_t*>>>().Data()));
}

Napi::Value OCRequest::get_response(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_response_t*> sp(&m_pvalue->response, nop_deleter);
    auto accessor = External<shared_ptr<oc_response_t*>>::New(info.Env(), &sp);
    return OCResponse::constructor.New({accessor});
}

void OCRequest::set_response(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->response = *(*(value.As<External<shared_ptr<oc_response_t*>>>().Data()));
}

Napi::FunctionReference OCResource::constructor;

Napi::Function OCResource::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCResource", {
        InstanceAccessor("default_interface", &OCResource::get_default_interface, &OCResource::set_default_interface),
        InstanceAccessor("delete_handler", &OCResource::get_delete_handler, &OCResource::set_delete_handler),
        InstanceAccessor("device", &OCResource::get_device, &OCResource::set_device),
        InstanceAccessor("get_handler", &OCResource::get_get_handler, &OCResource::set_get_handler),
        InstanceAccessor("get_properties", &OCResource::get_get_properties, &OCResource::set_get_properties),
        InstanceAccessor("interfaces", &OCResource::get_interfaces, &OCResource::set_interfaces),
        InstanceAccessor("name", &OCResource::get_name, &OCResource::set_name),
#if defined(OC_COLLECTIONS)
        InstanceAccessor("num_links", &OCResource::get_num_links, &OCResource::set_num_links),
#endif
        InstanceAccessor("num_observers", &OCResource::get_num_observers, &OCResource::set_num_observers),
        InstanceAccessor("observe_period_seconds", &OCResource::get_observe_period_seconds, &OCResource::set_observe_period_seconds),
        InstanceAccessor("post_handler", &OCResource::get_post_handler, &OCResource::set_post_handler),
        InstanceAccessor("properties", &OCResource::get_properties, &OCResource::set_properties),
        InstanceAccessor("put_handler", &OCResource::get_put_handler, &OCResource::set_put_handler),
        InstanceAccessor("set_properties", &OCResource::get_set_properties, &OCResource::set_set_properties),
        InstanceAccessor("tag_func_desc", &OCResource::get_tag_func_desc, &OCResource::set_tag_func_desc),
        InstanceAccessor("tag_pos_desc", &OCResource::get_tag_pos_desc, &OCResource::set_tag_pos_desc),
        InstanceAccessor("tag_pos_rel", &OCResource::get_tag_pos_rel, &OCResource::set_tag_pos_rel),
        InstanceAccessor("types", &OCResource::get_types, &OCResource::set_types),
        InstanceAccessor("uri", &OCResource::get_uri, &OCResource::set_uri),
        InstanceMethod("bind_resource_interface", &OCResource::bind_resource_interface),
        InstanceMethod("bind_resource_type", &OCResource::bind_resource_type),
        InstanceMethod("make_public", &OCResource::make_public),
        InstanceMethod("set_default_interface", &OCResource::set_default_interface),
        InstanceMethod("set_discoverable", &OCResource::set_discoverable),
        InstanceMethod("set_observable", &OCResource::set_observable),
        InstanceMethod("set_periodic_observable", &OCResource::set_periodic_observable),
        InstanceMethod("set_properties_cbs", &OCResource::set_properties_cbs),
        InstanceMethod("set_request_handler", &OCResource::set_request_handler),
        InstanceMethod("process_baseline_interface", &OCResource::process_baseline_interface),
        InstanceMethod("notify_observers", &OCResource::notify_observers),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCResource::~OCResource()
{
}
OCResource::OCResource(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 4) {
        string name_ = info[0].ToString().Utf8Value();
        auto name = name_.c_str();
        string uri_ = info[1].ToString().Utf8Value();
        auto uri = uri_.c_str();
        uint8_t num_resource_types = static_cast<uint8_t>(info[2].ToNumber().Uint32Value());
        size_t device = static_cast<size_t>(info[3].ToNumber().Uint32Value());

        m_pvalue = shared_ptr<oc_resource_s>( oc_new_resource(name, uri, num_resource_types, device), nop_deleter /* TODO */);
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_resource_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCResource::get_default_interface(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->default_interface);
}

void OCResource::set_default_interface(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->default_interface = static_cast<oc_interface_mask_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResource::get_delete_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->delete_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_delete_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->delete_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_device(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->device);
}

void OCResource::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->device = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResource::get_get_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->get_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->get_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_get_properties(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties, nop_deleter);
    auto accessor = External<shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
    return OCPropertiesCb::constructor.New({accessor});
}

void OCResource::set_get_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->get_properties = *(*(value.As<External<shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCResource::get_interfaces(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->interfaces);
}

void OCResource::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResource::get_name(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->name, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCResource::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->name = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

#if defined(OC_COLLECTIONS)
Napi::Value OCResource::get_num_links(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->num_links);
}

void OCResource::set_num_links(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->num_links = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}
#endif

Napi::Value OCResource::get_num_observers(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->num_observers);
}

void OCResource::set_num_observers(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->num_observers = static_cast<uint8_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResource::get_observe_period_seconds(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->observe_period_seconds);
}

void OCResource::set_observe_period_seconds(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->observe_period_seconds = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResource::get_post_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->post_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_post_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->post_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_properties(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->properties);
}

void OCResource::set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->properties = static_cast<oc_resource_properties_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResource::get_put_handler(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_request_handler_s> sp(&m_pvalue->put_handler, nop_deleter);
    auto accessor = External<shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
    return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->put_handler = *(*(value.As<External<shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_set_properties(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties, nop_deleter);
    auto accessor = External<shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
    return OCPropertiesCb::constructor.New({accessor});
}

void OCResource::set_set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->set_properties = *(*(value.As<External<shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCResource::get_tag_func_desc(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->tag_func_desc);
}

void OCResource::set_tag_func_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    oc_resource_tag_func_desc(m_pvalue.get(), static_cast<oc_enum_t>(value.ToNumber().Uint32Value()));
}

Napi::Value OCResource::get_tag_pos_desc(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->tag_pos_desc);
}

void OCResource::set_tag_pos_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    oc_resource_tag_pos_desc(m_pvalue.get(), static_cast<oc_pos_description_t>(value.ToNumber().Uint32Value()));
}

Napi::Value OCResource::get_tag_pos_rel(const Napi::CallbackInfo& info)
{
    auto array = Float64Array::New(info.Env(), 3);
    array[0] = m_pvalue->tag_pos_rel[0];
    array[1] = m_pvalue->tag_pos_rel[1];
    array[2] = m_pvalue->tag_pos_rel[2];
    return array;
}

void OCResource::set_tag_pos_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    oc_resource_tag_pos_rel(m_pvalue.get(), value.As<Float64Array>()[0],
                            value.As<Float64Array>()[1],
                            value.As<Float64Array>()[2]);
}

Napi::Value OCResource::get_types(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_string_array_t> sp(&m_pvalue->types, nop_deleter);
    auto accessor = External<shared_ptr<oc_string_array_t>>::New(info.Env(), &sp);
    return OCStringArray::constructor.New({accessor});
}

void OCResource::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->types = *(*(value.As<External<shared_ptr<oc_string_array_t>>>().Data()));
}

Napi::Value OCResource::get_uri(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->uri, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCResource::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->uri = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Value OCResource::bind_resource_interface(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto iface_mask = static_cast<oc_interface_mask_t>(info[0].ToNumber().Uint32Value());
    (void)oc_resource_bind_resource_interface(resource, iface_mask);
    return info.Env().Undefined();
}

Value OCResource::bind_resource_type(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto type_ = info[0].ToString().Utf8Value();
    auto type = type_.c_str();
    (void)oc_resource_bind_resource_type(resource, type);
    return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Value OCResource::make_public(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    (void)oc_resource_make_public(resource);
    return info.Env().Undefined();
}
#endif

Value OCResource::set_default_interface(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto iface_mask = static_cast<oc_interface_mask_t>(info[0].ToNumber().Uint32Value());
    (void)oc_resource_set_default_interface(resource, iface_mask);
    return info.Env().Undefined();
}

Value OCResource::set_discoverable(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto state = info[0].ToBoolean().Value();
    (void)oc_resource_set_discoverable(resource, state);
    return info.Env().Undefined();
}

Value OCResource::set_observable(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto state = info[0].ToBoolean().Value();
    (void)oc_resource_set_observable(resource, state);
    return info.Env().Undefined();
}

Value OCResource::set_periodic_observable(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto seconds = static_cast<uint16_t>(info[0].ToNumber().Uint32Value());
    (void)oc_resource_set_periodic_observable(resource, seconds);
    return info.Env().Undefined();
}

Value OCResource::set_properties_cbs(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto get_props = check_callback_func(info, 0, oc_resource_set_properties_cbs_get_helper);
    const int O_FUNC_G = 0;
    auto get_propr_user_data  =  check_callback_context(info, O_FUNC_G, 1);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(get_propr_user_data));
    auto set_props = check_callback_func(info, 2, oc_resource_set_properties_cbs_set_helper);
    const int O_FUNC_S = 2;
    auto set_props_user_data  =  check_callback_context(info, O_FUNC_S, 3);
    main_context->callback_helper_array.push_back(shared_ptr<ThreadSafeCallback>(set_props_user_data));
    (void)oc_resource_set_properties_cbs(resource, get_props, get_propr_user_data, set_props, set_props_user_data);
    return info.Env().Undefined();
}

Value OCResource::set_request_handler(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    auto method = static_cast<oc_method_t>(info[0].ToNumber().Uint32Value());
    oc_request_callback_t callback = nullptr;
    switch(method) {
    case OC_GET:
        get_handler.Reset(info[1].As<Function>());
        get_value = info[2];
        break;
    case OC_POST:
        post_handler.Reset(info[1].As<Function>());
        post_value = info[2];
        break;
    case OC_PUT:
        put_handler.Reset(info[1].As<Function>());
        put_value = info[2];
        break;
    }
    void* user_data = info[2];
    (void)oc_resource_set_request_handler(resource, method, callback, user_data);
    return info.Env().Undefined();
}

Value OCResource::process_baseline_interface(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    (void)oc_process_baseline_interface(resource);
    return info.Env().Undefined();
}

Value OCResource::notify_observers(const CallbackInfo& info) {
    auto& resource = *OCResource::Unwrap(info.This().ToObject());
    return Number::New(info.Env(), oc_notify_observers(resource));
}


Napi::FunctionReference OCResponseBuffer::constructor;

Napi::Function OCResponseBuffer::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCResponseBuffer", {
        InstanceAccessor("buffer", &OCResponseBuffer::get_buffer, &OCResponseBuffer::set_buffer),
        InstanceAccessor("buffer_size", &OCResponseBuffer::get_buffer_size, &OCResponseBuffer::set_buffer_size),
        InstanceAccessor("code", &OCResponseBuffer::get_code, &OCResponseBuffer::set_code),
        InstanceAccessor("content_format", &OCResponseBuffer::get_content_format, &OCResponseBuffer::set_content_format),
        InstanceAccessor("response_length", &OCResponseBuffer::get_response_length, &OCResponseBuffer::set_response_length),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCResponseBuffer::~OCResponseBuffer()
{
}
OCResponseBuffer::OCResponseBuffer(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_response_buffer_s>(new oc_response_buffer_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_response_buffer_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCResponseBuffer::get_buffer(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, m_pvalue->buffer_size);
}

void OCResponseBuffer::set_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->buffer =     reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data()); //TODO
    m_pvalue->buffer_size = value.As<TypedArray>().ArrayBuffer().ByteLength();
}

Napi::Value OCResponseBuffer::get_buffer_size(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->buffer_size);
}

void OCResponseBuffer::set_buffer_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->buffer_size = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResponseBuffer::get_code(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->code);
}

void OCResponseBuffer::set_code(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->code = static_cast<int>(value.ToNumber());
}

Napi::Value OCResponseBuffer::get_content_format(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->content_format);
}

void OCResponseBuffer::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->content_format = static_cast<oc_content_format_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCResponseBuffer::get_response_length(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->response_length);
}

void OCResponseBuffer::set_response_length(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->response_length = static_cast<uint16_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCResponse::constructor;

Napi::Function OCResponse::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCResponse", {
        InstanceAccessor("response_buffer", &OCResponse::get_response_buffer, &OCResponse::set_response_buffer),
        InstanceAccessor("separate_response", &OCResponse::get_separate_response, &OCResponse::set_separate_response),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCResponse::~OCResponse()
{
}
OCResponse::OCResponse(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_response_t>(new oc_response_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_response_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCResponse::get_response_buffer(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_response_buffer_t*> sp(&m_pvalue->response_buffer, nop_deleter);
    auto accessor = External<shared_ptr<oc_response_buffer_t*>>::New(info.Env(), &sp);
    return OCResponseBuffer::constructor.New({accessor});
}

void OCResponse::set_response_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->response_buffer = *(*(value.As<External<shared_ptr<oc_response_buffer_t*>>>().Data()));
}

Napi::Value OCResponse::get_separate_response(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_separate_response_t*> sp(&m_pvalue->separate_response, nop_deleter);
    auto accessor = External<shared_ptr<oc_separate_response_t*>>::New(info.Env(), &sp);
    return OCSeparateResponse::constructor.New({accessor});
}

void OCResponse::set_separate_response(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->separate_response = *(*(value.As<External<shared_ptr<oc_separate_response_t*>>>().Data()));
}

Napi::FunctionReference OCRole::constructor;

Napi::Function OCRole::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRole", {
        InstanceAccessor("authority", &OCRole::get_authority, &OCRole::set_authority),
        InstanceAccessor("role", &OCRole::get_role, &OCRole::set_role),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCRole::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRole::~OCRole()
{
}
OCRole::OCRole(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_role_t>(new oc_role_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_role_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCRole::get_authority(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->authority, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCRole::set_authority(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->authority = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCRole::get_role(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->role, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCRole::set_role(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->role = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCResourceType::constructor;

Napi::Function OCResourceType::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCResourceType", {
        InstanceAccessor("rt", &OCResourceType::get_rt, &OCResourceType::set_rt),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCResourceType::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCResourceType::~OCResourceType()
{
}
OCResourceType::OCResourceType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_rt_t>(new oc_rt_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_rt_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCResourceType::get_rt(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->rt, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCResourceType::set_rt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rt = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCSecurityAce::constructor;

Napi::Function OCSecurityAce::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSecurityAce", {
        InstanceAccessor("aceid", &OCSecurityAce::get_aceid, &OCSecurityAce::set_aceid),
        InstanceAccessor("permission", &OCSecurityAce::get_permission, &OCSecurityAce::set_permission),
        InstanceAccessor("subject", &OCSecurityAce::get_subject, &OCSecurityAce::set_subject),
        InstanceAccessor("subject_type", &OCSecurityAce::get_subject_type, &OCSecurityAce::set_subject_type),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCSecurityAce::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSecurityAce::~OCSecurityAce()
{
}
OCSecurityAce::OCSecurityAce(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_ace_t>(new oc_sec_ace_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_ace_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSecurityAce::get_aceid(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->aceid);
}

void OCSecurityAce::set_aceid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->aceid = static_cast<int>(value.ToNumber());
}

Napi::Value OCSecurityAce::get_permission(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->permission);
}

void OCSecurityAce::set_permission(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->permission = static_cast<oc_ace_permissions_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCSecurityAce::get_subject(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_ace_subject_t> sp(&m_pvalue->subject, nop_deleter);
    auto accessor = External<shared_ptr<oc_ace_subject_t>>::New(info.Env(), &sp);
    return OCAceSubject::constructor.New({accessor});
}

void OCSecurityAce::set_subject(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->subject = *(*(value.As<External<shared_ptr<oc_ace_subject_t>>>().Data()));
}

Napi::Value OCSecurityAce::get_subject_type(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->subject_type);
}

void OCSecurityAce::set_subject_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->subject_type = static_cast<oc_ace_subject_type_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCSecurityAcl::constructor;

Napi::Function OCSecurityAcl::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSecurityAcl", {
        InstanceAccessor("rowneruuid", &OCSecurityAcl::get_rowneruuid, &OCSecurityAcl::set_rowneruuid),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSecurityAcl::~OCSecurityAcl()
{
}
OCSecurityAcl::OCSecurityAcl(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_acl_s>(new oc_sec_acl_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_acl_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSecurityAcl::get_rowneruuid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->rowneruuid, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCSecurityAcl::set_rowneruuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rowneruuid = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCCreds::constructor;

Napi::Function OCCreds::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCreds", {
        InstanceAccessor("rowneruuid", &OCCreds::get_rowneruuid, &OCCreds::set_rowneruuid),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCreds::~OCCreds()
{
}
OCCreds::OCCreds(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_creds_t>(new oc_sec_creds_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_creds_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCreds::get_rowneruuid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->rowneruuid, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCCreds::set_rowneruuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->rowneruuid = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCCred::constructor;

Napi::Function OCCred::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCred", {
#if defined(OC_PKI)
        InstanceAccessor("chain", &OCCred::get_chain, &OCCred::set_chain),
#endif
#if defined(OC_PKI)
        InstanceAccessor("child", &OCCred::get_child, &OCCred::set_child),
#endif
        InstanceAccessor("credid", &OCCred::get_credid, &OCCred::set_credid),
        InstanceAccessor("credtype", &OCCred::get_credtype, &OCCred::set_credtype),
#if defined(OC_PKI)
        InstanceAccessor("credusage", &OCCred::get_credusage, &OCCred::set_credusage),
#endif
        InstanceAccessor("owner_cred", &OCCred::get_owner_cred, &OCCred::set_owner_cred),
        InstanceAccessor("privatedata", &OCCred::get_privatedata, &OCCred::set_privatedata),
#if defined(OC_PKI)
        InstanceAccessor("publicdata", &OCCred::get_publicdata, &OCCred::set_publicdata),
#endif
        InstanceAccessor("subjectuuid", &OCCred::get_subjectuuid, &OCCred::set_subjectuuid),
        StaticMethod("read_credusage", &OCCred::read_credusage),
        StaticMethod("read_encoding", &OCCred::read_encoding),
        StaticMethod("parse_credusage", &OCCred::parse_credusage),
        StaticMethod("parse_encoding", &OCCred::parse_encoding),
        StaticMethod("credtype_string", &OCCred::credtype_string),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCred::~OCCred()
{
}
OCCred::OCCred(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_cred_t>(new oc_sec_cred_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_cred_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
#if defined(OC_PKI)
Napi::Value OCCred::get_chain(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_sec_cred_t*> sp(&m_pvalue->chain);
    auto accessor = External<shared_ptr<oc_sec_cred_t*>>::New(info.Env(), &sp);
    return OCCred::constructor.New({accessor});

}

void OCCred::set_chain(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->chain = *(*(value.As<External<shared_ptr<oc_sec_cred_t*>>>().Data()));
}
#endif

#if defined(OC_PKI)
Napi::Value OCCred::get_child(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_sec_cred_t*> sp(&m_pvalue->child);
    auto accessor = External<shared_ptr<oc_sec_cred_t*>>::New(info.Env(), &sp);
    return OCCred::constructor.New({accessor});

}

void OCCred::set_child(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->child = *(*(value.As<External<shared_ptr<oc_sec_cred_t*>>>().Data()));
}
#endif

Napi::Value OCCred::get_credid(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->credid);
}

void OCCred::set_credid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->credid = static_cast<int>(value.ToNumber());
}

Napi::Value OCCred::get_credtype(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->credtype);
}

void OCCred::set_credtype(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->credtype = static_cast<oc_sec_credtype_t>(value.ToNumber().Uint32Value());
}

#if defined(OC_PKI)
Napi::Value OCCred::get_credusage(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->credusage);
}

void OCCred::set_credusage(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->credusage = static_cast<oc_sec_credusage_t>(value.ToNumber().Uint32Value());
}
#endif

Napi::Value OCCred::get_owner_cred(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->owner_cred);
}

void OCCred::set_owner_cred(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->owner_cred = value.ToBoolean().Value();
}

Napi::Value OCCred::get_privatedata(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_cred_data_t> sp(&m_pvalue->privatedata, nop_deleter);
    auto accessor = External<shared_ptr<oc_cred_data_t>>::New(info.Env(), &sp);
    return OCCredData::constructor.New({accessor});
}

void OCCred::set_privatedata(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->privatedata = *(*(value.As<External<shared_ptr<oc_cred_data_t>>>().Data()));
}

#if defined(OC_PKI)
Napi::Value OCCred::get_publicdata(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_cred_data_t> sp(&m_pvalue->publicdata, nop_deleter);
    auto accessor = External<shared_ptr<oc_cred_data_t>>::New(info.Env(), &sp);
    return OCCredData::constructor.New({accessor});
}

void OCCred::set_publicdata(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->publicdata = *(*(value.As<External<shared_ptr<oc_cred_data_t>>>().Data()));
}
#endif

Napi::Value OCCred::get_subjectuuid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->subjectuuid, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCCred::set_subjectuuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->subjectuuid = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCCred::read_credusage(const CallbackInfo& info) {
    auto credusage = static_cast<oc_sec_credusage_t>(info[0].ToNumber().Uint32Value());
    return String::New(info.Env(), oc_cred_read_credusage(credusage));
}
#endif

#if defined(OC_SECURITY)
Value OCCred::read_encoding(const CallbackInfo& info) {
    auto encoding = static_cast<oc_sec_encoding_t>(info[0].ToNumber().Uint32Value());
    return String::New(info.Env(), oc_cred_read_encoding(encoding));
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Value OCCred::parse_credusage(const CallbackInfo& info) {
    auto& credusage_string = *OCMmem::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_cred_parse_credusage(credusage_string));
}
#endif

#if defined(OC_SECURITY)
Value OCCred::parse_encoding(const CallbackInfo& info) {
    auto& encoding_string = *OCMmem::Unwrap(info[0].ToObject());
    return Number::New(info.Env(), oc_cred_parse_encoding(encoding_string));
}
#endif

#if defined(OC_SECURITY)
Value OCCred::credtype_string(const CallbackInfo& info) {
    auto credtype = static_cast<oc_sec_credtype_t>(info[0].ToNumber().Uint32Value());
    return String::New(info.Env(), oc_cred_credtype_string(credtype));
}
#endif


Napi::FunctionReference OCSeparateResponse::constructor;

Napi::Function OCSeparateResponse::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSeparateResponse", {
        InstanceAccessor("active", &OCSeparateResponse::get_active, &OCSeparateResponse::set_active),
        InstanceAccessor("buffer", &OCSeparateResponse::get_buffer, &OCSeparateResponse::set_buffer),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSeparateResponse::~OCSeparateResponse()
{
}
OCSeparateResponse::OCSeparateResponse(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_separate_response_s>(new oc_separate_response_s());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_separate_response_s>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSeparateResponse::get_active(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->active);
}

void OCSeparateResponse::set_active(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->active = static_cast<int>(value.ToNumber());
}

Napi::Value OCSeparateResponse::get_buffer(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, OC_MAX_APP_DATA_SIZE);
}

void OCSeparateResponse::set_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->buffer =     reinterpret_cast<uint8_t*>(value.As<TypedArray>().ArrayBuffer().Data()); //TODO
}

Napi::FunctionReference OCSessionEventCb::constructor;

Napi::Function OCSessionEventCb::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSessionEventCb", {
        InstanceAccessor("handler", &OCSessionEventCb::get_handler, &OCSessionEventCb::set_handler),
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCSessionEventCb::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSessionEventCb::~OCSessionEventCb()
{
}
OCSessionEventCb::OCSessionEventCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_session_event_cb>(new oc_session_event_cb());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_session_event_cb>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSessionEventCb::get_handler(const Napi::CallbackInfo& info)
{
    return handler_function;
}

void OCSessionEventCb::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    handler_function = value;
}

Napi::FunctionReference OCSoftwareUpdateHandler::constructor;

Napi::Function OCSoftwareUpdateHandler::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSoftwareUpdateHandler", {
        InstanceAccessor("check_new_version", &OCSoftwareUpdateHandler::get_check_new_version, &OCSoftwareUpdateHandler::set_check_new_version),
        InstanceAccessor("download_update", &OCSoftwareUpdateHandler::get_download_update, &OCSoftwareUpdateHandler::set_download_update),
        InstanceAccessor("perform_upgrade", &OCSoftwareUpdateHandler::get_perform_upgrade, &OCSoftwareUpdateHandler::set_perform_upgrade),
        InstanceAccessor("validate_purl", &OCSoftwareUpdateHandler::get_validate_purl, &OCSoftwareUpdateHandler::set_validate_purl),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSoftwareUpdateHandler::~OCSoftwareUpdateHandler()
{
}
OCSoftwareUpdateHandler::OCSoftwareUpdateHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_swupdate_cb_t>(new oc_swupdate_cb_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_swupdate_cb_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSoftwareUpdateHandler::get_check_new_version(const Napi::CallbackInfo& info)
{
    return check_new_version_function ;
}

void OCSoftwareUpdateHandler::set_check_new_version(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    check_new_version_function = value;
}

Napi::Value OCSoftwareUpdateHandler::get_download_update(const Napi::CallbackInfo& info)
{
    return download_update_function;
}

void OCSoftwareUpdateHandler::set_download_update(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    download_update_function = value;
}

Napi::Value OCSoftwareUpdateHandler::get_perform_upgrade(const Napi::CallbackInfo& info)
{
    return perform_upgrade_function;
}

void OCSoftwareUpdateHandler::set_perform_upgrade(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    perform_upgrade_function = value;
}

Napi::Value OCSoftwareUpdateHandler::get_validate_purl(const Napi::CallbackInfo& info)
{
    return validate_purl_function;
}

void OCSoftwareUpdateHandler::set_validate_purl(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    validate_purl_function = value;
}

Napi::FunctionReference OCTimer::constructor;

Napi::Function OCTimer::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCTimer", {
        InstanceAccessor("interval", &OCTimer::get_interval, &OCTimer::set_interval),
        InstanceAccessor("start", &OCTimer::get_start, &OCTimer::set_start),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCTimer::~OCTimer()
{
}
OCTimer::OCTimer(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_timer>(new oc_timer());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_timer>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCTimer::get_interval(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->interval);
}

void OCTimer::set_interval(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->interval = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCTimer::get_start(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->start);
}

void OCTimer::set_start(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->start = static_cast<uint32_t>(value.ToNumber().Uint32Value());
}

Napi::FunctionReference OCUuid::constructor;

Napi::Function OCUuid::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCUuid", {
        InstanceAccessor("id", &OCUuid::get_id, &OCUuid::set_id),
        InstanceMethod("toString", &OCUuid::toString),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCUuid::~OCUuid()
{
}

OCUuid::OCUuid(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_uuid_t>(new oc_uuid_t());
        oc_gen_uuid(m_pvalue.get());
    }
    else if (info.Length() == 1 && info[0].IsString()) {
        m_pvalue = shared_ptr<oc_uuid_t>(new oc_uuid_t());
        oc_str_to_uuid(info[0].ToString().Utf8Value().c_str(), m_pvalue.get());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_uuid_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCUuid::get_id(const Napi::CallbackInfo& info)
{
    return Buffer<uint8_t>::New(info.Env(), m_pvalue->id, 16);
}

void OCUuid::set_id(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    for(uint32_t i=0; i<16; i++) {
        m_pvalue->id[i] = reinterpret_cast<uint8_t*>(info[0].As<TypedArray>().ArrayBuffer().Data())[i];
    }
}

Value OCUuid::toString(const CallbackInfo& info) {
    auto& uuid = *OCUuid::Unwrap(info.This().ToObject());

    char buffer[OC_UUID_LEN] = { 0 };
    (void)oc_uuid_to_str(uuid, buffer, OC_UUID_LEN);
    return String::New(info.Env(), buffer);
}


Napi::FunctionReference OCAceSubject::constructor;

Napi::Function OCAceSubject::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAceSubject", {
        InstanceAccessor("conn", &OCAceSubject::get_conn, &OCAceSubject::set_conn),
        InstanceAccessor("uuid", &OCAceSubject::get_uuid, &OCAceSubject::set_uuid),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAceSubject::~OCAceSubject()
{
}
OCAceSubject::OCAceSubject(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ace_subject_t>(new oc_ace_subject_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ace_subject_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCAceSubject::get_conn(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->conn);
}

void OCAceSubject::set_conn(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->conn = static_cast<oc_ace_connection_type_t>(value.ToNumber().Uint32Value());
}

Napi::Value OCAceSubject::get_uuid(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_uuid_t> sp(&m_pvalue->uuid, nop_deleter);
    auto accessor = External<shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
    return OCUuid::constructor.New({accessor});
}

void OCAceSubject::set_uuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->uuid = *(*(value.As<External<shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference DevAddr::constructor;

Napi::Function DevAddr::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "DevAddr", {
        InstanceAccessor("bt", &DevAddr::get_bt, &DevAddr::set_bt),
        InstanceAccessor("ipv4", &DevAddr::get_ipv4, &DevAddr::set_ipv4),
        InstanceAccessor("ipv6", &DevAddr::get_ipv6, &DevAddr::set_ipv6),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

DevAddr::~DevAddr()
{
}
DevAddr::DevAddr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_endpoint_t::dev_addr>(new oc_endpoint_t::dev_addr());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_endpoint_t::dev_addr>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value DevAddr::get_bt(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_le_addr_t> sp(&m_pvalue->bt, nop_deleter);
    auto accessor = External<shared_ptr<oc_le_addr_t>>::New(info.Env(), &sp);
    return OCLEAddr::constructor.New({accessor});
}

void DevAddr::set_bt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->bt = *(*(value.As<External<shared_ptr<oc_le_addr_t>>>().Data()));
}

Napi::Value DevAddr::get_ipv4(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_ipv4_addr_t> sp(&m_pvalue->ipv4, nop_deleter);
    auto accessor = External<shared_ptr<oc_ipv4_addr_t>>::New(info.Env(), &sp);
    return OCIPv4Addr::constructor.New({accessor});
}

void DevAddr::set_ipv4(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->ipv4 = *(*(value.As<External<shared_ptr<oc_ipv4_addr_t>>>().Data()));
}

Napi::Value DevAddr::get_ipv6(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_ipv6_addr_t> sp(&m_pvalue->ipv6, nop_deleter);
    auto accessor = External<shared_ptr<oc_ipv6_addr_t>>::New(info.Env(), &sp);
    return OCIPv6Addr::constructor.New({accessor});
}

void DevAddr::set_ipv6(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->ipv6 = *(*(value.As<External<shared_ptr<oc_ipv6_addr_t>>>().Data()));
}

Napi::FunctionReference OCValue::constructor;

Napi::Function OCValue::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCValue", {
        InstanceAccessor("array", &OCValue::get_array, &OCValue::set_array),
        InstanceAccessor("boolean", &OCValue::get_boolean, &OCValue::set_boolean),
        InstanceAccessor("double_p", &OCValue::get_double_p, &OCValue::set_double_p),
        InstanceAccessor("integer", &OCValue::get_integer, &OCValue::set_integer),
        InstanceAccessor("object", &OCValue::get_object, &OCValue::set_object),
        InstanceAccessor("object_array", &OCValue::get_object_array, &OCValue::set_object_array),
        InstanceAccessor("string", &OCValue::get_string, &OCValue::set_string),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCValue::~OCValue()
{
}
OCValue::OCValue(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_rep_s::oc_rep_value>(new oc_rep_s::oc_rep_value());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_rep_s::oc_rep_value>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCValue::get_array(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_array_t> sp(&m_pvalue->array, nop_deleter);
    auto accessor = External<shared_ptr<oc_array_t>>::New(info.Env(), &sp);
    return OCArray::constructor.New({accessor});
}

void OCValue::set_array(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->array = *(*(value.As<External<shared_ptr<oc_array_t>>>().Data()));
}

Napi::Value OCValue::get_boolean(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->boolean);
}

void OCValue::set_boolean(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->boolean = value.ToBoolean().Value();
}

Napi::Value OCValue::get_double_p(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->double_p);
}

void OCValue::set_double_p(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->double_p = value.ToNumber().DoubleValue();
}

Napi::Value OCValue::get_integer(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), m_pvalue->integer);
}

void OCValue::set_integer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->integer = value.ToNumber().Int64Value();
}

Napi::Value OCValue::get_object(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_rep_s*> sp(&m_pvalue->object, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_s*>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({accessor});
}

void OCValue::set_object(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->object = *(*(value.As<External<shared_ptr<oc_rep_s*>>>().Data()));
}

Napi::Value OCValue::get_object_array(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_rep_s*> sp(&m_pvalue->object_array, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_s*>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({accessor});
}

void OCValue::set_object_array(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->object_array = *(*(value.As<External<shared_ptr<oc_rep_s*>>>().Data()));
}

Napi::Value OCValue::get_string(const Napi::CallbackInfo& info)
{
    shared_ptr<oc_mmem> sp(&m_pvalue->string, nop_deleter);
    auto accessor = External<shared_ptr<oc_mmem>>::New(info.Env(), &sp);
    return OCMmem::constructor.New({accessor});
}

void OCValue::set_string(const Napi::CallbackInfo& info, const Napi::Value& value)
{
    m_pvalue->string = *(*(value.As<External<shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCCborEncoder::constructor;

Napi::Function OCCborEncoder::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCborEncoder", {

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCborEncoder::~OCCborEncoder()
{
}
OCCborEncoder::OCCborEncoder(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<CborEncoder>(new CborEncoder());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<CborEncoder>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}

Napi::FunctionReference OCArray::constructor;

Napi::Function OCArray::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCArray", {

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCArray::~OCArray()
{
}
OCArray::OCArray(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_array_t>(new oc_array_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_array_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}

Napi::FunctionReference OCStringArray::constructor;

Napi::Function OCStringArray::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCStringArray", {
        InstanceMethod(Napi::Symbol::WellKnown(env, "iterator"), &OCStringArray::get_iterator),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCStringArray::~OCStringArray()
{
}
OCStringArray::OCStringArray(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_string_array_t>(new oc_string_array_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_string_array_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}

Napi::FunctionReference OCStringArrayIterator::constructor;

Napi::Function OCStringArrayIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCStringArrayIterator", {
        InstanceAccessor("value", &OCStringArrayIterator::get_value, &OCStringArrayIterator::set_value),
        InstanceAccessor("done", &OCStringArrayIterator::get_done, &OCStringArrayIterator::set_done),
        InstanceMethod("next", &OCStringArrayIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCStringArrayIterator::~OCStringArrayIterator()
{
}

OCStringArrayIterator::OCStringArrayIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_string_array_iterator_t>(new oc_string_array_iterator_t());
        m_pvalue->index = -1;
        m_pvalue->array = *info[0].As<External<shared_ptr<oc_string_array_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCStringArrayIterator::get_value(const Napi::CallbackInfo& info)
{
    return String::New(info.Env(), oc_string_array_get_item(m_pvalue->array, m_pvalue->index));
}

void OCStringArrayIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStringArrayIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->index >= oc_string_array_get_allocated_size(m_pvalue->array));
}

void OCStringArrayIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCEndpointIterator::constructor;

Napi::Function OCEndpointIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEndpointIterator", {
        InstanceAccessor("value", &OCEndpointIterator::get_value, &OCEndpointIterator::set_value),
        InstanceAccessor("done", &OCEndpointIterator::get_done, &OCEndpointIterator::set_done),
        InstanceMethod("next", &OCEndpointIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEndpointIterator::~OCEndpointIterator()
{
}

OCEndpointIterator::OCEndpointIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_endpoint_iterator_t>(new oc_endpoint_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_endpoint_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCEndpointIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_endpoint_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
    return OCEndpoint::constructor.New({ accessor });
}

void OCEndpointIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEndpointIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCEndpointIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCCollectionIterator::constructor;

Napi::Function OCCollectionIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCollectionIterator", {
        InstanceAccessor("value", &OCCollectionIterator::get_value, &OCCollectionIterator::set_value),
        InstanceAccessor("done", &OCCollectionIterator::get_done, &OCCollectionIterator::set_done),
        InstanceMethod("next", &OCCollectionIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCollectionIterator::~OCCollectionIterator()
{
}

OCCollectionIterator::OCCollectionIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_collection_iterator_t>(new oc_collection_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_collection_s>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCCollectionIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_collection_s> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_collection_s>>::New(info.Env(), &sp);
    return OCCollection::constructor.New({ accessor });
}

void OCCollectionIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCollectionIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCCollectionIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCLinkIterator::constructor;

Napi::Function OCLinkIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCLinkIterator", {
        InstanceAccessor("value", &OCLinkIterator::get_value, &OCLinkIterator::set_value),
        InstanceAccessor("done", &OCLinkIterator::get_done, &OCLinkIterator::set_done),
        InstanceMethod("next", &OCLinkIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCLinkIterator::~OCLinkIterator()
{
}

OCLinkIterator::OCLinkIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_link_iterator_t>(new oc_link_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_link_s>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCLinkIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_link_s> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_link_s>>::New(info.Env(), &sp);
    return OCLink::constructor.New({ accessor });
}

void OCLinkIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCLinkIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCLinkIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCSecurityAceIterator::constructor;

Napi::Function OCSecurityAceIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSecurityAceIterator", {
        InstanceAccessor("value", &OCSecurityAceIterator::get_value, &OCSecurityAceIterator::set_value),
        InstanceAccessor("done", &OCSecurityAceIterator::get_done, &OCSecurityAceIterator::set_done),
        InstanceMethod("next", &OCSecurityAceIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSecurityAceIterator::~OCSecurityAceIterator()
{
}

OCSecurityAceIterator::OCSecurityAceIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_sec_ace_iterator_t>(new oc_sec_ace_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_sec_ace_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCSecurityAceIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_sec_ace_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_sec_ace_t>>::New(info.Env(), &sp);
    return OCSecurityAce::constructor.New({ accessor });
}

void OCSecurityAceIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecurityAceIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCSecurityAceIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCAceResourceIterator::constructor;

Napi::Function OCAceResourceIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAceResourceIterator", {
        InstanceAccessor("value", &OCAceResourceIterator::get_value, &OCAceResourceIterator::set_value),
        InstanceAccessor("done", &OCAceResourceIterator::get_done, &OCAceResourceIterator::set_done),
        InstanceMethod("next", &OCAceResourceIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAceResourceIterator::~OCAceResourceIterator()
{
}

OCAceResourceIterator::OCAceResourceIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_ace_res_iterator_t>(new oc_ace_res_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_ace_res_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCAceResourceIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_ace_res_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_ace_res_t>>::New(info.Env(), &sp);
    return OCAceResource::constructor.New({ accessor });
}

void OCAceResourceIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceResourceIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCAceResourceIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCCloudContextIterator::constructor;

Napi::Function OCCloudContextIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCloudContextIterator", {
        InstanceAccessor("value", &OCCloudContextIterator::get_value, &OCCloudContextIterator::set_value),
        InstanceAccessor("done", &OCCloudContextIterator::get_done, &OCCloudContextIterator::set_done),
        InstanceMethod("next", &OCCloudContextIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCloudContextIterator::~OCCloudContextIterator()
{
}

OCCloudContextIterator::OCCloudContextIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_cloud_context_iterator_t>(new oc_cloud_context_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_cloud_context_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCCloudContextIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_cloud_context_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_cloud_context_t>>::New(info.Env(), &sp);
    return OCCloudContext::constructor.New({ accessor });
}

void OCCloudContextIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudContextIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCCloudContextIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCLinkParamsIterator::constructor;

Napi::Function OCLinkParamsIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCLinkParamsIterator", {
        InstanceAccessor("value", &OCLinkParamsIterator::get_value, &OCLinkParamsIterator::set_value),
        InstanceAccessor("done", &OCLinkParamsIterator::get_done, &OCLinkParamsIterator::set_done),
        InstanceMethod("next", &OCLinkParamsIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCLinkParamsIterator::~OCLinkParamsIterator()
{
}

OCLinkParamsIterator::OCLinkParamsIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_link_params_iterator_t>(new oc_link_params_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_link_params_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCLinkParamsIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_link_params_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_link_params_t>>::New(info.Env(), &sp);
    return OCLink::constructor.New({ accessor });
}

void OCLinkParamsIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCLinkParamsIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCLinkParamsIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCResourceTypeIterator::constructor;

Napi::Function OCResourceTypeIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCResourceTypeIterator", {
        InstanceAccessor("value", &OCResourceTypeIterator::get_value, &OCResourceTypeIterator::set_value),
        InstanceAccessor("done", &OCResourceTypeIterator::get_done, &OCResourceTypeIterator::set_done),
        InstanceMethod("next", &OCResourceTypeIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCResourceTypeIterator::~OCResourceTypeIterator()
{
}

OCResourceTypeIterator::OCResourceTypeIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_rt_iterator_t>(new oc_rt_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_rt_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCResourceTypeIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_rt_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_rt_t>>::New(info.Env(), &sp);
    return OCResourceType::constructor.New({ accessor });
}

void OCResourceTypeIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourceTypeIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCResourceTypeIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCEventCallbackIterator::constructor;

Napi::Function OCEventCallbackIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEventCallbackIterator", {
        InstanceAccessor("value", &OCEventCallbackIterator::get_value, &OCEventCallbackIterator::set_value),
        InstanceAccessor("done", &OCEventCallbackIterator::get_done, &OCEventCallbackIterator::set_done),
        InstanceMethod("next", &OCEventCallbackIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEventCallbackIterator::~OCEventCallbackIterator()
{
}

OCEventCallbackIterator::OCEventCallbackIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_event_callback_iterator_t>(new oc_event_callback_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_event_callback_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCEventCallbackIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_event_callback_s> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_event_callback_s>>::New(info.Env(), &sp);
    return OCEventCallback::constructor.New({ accessor });
}

void OCEventCallbackIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEventCallbackIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCEventCallbackIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCMessageIterator::constructor;

Napi::Function OCMessageIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCMessageIterator", {
        InstanceAccessor("value", &OCMessageIterator::get_value, &OCMessageIterator::set_value),
        InstanceAccessor("done", &OCMessageIterator::get_done, &OCMessageIterator::set_done),
        InstanceMethod("next", &OCMessageIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCMessageIterator::~OCMessageIterator()
{
}

OCMessageIterator::OCMessageIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_message_iterator_t>(new oc_message_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_message_s>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCMessageIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_message_s> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_message_s>>::New(info.Env(), &sp);
    return OCMessage::constructor.New({ accessor });
}

void OCMessageIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCMessageIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCMessageIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCRoleIterator::constructor;

Napi::Function OCRoleIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRoleIterator", {
        InstanceAccessor("value", &OCRoleIterator::get_value, &OCRoleIterator::set_value),
        InstanceAccessor("done", &OCRoleIterator::get_done, &OCRoleIterator::set_done),
        InstanceMethod("next", &OCRoleIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRoleIterator::~OCRoleIterator()
{
}

OCRoleIterator::OCRoleIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_role_iterator_t>(new oc_role_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_role_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCRoleIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_role_t> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_role_t>>::New(info.Env(), &sp);
    return OCRole::constructor.New({ accessor });
}

void OCRoleIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRoleIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCRoleIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCSessionEventCbIterator::constructor;

Napi::Function OCSessionEventCbIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSessionEventCbIterator", {
        InstanceAccessor("value", &OCSessionEventCbIterator::get_value, &OCSessionEventCbIterator::set_value),
        InstanceAccessor("done", &OCSessionEventCbIterator::get_done, &OCSessionEventCbIterator::set_done),
        InstanceMethod("next", &OCSessionEventCbIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSessionEventCbIterator::~OCSessionEventCbIterator()
{
}

OCSessionEventCbIterator::OCSessionEventCbIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_session_event_cb_iterator_t>(new oc_session_event_cb_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_session_event_cb_t>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCSessionEventCbIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_session_event_cb> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_session_event_cb>>::New(info.Env(), &sp);
    return OCSessionEventCb::constructor.New({ accessor });
}

void OCSessionEventCbIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSessionEventCbIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCSessionEventCbIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCRepresentationIterator::constructor;

Napi::Function OCRepresentationIterator::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRepresentationIterator", {
        InstanceAccessor("value", &OCRepresentationIterator::get_value, &OCRepresentationIterator::set_value),
        InstanceAccessor("done", &OCRepresentationIterator::get_done, &OCRepresentationIterator::set_done),
        InstanceMethod("next", &OCRepresentationIterator::get_next),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRepresentationIterator::~OCRepresentationIterator()
{
}

OCRepresentationIterator::OCRepresentationIterator(const CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = shared_ptr<oc_rep_iterator_t>(new oc_rep_iterator_t());
        m_pvalue->current = info[0].As<External<shared_ptr<oc_rep_s>>>().Data()->get();
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself").ThrowAsJavaScriptException();
    }
}
Napi::Value OCRepresentationIterator::get_value(const Napi::CallbackInfo& info)
{

    shared_ptr<oc_rep_s> sp(m_pvalue->current, nop_deleter);
    auto accessor = External<shared_ptr<oc_rep_s>>::New(info.Env(), &sp);
    return OCRepresentation::constructor.New({ accessor });
}

void OCRepresentationIterator::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepresentationIterator::get_done(const Napi::CallbackInfo& info)
{
    return Boolean::New(info.Env(), m_pvalue->current == nullptr);
}

void OCRepresentationIterator::set_done(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}









Napi::FunctionReference OCAceConnectionType::constructor;

Napi::Function OCAceConnectionType::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAceConnectionType", {
        StaticAccessor("OC_CONN_AUTH_CRYPT", OCAceConnectionType::get_OC_CONN_AUTH_CRYPT, nullptr),
        StaticAccessor("OC_CONN_ANON_CLEAR", OCAceConnectionType::get_OC_CONN_ANON_CLEAR, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAceConnectionType::~OCAceConnectionType()
{
}
OCAceConnectionType::OCAceConnectionType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ace_connection_type_t>(new oc_ace_connection_type_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ace_connection_type_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCAceConnectionType::get_OC_CONN_AUTH_CRYPT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CONN_AUTH_CRYPT);
}

Napi::Value OCAceConnectionType::get_OC_CONN_ANON_CLEAR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CONN_ANON_CLEAR);
}

Napi::FunctionReference OCAcePermissionsMask::constructor;

Napi::Function OCAcePermissionsMask::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAcePermissionsMask", {
        StaticAccessor("OC_PERM_NONE", OCAcePermissionsMask::get_OC_PERM_NONE, nullptr),
        StaticAccessor("OC_PERM_CREATE", OCAcePermissionsMask::get_OC_PERM_CREATE, nullptr),
        StaticAccessor("OC_PERM_RETRIEVE", OCAcePermissionsMask::get_OC_PERM_RETRIEVE, nullptr),
        StaticAccessor("OC_PERM_UPDATE", OCAcePermissionsMask::get_OC_PERM_UPDATE, nullptr),
        StaticAccessor("OC_PERM_DELETE", OCAcePermissionsMask::get_OC_PERM_DELETE, nullptr),
        StaticAccessor("OC_PERM_NOTIFY", OCAcePermissionsMask::get_OC_PERM_NOTIFY, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAcePermissionsMask::~OCAcePermissionsMask()
{
}
OCAcePermissionsMask::OCAcePermissionsMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ace_permissions_t>(new oc_ace_permissions_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ace_permissions_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCAcePermissionsMask::get_OC_PERM_NONE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERM_NONE);
}

Napi::Value OCAcePermissionsMask::get_OC_PERM_CREATE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERM_CREATE);
}

Napi::Value OCAcePermissionsMask::get_OC_PERM_RETRIEVE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERM_RETRIEVE);
}

Napi::Value OCAcePermissionsMask::get_OC_PERM_UPDATE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERM_UPDATE);
}

Napi::Value OCAcePermissionsMask::get_OC_PERM_DELETE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERM_DELETE);
}

Napi::Value OCAcePermissionsMask::get_OC_PERM_NOTIFY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERM_NOTIFY);
}

Napi::FunctionReference OCAceSubjectType::constructor;

Napi::Function OCAceSubjectType::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAceSubjectType", {
        StaticAccessor("OC_SUBJECT_UUID", OCAceSubjectType::get_OC_SUBJECT_UUID, nullptr),
        StaticAccessor("OC_SUBJECT_ROLE", OCAceSubjectType::get_OC_SUBJECT_ROLE, nullptr),
        StaticAccessor("OC_SUBJECT_CONN", OCAceSubjectType::get_OC_SUBJECT_CONN, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAceSubjectType::~OCAceSubjectType()
{
}
OCAceSubjectType::OCAceSubjectType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ace_subject_type_t>(new oc_ace_subject_type_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ace_subject_type_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCAceSubjectType::get_OC_SUBJECT_UUID(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SUBJECT_UUID);
}

Napi::Value OCAceSubjectType::get_OC_SUBJECT_ROLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SUBJECT_ROLE);
}

Napi::Value OCAceSubjectType::get_OC_SUBJECT_CONN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SUBJECT_CONN);
}

Napi::FunctionReference OCAceWildcard::constructor;

Napi::Function OCAceWildcard::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCAceWildcard", {
        StaticAccessor("OC_ACE_NO_WC", OCAceWildcard::get_OC_ACE_NO_WC, nullptr),
        StaticAccessor("OC_ACE_WC_ALL", OCAceWildcard::get_OC_ACE_WC_ALL, nullptr),
        StaticAccessor("OC_ACE_WC_ALL_SECURED", OCAceWildcard::get_OC_ACE_WC_ALL_SECURED, nullptr),
        StaticAccessor("OC_ACE_WC_ALL_PUBLIC", OCAceWildcard::get_OC_ACE_WC_ALL_PUBLIC, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCAceWildcard::~OCAceWildcard()
{
}
OCAceWildcard::OCAceWildcard(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_ace_wildcard_t>(new oc_ace_wildcard_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_ace_wildcard_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCAceWildcard::get_OC_ACE_NO_WC(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ACE_NO_WC);
}

Napi::Value OCAceWildcard::get_OC_ACE_WC_ALL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ACE_WC_ALL);
}

Napi::Value OCAceWildcard::get_OC_ACE_WC_ALL_SECURED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ACE_WC_ALL_SECURED);
}

Napi::Value OCAceWildcard::get_OC_ACE_WC_ALL_PUBLIC(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ACE_WC_ALL_PUBLIC);
}

Napi::FunctionReference OCBlockwiseRole::constructor;

Napi::Function OCBlockwiseRole::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCBlockwiseRole", {
        StaticAccessor("OC_BLOCKWISE_CLIENT", OCBlockwiseRole::get_OC_BLOCKWISE_CLIENT, nullptr),
        StaticAccessor("OC_BLOCKWISE_SERVER", OCBlockwiseRole::get_OC_BLOCKWISE_SERVER, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCBlockwiseRole::~OCBlockwiseRole()
{
}
OCBlockwiseRole::OCBlockwiseRole(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_blockwise_role_t>(new oc_blockwise_role_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_blockwise_role_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCBlockwiseRole::get_OC_BLOCKWISE_CLIENT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_BLOCKWISE_CLIENT);
}

Napi::Value OCBlockwiseRole::get_OC_BLOCKWISE_SERVER(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_BLOCKWISE_SERVER);
}

Napi::FunctionReference OCDiscoveryFlags::constructor;

Napi::Function OCDiscoveryFlags::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCDiscoveryFlags", {
        StaticAccessor("OC_STOP_DISCOVERY", OCDiscoveryFlags::get_OC_STOP_DISCOVERY, nullptr),
        StaticAccessor("OC_CONTINUE_DISCOVERY", OCDiscoveryFlags::get_OC_CONTINUE_DISCOVERY, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCDiscoveryFlags::~OCDiscoveryFlags()
{
}
OCDiscoveryFlags::OCDiscoveryFlags(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_discovery_flags_t>(new oc_discovery_flags_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_discovery_flags_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCDiscoveryFlags::get_OC_STOP_DISCOVERY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STOP_DISCOVERY);
}

Napi::Value OCDiscoveryFlags::get_OC_CONTINUE_DISCOVERY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CONTINUE_DISCOVERY);
}

Napi::FunctionReference OCQos::constructor;

Napi::Function OCQos::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCQos", {
        StaticAccessor("HIGH_QOS", OCQos::get_HIGH_QOS, nullptr),
        StaticAccessor("LOW_QOS", OCQos::get_LOW_QOS, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCQos::~OCQos()
{
}
OCQos::OCQos(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_qos_t>(new oc_qos_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_qos_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCQos::get_HIGH_QOS(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), HIGH_QOS);
}

Napi::Value OCQos::get_LOW_QOS(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), LOW_QOS);
}

Napi::FunctionReference OCCloudError::constructor;

Napi::Function OCCloudError::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCloudError", {
        StaticAccessor("CLOUD_OK", OCCloudError::get_CLOUD_OK, nullptr),
        StaticAccessor("CLOUD_ERROR_RESPONSE", OCCloudError::get_CLOUD_ERROR_RESPONSE, nullptr),
        StaticAccessor("CLOUD_ERROR_CONNECT", OCCloudError::get_CLOUD_ERROR_CONNECT, nullptr),
        StaticAccessor("CLOUD_ERROR_REFRESH_ACCESS_TOKEN", OCCloudError::get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCloudError::~OCCloudError()
{
}
OCCloudError::OCCloudError(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_cloud_error_t>(new oc_cloud_error_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_cloud_error_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCloudError::get_CLOUD_OK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CLOUD_OK);
}

Napi::Value OCCloudError::get_CLOUD_ERROR_RESPONSE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CLOUD_ERROR_RESPONSE);
}

Napi::Value OCCloudError::get_CLOUD_ERROR_CONNECT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CLOUD_ERROR_CONNECT);
}

Napi::Value OCCloudError::get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
}

Napi::FunctionReference OCCloudStatusMask::constructor;

Napi::Function OCCloudStatusMask::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCloudStatusMask", {
        StaticAccessor("OC_CLOUD_INITIALIZED", OCCloudStatusMask::get_OC_CLOUD_INITIALIZED, nullptr),
        StaticAccessor("OC_CLOUD_REGISTERED", OCCloudStatusMask::get_OC_CLOUD_REGISTERED, nullptr),
        StaticAccessor("OC_CLOUD_LOGGED_IN", OCCloudStatusMask::get_OC_CLOUD_LOGGED_IN, nullptr),
        StaticAccessor("OC_CLOUD_TOKEN_EXPIRY", OCCloudStatusMask::get_OC_CLOUD_TOKEN_EXPIRY, nullptr),
        StaticAccessor("OC_CLOUD_REFRESHED_TOKEN", OCCloudStatusMask::get_OC_CLOUD_REFRESHED_TOKEN, nullptr),
        StaticAccessor("OC_CLOUD_LOGGED_OUT", OCCloudStatusMask::get_OC_CLOUD_LOGGED_OUT, nullptr),
        StaticAccessor("OC_CLOUD_FAILURE", OCCloudStatusMask::get_OC_CLOUD_FAILURE, nullptr),
        StaticAccessor("OC_CLOUD_DEREGISTERED", OCCloudStatusMask::get_OC_CLOUD_DEREGISTERED, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCloudStatusMask::~OCCloudStatusMask()
{
}
OCCloudStatusMask::OCCloudStatusMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_cloud_status_t>(new oc_cloud_status_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_cloud_status_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCloudStatusMask::get_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_INITIALIZED);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_REGISTERED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_REGISTERED);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_LOGGED_IN);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_TOKEN_EXPIRY);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_REFRESHED_TOKEN);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_LOGGED_OUT);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_FAILURE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_FAILURE);
}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CLOUD_DEREGISTERED);
}

Napi::FunctionReference OCCloudPrivisoningStatus::constructor;

Napi::Function OCCloudPrivisoningStatus::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCloudPrivisoningStatus", {
        StaticAccessor("OC_CPS_UNINITIALIZED", OCCloudPrivisoningStatus::get_OC_CPS_UNINITIALIZED, nullptr),
        StaticAccessor("OC_CPS_READYTOREGISTER", OCCloudPrivisoningStatus::get_OC_CPS_READYTOREGISTER, nullptr),
        StaticAccessor("OC_CPS_REGISTERING", OCCloudPrivisoningStatus::get_OC_CPS_REGISTERING, nullptr),
        StaticAccessor("OC_CPS_REGISTERED", OCCloudPrivisoningStatus::get_OC_CPS_REGISTERED, nullptr),
        StaticAccessor("OC_CPS_FAILED", OCCloudPrivisoningStatus::get_OC_CPS_FAILED, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCloudPrivisoningStatus::~OCCloudPrivisoningStatus()
{
}
OCCloudPrivisoningStatus::OCCloudPrivisoningStatus(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_cps_t>(new oc_cps_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_cps_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CPS_UNINITIALIZED);
}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CPS_READYTOREGISTER);
}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_REGISTERING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CPS_REGISTERING);
}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_REGISTERED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CPS_REGISTERED);
}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_FAILED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CPS_FAILED);
}

#if defined(OC_TCP)
Napi::FunctionReference tcpCsmState::constructor;

Napi::Function tcpCsmState::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "tcpCsmState", {
        StaticAccessor("CSM_NONE", tcpCsmState::get_CSM_NONE, nullptr),
        StaticAccessor("CSM_SENT", tcpCsmState::get_CSM_SENT, nullptr),
        StaticAccessor("CSM_DONE", tcpCsmState::get_CSM_DONE, nullptr),
        StaticAccessor("CSM_ERROR", tcpCsmState::get_CSM_ERROR, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

tcpCsmState::~tcpCsmState()
{
}
tcpCsmState::tcpCsmState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<tcp_csm_state_t>(new tcp_csm_state_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<tcp_csm_state_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value tcpCsmState::get_CSM_NONE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CSM_NONE);
}

Napi::Value tcpCsmState::get_CSM_SENT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CSM_SENT);
}

Napi::Value tcpCsmState::get_CSM_DONE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CSM_DONE);
}

Napi::Value tcpCsmState::get_CSM_ERROR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), CSM_ERROR);
}
#endif

Napi::FunctionReference OCCredType::constructor;

Napi::Function OCCredType::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCredType", {
        StaticAccessor("OC_CREDTYPE_NULL", OCCredType::get_OC_CREDTYPE_NULL, nullptr),
        StaticAccessor("OC_CREDTYPE_PSK", OCCredType::get_OC_CREDTYPE_PSK, nullptr),
        StaticAccessor("OC_CREDTYPE_CERT", OCCredType::get_OC_CREDTYPE_CERT, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCredType::~OCCredType()
{
}
OCCredType::OCCredType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_credtype_t>(new oc_sec_credtype_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_credtype_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCredType::get_OC_CREDTYPE_NULL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDTYPE_NULL);
}

Napi::Value OCCredType::get_OC_CREDTYPE_PSK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDTYPE_PSK);
}

Napi::Value OCCredType::get_OC_CREDTYPE_CERT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDTYPE_CERT);
}

Napi::FunctionReference OCCredUsage::constructor;

Napi::Function OCCredUsage::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCredUsage", {
        StaticAccessor("OC_CREDUSAGE_NULL", OCCredUsage::get_OC_CREDUSAGE_NULL, nullptr),
        StaticAccessor("OC_CREDUSAGE_TRUSTCA", OCCredUsage::get_OC_CREDUSAGE_TRUSTCA, nullptr),
        StaticAccessor("OC_CREDUSAGE_IDENTITY_CERT", OCCredUsage::get_OC_CREDUSAGE_IDENTITY_CERT, nullptr),
        StaticAccessor("OC_CREDUSAGE_ROLE_CERT", OCCredUsage::get_OC_CREDUSAGE_ROLE_CERT, nullptr),
        StaticAccessor("OC_CREDUSAGE_MFG_TRUSTCA", OCCredUsage::get_OC_CREDUSAGE_MFG_TRUSTCA, nullptr),
        StaticAccessor("OC_CREDUSAGE_MFG_CERT", OCCredUsage::get_OC_CREDUSAGE_MFG_CERT, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCredUsage::~OCCredUsage()
{
}
OCCredUsage::OCCredUsage(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_credusage_t>(new oc_sec_credusage_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_credusage_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCredUsage::get_OC_CREDUSAGE_NULL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDUSAGE_NULL);
}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDUSAGE_TRUSTCA);
}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDUSAGE_IDENTITY_CERT);
}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDUSAGE_ROLE_CERT);
}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDUSAGE_MFG_TRUSTCA);
}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_CREDUSAGE_MFG_CERT);
}

Napi::FunctionReference OCEncoding::constructor;

Napi::Function OCEncoding::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEncoding", {
        StaticAccessor("OC_ENCODING_UNSUPPORTED", OCEncoding::get_OC_ENCODING_UNSUPPORTED, nullptr),
        StaticAccessor("OC_ENCODING_BASE64", OCEncoding::get_OC_ENCODING_BASE64, nullptr),
        StaticAccessor("OC_ENCODING_RAW", OCEncoding::get_OC_ENCODING_RAW, nullptr),
        StaticAccessor("OC_ENCODING_PEM", OCEncoding::get_OC_ENCODING_PEM, nullptr),
        StaticAccessor("OC_ENCODING_HANDLE", OCEncoding::get_OC_ENCODING_HANDLE, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEncoding::~OCEncoding()
{
}
OCEncoding::OCEncoding(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sec_encoding_t>(new oc_sec_encoding_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sec_encoding_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCEncoding::get_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENCODING_UNSUPPORTED);
}

Napi::Value OCEncoding::get_OC_ENCODING_BASE64(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENCODING_BASE64);
}

Napi::Value OCEncoding::get_OC_ENCODING_RAW(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENCODING_RAW);
}

Napi::Value OCEncoding::get_OC_ENCODING_PEM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENCODING_PEM);
}

Napi::Value OCEncoding::get_OC_ENCODING_HANDLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENCODING_HANDLE);
}

Napi::FunctionReference OCFVersion::constructor;

Napi::Function OCFVersion::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCFVersion", {
        StaticAccessor("OCF_VER_1_0_0", OCFVersion::get_OCF_VER_1_0_0, nullptr),
        StaticAccessor("OIC_VER_1_1_0", OCFVersion::get_OIC_VER_1_1_0, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCFVersion::~OCFVersion()
{
}
OCFVersion::OCFVersion(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<ocf_version_t>(new ocf_version_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<ocf_version_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCFVersion::get_OCF_VER_1_0_0(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_VER_1_0_0);
}

Napi::Value OCFVersion::get_OIC_VER_1_1_0(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OIC_VER_1_1_0);
}

Napi::FunctionReference OCTransportFlags::constructor;

Napi::Function OCTransportFlags::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCTransportFlags", {
        StaticAccessor("DISCOVERY", OCTransportFlags::get_DISCOVERY, nullptr),
        StaticAccessor("SECURED", OCTransportFlags::get_SECURED, nullptr),
        StaticAccessor("IPV4", OCTransportFlags::get_IPV4, nullptr),
        StaticAccessor("IPV6", OCTransportFlags::get_IPV6, nullptr),
        StaticAccessor("TCP", OCTransportFlags::get_TCP, nullptr),
        StaticAccessor("GATT", OCTransportFlags::get_GATT, nullptr),
        StaticAccessor("MULTICAST", OCTransportFlags::get_MULTICAST, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCTransportFlags::~OCTransportFlags()
{
}
OCTransportFlags::OCTransportFlags(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<transport_flags>(new transport_flags());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<transport_flags>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCTransportFlags::get_DISCOVERY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), DISCOVERY);
}

Napi::Value OCTransportFlags::get_SECURED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), SECURED);
}

Napi::Value OCTransportFlags::get_IPV4(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), IPV4);
}

Napi::Value OCTransportFlags::get_IPV6(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), IPV6);
}

Napi::Value OCTransportFlags::get_TCP(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), TCP);
}

Napi::Value OCTransportFlags::get_GATT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), GATT);
}

Napi::Value OCTransportFlags::get_MULTICAST(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), MULTICAST);
}

Napi::FunctionReference OCEnum::constructor;

Napi::Function OCEnum::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEnum", {
        StaticAccessor("OC_ENUM_ABORTED", OCEnum::get_OC_ENUM_ABORTED, nullptr),
        StaticAccessor("OC_ENUM_ACTIVE", OCEnum::get_OC_ENUM_ACTIVE, nullptr),
        StaticAccessor("OC_ENUM_AIRDRY", OCEnum::get_OC_ENUM_AIRDRY, nullptr),
        StaticAccessor("OC_ENUM_ARMEDAWAY", OCEnum::get_OC_ENUM_ARMEDAWAY, nullptr),
        StaticAccessor("OC_ENUM_ARMEDINSTANT", OCEnum::get_OC_ENUM_ARMEDINSTANT, nullptr),
        StaticAccessor("OC_ENUM_ARMEDMAXIMUM", OCEnum::get_OC_ENUM_ARMEDMAXIMUM, nullptr),
        StaticAccessor("OC_ENUM_ARMEDNIGHTSTAY", OCEnum::get_OC_ENUM_ARMEDNIGHTSTAY, nullptr),
        StaticAccessor("OC_ENUM_ARMEDSTAY", OCEnum::get_OC_ENUM_ARMEDSTAY, nullptr),
        StaticAccessor("OC_ENUM_AROMA", OCEnum::get_OC_ENUM_AROMA, nullptr),
        StaticAccessor("OC_ENUM_AI", OCEnum::get_OC_ENUM_AI, nullptr),
        StaticAccessor("OC_ENUM_AUTO", OCEnum::get_OC_ENUM_AUTO, nullptr),
        StaticAccessor("OC_ENUM_BOILING", OCEnum::get_OC_ENUM_BOILING, nullptr),
        StaticAccessor("OC_ENUM_BREWING", OCEnum::get_OC_ENUM_BREWING, nullptr),
        StaticAccessor("OC_ENUM_CANCELLED", OCEnum::get_OC_ENUM_CANCELLED, nullptr),
        StaticAccessor("OC_ENUM_CIRCULATING", OCEnum::get_OC_ENUM_CIRCULATING, nullptr),
        StaticAccessor("OC_ENUM_CLEANING", OCEnum::get_OC_ENUM_CLEANING, nullptr),
        StaticAccessor("OC_ENUM_CLOTHES", OCEnum::get_OC_ENUM_CLOTHES, nullptr),
        StaticAccessor("OC_ENUM_COMPLETED", OCEnum::get_OC_ENUM_COMPLETED, nullptr),
        StaticAccessor("OC_ENUM_COOL", OCEnum::get_OC_ENUM_COOL, nullptr),
        StaticAccessor("OC_ENUM_DELICATE", OCEnum::get_OC_ENUM_DELICATE, nullptr),
        StaticAccessor("OC_ENUM_DISABLED", OCEnum::get_OC_ENUM_DISABLED, nullptr),
        StaticAccessor("OC_ENUM_DOWN", OCEnum::get_OC_ENUM_DOWN, nullptr),
        StaticAccessor("OC_ENUM_DUAL", OCEnum::get_OC_ENUM_DUAL, nullptr),
        StaticAccessor("OC_ENUM_DRY", OCEnum::get_OC_ENUM_DRY, nullptr),
        StaticAccessor("OC_ENUM_ENABLED", OCEnum::get_OC_ENUM_ENABLED, nullptr),
        StaticAccessor("OC_ENUM_EXTENDED", OCEnum::get_OC_ENUM_EXTENDED, nullptr),
        StaticAccessor("OC_ENUM_FAN", OCEnum::get_OC_ENUM_FAN, nullptr),
        StaticAccessor("OC_ENUM_FAST", OCEnum::get_OC_ENUM_FAST, nullptr),
        StaticAccessor("OC_ENUM_FILTERMATERIAL", OCEnum::get_OC_ENUM_FILTERMATERIAL, nullptr),
        StaticAccessor("OC_ENUM_FOCUSED", OCEnum::get_OC_ENUM_FOCUSED, nullptr),
        StaticAccessor("OC_ENUM_GRINDING", OCEnum::get_OC_ENUM_GRINDING, nullptr),
        StaticAccessor("OC_ENUM_HEATING", OCEnum::get_OC_ENUM_HEATING, nullptr),
        StaticAccessor("OC_ENUM_HEAVY", OCEnum::get_OC_ENUM_HEAVY, nullptr),
        StaticAccessor("OC_ENUM_IDLE", OCEnum::get_OC_ENUM_IDLE, nullptr),
        StaticAccessor("OC_ENUM_INK", OCEnum::get_OC_ENUM_INK, nullptr),
        StaticAccessor("OC_ENUM_INKBLACK", OCEnum::get_OC_ENUM_INKBLACK, nullptr),
        StaticAccessor("OC_ENUM_INKCYAN", OCEnum::get_OC_ENUM_INKCYAN, nullptr),
        StaticAccessor("OC_ENUM_INKMAGENTA", OCEnum::get_OC_ENUM_INKMAGENTA, nullptr),
        StaticAccessor("OC_ENUM_INKTRICOLOUR", OCEnum::get_OC_ENUM_INKTRICOLOUR, nullptr),
        StaticAccessor("OC_ENUM_INKYELLOW", OCEnum::get_OC_ENUM_INKYELLOW, nullptr),
        StaticAccessor("OC_ENUM_KEEPWARM", OCEnum::get_OC_ENUM_KEEPWARM, nullptr),
        StaticAccessor("OC_ENUM_NORMAL", OCEnum::get_OC_ENUM_NORMAL, nullptr),
        StaticAccessor("OC_ENUM_NOTSUPPORTED", OCEnum::get_OC_ENUM_NOTSUPPORTED, nullptr),
        StaticAccessor("OC_ENUM_PAUSE", OCEnum::get_OC_ENUM_PAUSE, nullptr),
        StaticAccessor("OC_ENUM_PENDING", OCEnum::get_OC_ENUM_PENDING, nullptr),
        StaticAccessor("OC_ENUM_PENDINGHELD", OCEnum::get_OC_ENUM_PENDINGHELD, nullptr),
        StaticAccessor("OC_ENUM_PERMAPRESS", OCEnum::get_OC_ENUM_PERMAPRESS, nullptr),
        StaticAccessor("OC_ENUM_PREWASH", OCEnum::get_OC_ENUM_PREWASH, nullptr),
        StaticAccessor("OC_ENUM_PROCESSING", OCEnum::get_OC_ENUM_PROCESSING, nullptr),
        StaticAccessor("OC_ENUM_PURE", OCEnum::get_OC_ENUM_PURE, nullptr),
        StaticAccessor("OC_ENUM_QUICK", OCEnum::get_OC_ENUM_QUICK, nullptr),
        StaticAccessor("OC_ENUM_QUIET", OCEnum::get_OC_ENUM_QUIET, nullptr),
        StaticAccessor("OC_ENUM_RINSE", OCEnum::get_OC_ENUM_RINSE, nullptr),
        StaticAccessor("OC_ENUM_SECTORED", OCEnum::get_OC_ENUM_SECTORED, nullptr),
        StaticAccessor("OC_ENUM_SILENT", OCEnum::get_OC_ENUM_SILENT, nullptr),
        StaticAccessor("OC_ENUM_SLEEP", OCEnum::get_OC_ENUM_SLEEP, nullptr),
        StaticAccessor("OC_ENUM_SMART", OCEnum::get_OC_ENUM_SMART, nullptr),
        StaticAccessor("OC_ENUM_SPOT", OCEnum::get_OC_ENUM_SPOT, nullptr),
        StaticAccessor("OC_ENUM_STEAM", OCEnum::get_OC_ENUM_STEAM, nullptr),
        StaticAccessor("OC_ENUM_STOPPED", OCEnum::get_OC_ENUM_STOPPED, nullptr),
        StaticAccessor("OC_ENUM_SPIN", OCEnum::get_OC_ENUM_SPIN, nullptr),
        StaticAccessor("OC_ENUM_TESTING", OCEnum::get_OC_ENUM_TESTING, nullptr),
        StaticAccessor("OC_ENUM_TONER", OCEnum::get_OC_ENUM_TONER, nullptr),
        StaticAccessor("OC_ENUM_TONERBLACK", OCEnum::get_OC_ENUM_TONERBLACK, nullptr),
        StaticAccessor("OC_ENUM_TONERCYAN", OCEnum::get_OC_ENUM_TONERCYAN, nullptr),
        StaticAccessor("OC_ENUM_TONERMAGENTA", OCEnum::get_OC_ENUM_TONERMAGENTA, nullptr),
        StaticAccessor("OC_ENUM_TONERYELLOW", OCEnum::get_OC_ENUM_TONERYELLOW, nullptr),
        StaticAccessor("OC_ENUM_WARM", OCEnum::get_OC_ENUM_WARM, nullptr),
        StaticAccessor("OC_ENUM_WASH", OCEnum::get_OC_ENUM_WASH, nullptr),
        StaticAccessor("OC_ENUM_WET", OCEnum::get_OC_ENUM_WET, nullptr),
        StaticAccessor("OC_ENUM_WIND", OCEnum::get_OC_ENUM_WIND, nullptr),
        StaticAccessor("OC_ENUM_WRINKLEPREVENT", OCEnum::get_OC_ENUM_WRINKLEPREVENT, nullptr),
        StaticAccessor("OC_ENUM_ZIGZAG", OCEnum::get_OC_ENUM_ZIGZAG, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEnum::~OCEnum()
{
}
OCEnum::OCEnum(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_enum_t>(new oc_enum_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_enum_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCEnum::get_OC_ENUM_ABORTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ABORTED);
}

Napi::Value OCEnum::get_OC_ENUM_ACTIVE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ACTIVE);
}

Napi::Value OCEnum::get_OC_ENUM_AIRDRY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_AIRDRY);
}

Napi::Value OCEnum::get_OC_ENUM_ARMEDAWAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ARMEDAWAY);
}

Napi::Value OCEnum::get_OC_ENUM_ARMEDINSTANT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ARMEDINSTANT);
}

Napi::Value OCEnum::get_OC_ENUM_ARMEDMAXIMUM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ARMEDMAXIMUM);
}

Napi::Value OCEnum::get_OC_ENUM_ARMEDNIGHTSTAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ARMEDNIGHTSTAY);
}

Napi::Value OCEnum::get_OC_ENUM_ARMEDSTAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ARMEDSTAY);
}

Napi::Value OCEnum::get_OC_ENUM_AROMA(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_AROMA);
}

Napi::Value OCEnum::get_OC_ENUM_AI(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_AI);
}

Napi::Value OCEnum::get_OC_ENUM_AUTO(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_AUTO);
}

Napi::Value OCEnum::get_OC_ENUM_BOILING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_BOILING);
}

Napi::Value OCEnum::get_OC_ENUM_BREWING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_BREWING);
}

Napi::Value OCEnum::get_OC_ENUM_CANCELLED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_CANCELLED);
}

Napi::Value OCEnum::get_OC_ENUM_CIRCULATING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_CIRCULATING);
}

Napi::Value OCEnum::get_OC_ENUM_CLEANING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_CLEANING);
}

Napi::Value OCEnum::get_OC_ENUM_CLOTHES(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_CLOTHES);
}

Napi::Value OCEnum::get_OC_ENUM_COMPLETED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_COMPLETED);
}

Napi::Value OCEnum::get_OC_ENUM_COOL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_COOL);
}

Napi::Value OCEnum::get_OC_ENUM_DELICATE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_DELICATE);
}

Napi::Value OCEnum::get_OC_ENUM_DISABLED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_DISABLED);
}

Napi::Value OCEnum::get_OC_ENUM_DOWN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_DOWN);
}

Napi::Value OCEnum::get_OC_ENUM_DUAL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_DUAL);
}

Napi::Value OCEnum::get_OC_ENUM_DRY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_DRY);
}

Napi::Value OCEnum::get_OC_ENUM_ENABLED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ENABLED);
}

Napi::Value OCEnum::get_OC_ENUM_EXTENDED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_EXTENDED);
}

Napi::Value OCEnum::get_OC_ENUM_FAN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_FAN);
}

Napi::Value OCEnum::get_OC_ENUM_FAST(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_FAST);
}

Napi::Value OCEnum::get_OC_ENUM_FILTERMATERIAL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_FILTERMATERIAL);
}

Napi::Value OCEnum::get_OC_ENUM_FOCUSED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_FOCUSED);
}

Napi::Value OCEnum::get_OC_ENUM_GRINDING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_GRINDING);
}

Napi::Value OCEnum::get_OC_ENUM_HEATING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_HEATING);
}

Napi::Value OCEnum::get_OC_ENUM_HEAVY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_HEAVY);
}

Napi::Value OCEnum::get_OC_ENUM_IDLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_IDLE);
}

Napi::Value OCEnum::get_OC_ENUM_INK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_INK);
}

Napi::Value OCEnum::get_OC_ENUM_INKBLACK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_INKBLACK);
}

Napi::Value OCEnum::get_OC_ENUM_INKCYAN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_INKCYAN);
}

Napi::Value OCEnum::get_OC_ENUM_INKMAGENTA(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_INKMAGENTA);
}

Napi::Value OCEnum::get_OC_ENUM_INKTRICOLOUR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_INKTRICOLOUR);
}

Napi::Value OCEnum::get_OC_ENUM_INKYELLOW(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_INKYELLOW);
}

Napi::Value OCEnum::get_OC_ENUM_KEEPWARM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_KEEPWARM);
}

Napi::Value OCEnum::get_OC_ENUM_NORMAL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_NORMAL);
}

Napi::Value OCEnum::get_OC_ENUM_NOTSUPPORTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_NOTSUPPORTED);
}

Napi::Value OCEnum::get_OC_ENUM_PAUSE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PAUSE);
}

Napi::Value OCEnum::get_OC_ENUM_PENDING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PENDING);
}

Napi::Value OCEnum::get_OC_ENUM_PENDINGHELD(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PENDINGHELD);
}

Napi::Value OCEnum::get_OC_ENUM_PERMAPRESS(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PERMAPRESS);
}

Napi::Value OCEnum::get_OC_ENUM_PREWASH(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PREWASH);
}

Napi::Value OCEnum::get_OC_ENUM_PROCESSING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PROCESSING);
}

Napi::Value OCEnum::get_OC_ENUM_PURE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_PURE);
}

Napi::Value OCEnum::get_OC_ENUM_QUICK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_QUICK);
}

Napi::Value OCEnum::get_OC_ENUM_QUIET(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_QUIET);
}

Napi::Value OCEnum::get_OC_ENUM_RINSE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_RINSE);
}

Napi::Value OCEnum::get_OC_ENUM_SECTORED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_SECTORED);
}

Napi::Value OCEnum::get_OC_ENUM_SILENT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_SILENT);
}

Napi::Value OCEnum::get_OC_ENUM_SLEEP(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_SLEEP);
}

Napi::Value OCEnum::get_OC_ENUM_SMART(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_SMART);
}

Napi::Value OCEnum::get_OC_ENUM_SPOT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_SPOT);
}

Napi::Value OCEnum::get_OC_ENUM_STEAM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_STEAM);
}

Napi::Value OCEnum::get_OC_ENUM_STOPPED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_STOPPED);
}

Napi::Value OCEnum::get_OC_ENUM_SPIN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_SPIN);
}

Napi::Value OCEnum::get_OC_ENUM_TESTING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_TESTING);
}

Napi::Value OCEnum::get_OC_ENUM_TONER(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_TONER);
}

Napi::Value OCEnum::get_OC_ENUM_TONERBLACK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_TONERBLACK);
}

Napi::Value OCEnum::get_OC_ENUM_TONERCYAN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_TONERCYAN);
}

Napi::Value OCEnum::get_OC_ENUM_TONERMAGENTA(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_TONERMAGENTA);
}

Napi::Value OCEnum::get_OC_ENUM_TONERYELLOW(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_TONERYELLOW);
}

Napi::Value OCEnum::get_OC_ENUM_WARM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_WARM);
}

Napi::Value OCEnum::get_OC_ENUM_WASH(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_WASH);
}

Napi::Value OCEnum::get_OC_ENUM_WET(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_WET);
}

Napi::Value OCEnum::get_OC_ENUM_WIND(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_WIND);
}

Napi::Value OCEnum::get_OC_ENUM_WRINKLEPREVENT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_WRINKLEPREVENT);
}

Napi::Value OCEnum::get_OC_ENUM_ZIGZAG(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_ENUM_ZIGZAG);
}

Napi::FunctionReference OCPositionDescription::constructor;

Napi::Function OCPositionDescription::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCPositionDescription", {
        StaticAccessor("OC_POS_UNKNOWN", OCPositionDescription::get_OC_POS_UNKNOWN, nullptr),
        StaticAccessor("OC_POS_TOP", OCPositionDescription::get_OC_POS_TOP, nullptr),
        StaticAccessor("OC_POS_BOTTOM", OCPositionDescription::get_OC_POS_BOTTOM, nullptr),
        StaticAccessor("OC_POS_LEFT", OCPositionDescription::get_OC_POS_LEFT, nullptr),
        StaticAccessor("OC_POS_RIGHT", OCPositionDescription::get_OC_POS_RIGHT, nullptr),
        StaticAccessor("OC_POS_CENTRE", OCPositionDescription::get_OC_POS_CENTRE, nullptr),
        StaticAccessor("OC_POS_TOPLEFT", OCPositionDescription::get_OC_POS_TOPLEFT, nullptr),
        StaticAccessor("OC_POS_BOTTOMLEFT", OCPositionDescription::get_OC_POS_BOTTOMLEFT, nullptr),
        StaticAccessor("OC_POS_CENTRELEFT", OCPositionDescription::get_OC_POS_CENTRELEFT, nullptr),
        StaticAccessor("OC_POS_CENTRERIGHT", OCPositionDescription::get_OC_POS_CENTRERIGHT, nullptr),
        StaticAccessor("OC_POS_BOTTOMRIGHT", OCPositionDescription::get_OC_POS_BOTTOMRIGHT, nullptr),
        StaticAccessor("OC_POS_TOPRIGHT", OCPositionDescription::get_OC_POS_TOPRIGHT, nullptr),
        StaticAccessor("OC_POS_TOPCENTRE", OCPositionDescription::get_OC_POS_TOPCENTRE, nullptr),
        StaticAccessor("OC_POS_BOTTOMCENTRE", OCPositionDescription::get_OC_POS_BOTTOMCENTRE, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCPositionDescription::~OCPositionDescription()
{
}
OCPositionDescription::OCPositionDescription(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_pos_description_t>(new oc_pos_description_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_pos_description_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCPositionDescription::get_OC_POS_UNKNOWN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_UNKNOWN);
}

Napi::Value OCPositionDescription::get_OC_POS_TOP(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_TOP);
}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_BOTTOM);
}

Napi::Value OCPositionDescription::get_OC_POS_LEFT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_LEFT);
}

Napi::Value OCPositionDescription::get_OC_POS_RIGHT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_RIGHT);
}

Napi::Value OCPositionDescription::get_OC_POS_CENTRE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_CENTRE);
}

Napi::Value OCPositionDescription::get_OC_POS_TOPLEFT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_TOPLEFT);
}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_BOTTOMLEFT);
}

Napi::Value OCPositionDescription::get_OC_POS_CENTRELEFT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_CENTRELEFT);
}

Napi::Value OCPositionDescription::get_OC_POS_CENTRERIGHT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_CENTRERIGHT);
}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_BOTTOMRIGHT);
}

Napi::Value OCPositionDescription::get_OC_POS_TOPRIGHT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_TOPRIGHT);
}

Napi::Value OCPositionDescription::get_OC_POS_TOPCENTRE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_TOPCENTRE);
}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POS_BOTTOMCENTRE);
}


Napi::FunctionReference OCInterfaceEvent::constructor;

Napi::Function OCInterfaceEvent::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCInterfaceEvent", {
        StaticAccessor("NETWORK_INTERFACE_DOWN", OCInterfaceEvent::get_NETWORK_INTERFACE_DOWN, nullptr),
        StaticAccessor("NETWORK_INTERFACE_UP", OCInterfaceEvent::get_NETWORK_INTERFACE_UP, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCInterfaceEvent::~OCInterfaceEvent()
{
}
OCInterfaceEvent::OCInterfaceEvent(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_interface_event_t>(new oc_interface_event_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_interface_event_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCInterfaceEvent::get_NETWORK_INTERFACE_DOWN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), NETWORK_INTERFACE_DOWN);
}

Napi::Value OCInterfaceEvent::get_NETWORK_INTERFACE_UP(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), NETWORK_INTERFACE_UP);
}

Napi::FunctionReference OCSpTypesMask::constructor;

Napi::Function OCSpTypesMask::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSpTypesMask", {
        StaticAccessor("OC_SP_BASELINE", OCSpTypesMask::get_OC_SP_BASELINE, nullptr),
        StaticAccessor("OC_SP_BLACK", OCSpTypesMask::get_OC_SP_BLACK, nullptr),
        StaticAccessor("OC_SP_BLUE", OCSpTypesMask::get_OC_SP_BLUE, nullptr),
        StaticAccessor("OC_SP_PURPLE", OCSpTypesMask::get_OC_SP_PURPLE, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSpTypesMask::~OCSpTypesMask()
{
}
OCSpTypesMask::OCSpTypesMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_sp_types_t>(new oc_sp_types_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_sp_types_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSpTypesMask::get_OC_SP_BASELINE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SP_BASELINE);
}

Napi::Value OCSpTypesMask::get_OC_SP_BLACK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SP_BLACK);
}

Napi::Value OCSpTypesMask::get_OC_SP_BLUE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SP_BLUE);
}

Napi::Value OCSpTypesMask::get_OC_SP_PURPLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SP_PURPLE);
}

Napi::FunctionReference OCRepValueType::constructor;

Napi::Function OCRepValueType::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCRepValueType", {
        StaticAccessor("OC_REP_NIL", OCRepValueType::get_OC_REP_NIL, nullptr),
        StaticAccessor("OC_REP_INT", OCRepValueType::get_OC_REP_INT, nullptr),
        StaticAccessor("OC_REP_DOUBLE", OCRepValueType::get_OC_REP_DOUBLE, nullptr),
        StaticAccessor("OC_REP_BOOL", OCRepValueType::get_OC_REP_BOOL, nullptr),
        StaticAccessor("OC_REP_BYTE_STRING", OCRepValueType::get_OC_REP_BYTE_STRING, nullptr),
        StaticAccessor("OC_REP_STRING", OCRepValueType::get_OC_REP_STRING, nullptr),
        StaticAccessor("OC_REP_OBJECT", OCRepValueType::get_OC_REP_OBJECT, nullptr),
        StaticAccessor("OC_REP_ARRAY", OCRepValueType::get_OC_REP_ARRAY, nullptr),
        StaticAccessor("OC_REP_INT_ARRAY", OCRepValueType::get_OC_REP_INT_ARRAY, nullptr),
        StaticAccessor("OC_REP_DOUBLE_ARRAY", OCRepValueType::get_OC_REP_DOUBLE_ARRAY, nullptr),
        StaticAccessor("OC_REP_BOOL_ARRAY", OCRepValueType::get_OC_REP_BOOL_ARRAY, nullptr),
        StaticAccessor("OC_REP_BYTE_STRING_ARRAY", OCRepValueType::get_OC_REP_BYTE_STRING_ARRAY, nullptr),
        StaticAccessor("OC_REP_STRING_ARRAY", OCRepValueType::get_OC_REP_STRING_ARRAY, nullptr),
        StaticAccessor("OC_REP_OBJECT_ARRAY", OCRepValueType::get_OC_REP_OBJECT_ARRAY, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCRepValueType::~OCRepValueType()
{
}
OCRepValueType::OCRepValueType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_rep_value_type_t>(new oc_rep_value_type_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_rep_value_type_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCRepValueType::get_OC_REP_NIL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_NIL);
}

Napi::Value OCRepValueType::get_OC_REP_INT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_INT);
}

Napi::Value OCRepValueType::get_OC_REP_DOUBLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_DOUBLE);
}

Napi::Value OCRepValueType::get_OC_REP_BOOL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_BOOL);
}

Napi::Value OCRepValueType::get_OC_REP_BYTE_STRING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_BYTE_STRING);
}

Napi::Value OCRepValueType::get_OC_REP_STRING(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_STRING);
}

Napi::Value OCRepValueType::get_OC_REP_OBJECT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_OBJECT);
}

Napi::Value OCRepValueType::get_OC_REP_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_ARRAY);
}

Napi::Value OCRepValueType::get_OC_REP_INT_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_INT_ARRAY);
}

Napi::Value OCRepValueType::get_OC_REP_DOUBLE_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_DOUBLE_ARRAY);
}

Napi::Value OCRepValueType::get_OC_REP_BOOL_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_BOOL_ARRAY);
}

Napi::Value OCRepValueType::get_OC_REP_BYTE_STRING_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_BYTE_STRING_ARRAY);
}

Napi::Value OCRepValueType::get_OC_REP_STRING_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_STRING_ARRAY);
}

Napi::Value OCRepValueType::get_OC_REP_OBJECT_ARRAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_REP_OBJECT_ARRAY);
}

Napi::FunctionReference OCContentFormat::constructor;

Napi::Function OCContentFormat::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCContentFormat", {
        StaticAccessor("TEXT_PLAIN", OCContentFormat::get_TEXT_PLAIN, nullptr),
        StaticAccessor("TEXT_XML", OCContentFormat::get_TEXT_XML, nullptr),
        StaticAccessor("TEXT_CSV", OCContentFormat::get_TEXT_CSV, nullptr),
        StaticAccessor("TEXT_HTML", OCContentFormat::get_TEXT_HTML, nullptr),
        StaticAccessor("IMAGE_GIF", OCContentFormat::get_IMAGE_GIF, nullptr),
        StaticAccessor("IMAGE_JPEG", OCContentFormat::get_IMAGE_JPEG, nullptr),
        StaticAccessor("IMAGE_PNG", OCContentFormat::get_IMAGE_PNG, nullptr),
        StaticAccessor("IMAGE_TIFF", OCContentFormat::get_IMAGE_TIFF, nullptr),
        StaticAccessor("AUDIO_RAW", OCContentFormat::get_AUDIO_RAW, nullptr),
        StaticAccessor("VIDEO_RAW", OCContentFormat::get_VIDEO_RAW, nullptr),
        StaticAccessor("APPLICATION_LINK_FORMAT", OCContentFormat::get_APPLICATION_LINK_FORMAT, nullptr),
        StaticAccessor("APPLICATION_XML", OCContentFormat::get_APPLICATION_XML, nullptr),
        StaticAccessor("APPLICATION_OCTET_STREAM", OCContentFormat::get_APPLICATION_OCTET_STREAM, nullptr),
        StaticAccessor("APPLICATION_RDF_XML", OCContentFormat::get_APPLICATION_RDF_XML, nullptr),
        StaticAccessor("APPLICATION_SOAP_XML", OCContentFormat::get_APPLICATION_SOAP_XML, nullptr),
        StaticAccessor("APPLICATION_ATOM_XML", OCContentFormat::get_APPLICATION_ATOM_XML, nullptr),
        StaticAccessor("APPLICATION_XMPP_XML", OCContentFormat::get_APPLICATION_XMPP_XML, nullptr),
        StaticAccessor("APPLICATION_EXI", OCContentFormat::get_APPLICATION_EXI, nullptr),
        StaticAccessor("APPLICATION_FASTINFOSET", OCContentFormat::get_APPLICATION_FASTINFOSET, nullptr),
        StaticAccessor("APPLICATION_SOAP_FASTINFOSET", OCContentFormat::get_APPLICATION_SOAP_FASTINFOSET, nullptr),
        StaticAccessor("APPLICATION_JSON", OCContentFormat::get_APPLICATION_JSON, nullptr),
        StaticAccessor("APPLICATION_X_OBIX_BINARY", OCContentFormat::get_APPLICATION_X_OBIX_BINARY, nullptr),
        StaticAccessor("APPLICATION_CBOR", OCContentFormat::get_APPLICATION_CBOR, nullptr),
        StaticAccessor("APPLICATION_VND_OCF_CBOR", OCContentFormat::get_APPLICATION_VND_OCF_CBOR, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCContentFormat::~OCContentFormat()
{
}
OCContentFormat::OCContentFormat(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_content_format_t>(new oc_content_format_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_content_format_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCContentFormat::get_TEXT_PLAIN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), TEXT_PLAIN);
}

Napi::Value OCContentFormat::get_TEXT_XML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), TEXT_XML);
}

Napi::Value OCContentFormat::get_TEXT_CSV(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), TEXT_CSV);
}

Napi::Value OCContentFormat::get_TEXT_HTML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), TEXT_HTML);
}

Napi::Value OCContentFormat::get_IMAGE_GIF(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), IMAGE_GIF);
}

Napi::Value OCContentFormat::get_IMAGE_JPEG(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), IMAGE_JPEG);
}

Napi::Value OCContentFormat::get_IMAGE_PNG(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), IMAGE_PNG);
}

Napi::Value OCContentFormat::get_IMAGE_TIFF(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), IMAGE_TIFF);
}

Napi::Value OCContentFormat::get_AUDIO_RAW(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), AUDIO_RAW);
}

Napi::Value OCContentFormat::get_VIDEO_RAW(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), VIDEO_RAW);
}

Napi::Value OCContentFormat::get_APPLICATION_LINK_FORMAT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_LINK_FORMAT);
}

Napi::Value OCContentFormat::get_APPLICATION_XML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_XML);
}

Napi::Value OCContentFormat::get_APPLICATION_OCTET_STREAM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_OCTET_STREAM);
}

Napi::Value OCContentFormat::get_APPLICATION_RDF_XML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_RDF_XML);
}

Napi::Value OCContentFormat::get_APPLICATION_SOAP_XML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_SOAP_XML);
}

Napi::Value OCContentFormat::get_APPLICATION_ATOM_XML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_ATOM_XML);
}

Napi::Value OCContentFormat::get_APPLICATION_XMPP_XML(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_XMPP_XML);
}

Napi::Value OCContentFormat::get_APPLICATION_EXI(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_EXI);
}

Napi::Value OCContentFormat::get_APPLICATION_FASTINFOSET(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_FASTINFOSET);
}

Napi::Value OCContentFormat::get_APPLICATION_SOAP_FASTINFOSET(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_SOAP_FASTINFOSET);
}

Napi::Value OCContentFormat::get_APPLICATION_JSON(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_JSON);
}

Napi::Value OCContentFormat::get_APPLICATION_X_OBIX_BINARY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_X_OBIX_BINARY);
}

Napi::Value OCContentFormat::get_APPLICATION_CBOR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_CBOR);
}

Napi::Value OCContentFormat::get_APPLICATION_VND_OCF_CBOR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), APPLICATION_VND_OCF_CBOR);
}

Napi::FunctionReference OCCoreResource::constructor;

Napi::Function OCCoreResource::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCCoreResource", {
        StaticAccessor("OCF_P", OCCoreResource::get_OCF_P, nullptr),
        StaticAccessor("OCF_CON", OCCoreResource::get_OCF_CON, nullptr),
        StaticAccessor("OCF_INTROSPECTION_WK", OCCoreResource::get_OCF_INTROSPECTION_WK, nullptr),
        StaticAccessor("OCF_INTROSPECTION_DATA", OCCoreResource::get_OCF_INTROSPECTION_DATA, nullptr),
        StaticAccessor("OCF_RES", OCCoreResource::get_OCF_RES, nullptr),
#if defined(OC_MNT)
        StaticAccessor("OCF_MNT", OCCoreResource::get_OCF_MNT, nullptr),
#endif
#if defined(OC_CLOUD)
        StaticAccessor("OCF_COAPCLOUDCONF", OCCoreResource::get_OCF_COAPCLOUDCONF, nullptr),
#endif
#if defined(OC_SOFTWARE_UPDATE)
        StaticAccessor("OCF_SW_UPDATE", OCCoreResource::get_OCF_SW_UPDATE, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_DOXM", OCCoreResource::get_OCF_SEC_DOXM, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_PSTAT", OCCoreResource::get_OCF_SEC_PSTAT, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_ACL", OCCoreResource::get_OCF_SEC_ACL, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_AEL", OCCoreResource::get_OCF_SEC_AEL, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_CRED", OCCoreResource::get_OCF_SEC_CRED, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_SDI", OCCoreResource::get_OCF_SEC_SDI, nullptr),
#endif
#if defined(OC_SECURITY)
        StaticAccessor("OCF_SEC_SP", OCCoreResource::get_OCF_SEC_SP, nullptr),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticAccessor("OCF_SEC_CSR", OCCoreResource::get_OCF_SEC_CSR, nullptr),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
        StaticAccessor("OCF_SEC_ROLES", OCCoreResource::get_OCF_SEC_ROLES, nullptr),
#endif
        StaticAccessor("OCF_D", OCCoreResource::get_OCF_D, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCCoreResource::~OCCoreResource()
{
}
OCCoreResource::OCCoreResource(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_core_resource_t>(new oc_core_resource_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_core_resource_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCCoreResource::get_OCF_P(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_P);
}

Napi::Value OCCoreResource::get_OCF_CON(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_CON);
}

Napi::Value OCCoreResource::get_OCF_INTROSPECTION_WK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_INTROSPECTION_WK);
}

Napi::Value OCCoreResource::get_OCF_INTROSPECTION_DATA(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_INTROSPECTION_DATA);
}

Napi::Value OCCoreResource::get_OCF_RES(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_RES);
}

#if defined(OC_MNT)
Napi::Value OCCoreResource::get_OCF_MNT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_MNT);
}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCoreResource::get_OCF_COAPCLOUDCONF(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_COAPCLOUDCONF);
}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCCoreResource::get_OCF_SW_UPDATE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SW_UPDATE);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_DOXM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_DOXM);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_PSTAT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_PSTAT);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_ACL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_ACL);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_AEL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_AEL);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_CRED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_CRED);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_SDI(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_SDI);
}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_SP(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_SP);
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCCoreResource::get_OCF_SEC_CSR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_CSR);
}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCCoreResource::get_OCF_SEC_ROLES(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_SEC_ROLES);
}
#endif

Napi::Value OCCoreResource::get_OCF_D(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OCF_D);
}

Napi::FunctionReference OCEventCallbackResult::constructor;

Napi::Function OCEventCallbackResult::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCEventCallbackResult", {
        StaticAccessor("OC_EVENT_DONE", OCEventCallbackResult::get_OC_EVENT_DONE, nullptr),
        StaticAccessor("OC_EVENT_CONTINUE", OCEventCallbackResult::get_OC_EVENT_CONTINUE, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCEventCallbackResult::~OCEventCallbackResult()
{
}
OCEventCallbackResult::OCEventCallbackResult(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_event_callback_retval_t>(new oc_event_callback_retval_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_event_callback_retval_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCEventCallbackResult::get_OC_EVENT_DONE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_EVENT_DONE);
}

Napi::Value OCEventCallbackResult::get_OC_EVENT_CONTINUE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_EVENT_CONTINUE);
}

Napi::FunctionReference OCInterfaceMask::constructor;

Napi::Function OCInterfaceMask::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCInterfaceMask", {
        StaticAccessor("OC_IF_BASELINE", OCInterfaceMask::get_OC_IF_BASELINE, nullptr),
        StaticAccessor("OC_IF_LL", OCInterfaceMask::get_OC_IF_LL, nullptr),
        StaticAccessor("OC_IF_B", OCInterfaceMask::get_OC_IF_B, nullptr),
        StaticAccessor("OC_IF_R", OCInterfaceMask::get_OC_IF_R, nullptr),
        StaticAccessor("OC_IF_RW", OCInterfaceMask::get_OC_IF_RW, nullptr),
        StaticAccessor("OC_IF_A", OCInterfaceMask::get_OC_IF_A, nullptr),
        StaticAccessor("OC_IF_S", OCInterfaceMask::get_OC_IF_S, nullptr),
        StaticAccessor("OC_IF_CREATE", OCInterfaceMask::get_OC_IF_CREATE, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCInterfaceMask::~OCInterfaceMask()
{
}
OCInterfaceMask::OCInterfaceMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_interface_mask_t>(new oc_interface_mask_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_interface_mask_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCInterfaceMask::get_OC_IF_BASELINE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_BASELINE);
}

Napi::Value OCInterfaceMask::get_OC_IF_LL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_LL);
}

Napi::Value OCInterfaceMask::get_OC_IF_B(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_B);
}

Napi::Value OCInterfaceMask::get_OC_IF_R(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_R);
}

Napi::Value OCInterfaceMask::get_OC_IF_RW(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_RW);
}

Napi::Value OCInterfaceMask::get_OC_IF_A(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_A);
}

Napi::Value OCInterfaceMask::get_OC_IF_S(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_S);
}

Napi::Value OCInterfaceMask::get_OC_IF_CREATE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IF_CREATE);
}

Napi::FunctionReference OCMethod::constructor;

Napi::Function OCMethod::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCMethod", {
        StaticAccessor("OC_GET", OCMethod::get_OC_GET, nullptr),
        StaticAccessor("OC_POST", OCMethod::get_OC_POST, nullptr),
        StaticAccessor("OC_PUT", OCMethod::get_OC_PUT, nullptr),
        StaticAccessor("OC_DELETE", OCMethod::get_OC_DELETE, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCMethod::~OCMethod()
{
}
OCMethod::OCMethod(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_method_t>(new oc_method_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_method_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCMethod::get_OC_GET(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_GET);
}

Napi::Value OCMethod::get_OC_POST(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_POST);
}

Napi::Value OCMethod::get_OC_PUT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PUT);
}

Napi::Value OCMethod::get_OC_DELETE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_DELETE);
}

Napi::FunctionReference OCResourcePropertiesMask::constructor;

Napi::Function OCResourcePropertiesMask::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCResourcePropertiesMask", {
        StaticAccessor("OC_DISCOVERABLE", OCResourcePropertiesMask::get_OC_DISCOVERABLE, nullptr),
        StaticAccessor("OC_OBSERVABLE", OCResourcePropertiesMask::get_OC_OBSERVABLE, nullptr),
        StaticAccessor("OC_SECURE", OCResourcePropertiesMask::get_OC_SECURE, nullptr),
        StaticAccessor("OC_PERIODIC", OCResourcePropertiesMask::get_OC_PERIODIC, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCResourcePropertiesMask::~OCResourcePropertiesMask()
{
}
OCResourcePropertiesMask::OCResourcePropertiesMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_resource_properties_t>(new oc_resource_properties_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_resource_properties_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCResourcePropertiesMask::get_OC_DISCOVERABLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_DISCOVERABLE);
}

Napi::Value OCResourcePropertiesMask::get_OC_OBSERVABLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_OBSERVABLE);
}

Napi::Value OCResourcePropertiesMask::get_OC_SECURE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SECURE);
}

Napi::Value OCResourcePropertiesMask::get_OC_PERIODIC(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PERIODIC);
}

Napi::FunctionReference OCStatus::constructor;

Napi::Function OCStatus::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCStatus", {
        StaticAccessor("OC_STATUS_OK", OCStatus::get_OC_STATUS_OK, nullptr),
        StaticAccessor("OC_STATUS_CREATED", OCStatus::get_OC_STATUS_CREATED, nullptr),
        StaticAccessor("OC_STATUS_CHANGED", OCStatus::get_OC_STATUS_CHANGED, nullptr),
        StaticAccessor("OC_STATUS_DELETED", OCStatus::get_OC_STATUS_DELETED, nullptr),
        StaticAccessor("OC_STATUS_NOT_MODIFIED", OCStatus::get_OC_STATUS_NOT_MODIFIED, nullptr),
        StaticAccessor("OC_STATUS_BAD_REQUEST", OCStatus::get_OC_STATUS_BAD_REQUEST, nullptr),
        StaticAccessor("OC_STATUS_UNAUTHORIZED", OCStatus::get_OC_STATUS_UNAUTHORIZED, nullptr),
        StaticAccessor("OC_STATUS_BAD_OPTION", OCStatus::get_OC_STATUS_BAD_OPTION, nullptr),
        StaticAccessor("OC_STATUS_FORBIDDEN", OCStatus::get_OC_STATUS_FORBIDDEN, nullptr),
        StaticAccessor("OC_STATUS_NOT_FOUND", OCStatus::get_OC_STATUS_NOT_FOUND, nullptr),
        StaticAccessor("OC_STATUS_METHOD_NOT_ALLOWED", OCStatus::get_OC_STATUS_METHOD_NOT_ALLOWED, nullptr),
        StaticAccessor("OC_STATUS_NOT_ACCEPTABLE", OCStatus::get_OC_STATUS_NOT_ACCEPTABLE, nullptr),
        StaticAccessor("OC_STATUS_REQUEST_ENTITY_TOO_LARGE", OCStatus::get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE, nullptr),
        StaticAccessor("OC_STATUS_UNSUPPORTED_MEDIA_TYPE", OCStatus::get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE, nullptr),
        StaticAccessor("OC_STATUS_INTERNAL_SERVER_ERROR", OCStatus::get_OC_STATUS_INTERNAL_SERVER_ERROR, nullptr),
        StaticAccessor("OC_STATUS_NOT_IMPLEMENTED", OCStatus::get_OC_STATUS_NOT_IMPLEMENTED, nullptr),
        StaticAccessor("OC_STATUS_BAD_GATEWAY", OCStatus::get_OC_STATUS_BAD_GATEWAY, nullptr),
        StaticAccessor("OC_STATUS_SERVICE_UNAVAILABLE", OCStatus::get_OC_STATUS_SERVICE_UNAVAILABLE, nullptr),
        StaticAccessor("OC_STATUS_GATEWAY_TIMEOUT", OCStatus::get_OC_STATUS_GATEWAY_TIMEOUT, nullptr),
        StaticAccessor("OC_STATUS_PROXYING_NOT_SUPPORTED", OCStatus::get_OC_STATUS_PROXYING_NOT_SUPPORTED, nullptr),
        StaticAccessor("__NUM_OC_STATUS_CODES__", OCStatus::get___NUM_OC_STATUS_CODES__, nullptr),
        StaticAccessor("OC_IGNORE", OCStatus::get_OC_IGNORE, nullptr),
        StaticAccessor("OC_PING_TIMEOUT", OCStatus::get_OC_PING_TIMEOUT, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCStatus::~OCStatus()
{
}
OCStatus::OCStatus(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_status_t>(new oc_status_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_status_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCStatus::get_OC_STATUS_OK(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_OK);
}

Napi::Value OCStatus::get_OC_STATUS_CREATED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_CREATED);
}

Napi::Value OCStatus::get_OC_STATUS_CHANGED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_CHANGED);
}

Napi::Value OCStatus::get_OC_STATUS_DELETED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_DELETED);
}

Napi::Value OCStatus::get_OC_STATUS_NOT_MODIFIED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_NOT_MODIFIED);
}

Napi::Value OCStatus::get_OC_STATUS_BAD_REQUEST(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_BAD_REQUEST);
}

Napi::Value OCStatus::get_OC_STATUS_UNAUTHORIZED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_UNAUTHORIZED);
}

Napi::Value OCStatus::get_OC_STATUS_BAD_OPTION(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_BAD_OPTION);
}

Napi::Value OCStatus::get_OC_STATUS_FORBIDDEN(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_FORBIDDEN);
}

Napi::Value OCStatus::get_OC_STATUS_NOT_FOUND(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_NOT_FOUND);
}

Napi::Value OCStatus::get_OC_STATUS_METHOD_NOT_ALLOWED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_METHOD_NOT_ALLOWED);
}

Napi::Value OCStatus::get_OC_STATUS_NOT_ACCEPTABLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_NOT_ACCEPTABLE);
}

Napi::Value OCStatus::get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_REQUEST_ENTITY_TOO_LARGE);
}

Napi::Value OCStatus::get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_UNSUPPORTED_MEDIA_TYPE);
}

Napi::Value OCStatus::get_OC_STATUS_INTERNAL_SERVER_ERROR(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_INTERNAL_SERVER_ERROR);
}

Napi::Value OCStatus::get_OC_STATUS_NOT_IMPLEMENTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_NOT_IMPLEMENTED);
}

Napi::Value OCStatus::get_OC_STATUS_BAD_GATEWAY(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_BAD_GATEWAY);
}

Napi::Value OCStatus::get_OC_STATUS_SERVICE_UNAVAILABLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_SERVICE_UNAVAILABLE);
}

Napi::Value OCStatus::get_OC_STATUS_GATEWAY_TIMEOUT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_GATEWAY_TIMEOUT);
}

Napi::Value OCStatus::get_OC_STATUS_PROXYING_NOT_SUPPORTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_STATUS_PROXYING_NOT_SUPPORTED);
}

Napi::Value OCStatus::get___NUM_OC_STATUS_CODES__(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), __NUM_OC_STATUS_CODES__);
}

Napi::Value OCStatus::get_OC_IGNORE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_IGNORE);
}

Napi::Value OCStatus::get_OC_PING_TIMEOUT(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_PING_TIMEOUT);
}

Napi::FunctionReference OCSessionState::constructor;

Napi::Function OCSessionState::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSessionState", {
        StaticAccessor("OC_SESSION_CONNECTED", OCSessionState::get_OC_SESSION_CONNECTED, nullptr),
        StaticAccessor("OC_SESSION_DISCONNECTED", OCSessionState::get_OC_SESSION_DISCONNECTED, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSessionState::~OCSessionState()
{
}
OCSessionState::OCSessionState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_session_state_t>(new oc_session_state_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_session_state_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSessionState::get_OC_SESSION_CONNECTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SESSION_CONNECTED);
}

Napi::Value OCSessionState::get_OC_SESSION_DISCONNECTED(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SESSION_DISCONNECTED);
}

Napi::FunctionReference OCSoftwareUpdateResult::constructor;

Napi::Function OCSoftwareUpdateResult::GetClass(Napi::Env env) {
    auto func = DefineClass(env, "OCSoftwareUpdateResult", {
        StaticAccessor("OC_SWUPDATE_RESULT_IDLE", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_IDLE, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_SUCCESS", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SUCCESS, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_LESS_RAM", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_LESS_FLASH", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_CONN_FAIL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_SVV_FAIL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_INVALID_URL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL, nullptr),
        StaticAccessor("OC_SWUPDATE_RESULT_UPGRADE_FAIL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL, nullptr),

    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    return func;
}

OCSoftwareUpdateResult::~OCSoftwareUpdateResult()
{
}
OCSoftwareUpdateResult::OCSoftwareUpdateResult(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
    if (info.Length() == 0) {
        m_pvalue = shared_ptr<oc_swupdate_result_t>(new oc_swupdate_result_t());
    }
    else if (info.Length() == 1 && info[0].IsExternal() ) {
        m_pvalue = *(info[0].As<External<shared_ptr<oc_swupdate_result_t>>>().Data());
    }
    else {
        TypeError::New(info.Env(), "You need to name yourself")
        .ThrowAsJavaScriptException();
    }
}
Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_IDLE);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_SUCCESS);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_LESS_RAM);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_LESS_FLASH);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_CONN_FAIL);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_SVV_FAIL);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_INVALID_URL);
}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo& info)
{
    return Number::New(info.Env(), OC_SWUPDATE_RESULT_UPGRADE_FAIL);
}

