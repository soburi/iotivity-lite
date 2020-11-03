#include "helper.h"
#include <chrono>

struct main_context_t* main_context;
main_loop_t* main_loop;

Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
Napi::FunctionReference oc_swupdate_cb_download_update_ref;
Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;

callback_helper_t* oc_handler_init_helper_data;


int helper_oc_handler_init()
{
  Napi::Value ret = main_context->oc_handler_init_ref.Call({});
  if(ret.IsNumber()) return ret.As<Napi::Number>().Int32Value();
  return 0;
}

void helper_oc_handler_signal_event_loop()
{
  main_context->helper_cv.notify_all();
}

void helper_oc_handler_register_resources()
{
  main_context->oc_handler_register_resources_ref.Call({});
}

void helper_oc_handler_requests_entry()
{
  main_context->oc_handler_requests_entry_ref.Call({});
}

Napi::FunctionReference CallbackHelper::constructor;

Napi::Function CallbackHelper::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "CallbackHelper", {
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
CallbackHelper::CallbackHelper(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 2 && info[0].IsFunction() ) {
     function.Reset(info[0].As<Napi::Function>());
     //value.Set("0", info[1]);
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::FunctionReference OCResource::constructor;

Napi::Function OCResource::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResource", {
    OCResource::InstanceAccessor("default_interface", &OCResource::get_default_interface, &OCResource::set_default_interface),
    OCResource::InstanceAccessor("delete_handler", &OCResource::get_delete_handler, &OCResource::set_delete_handler),
    OCResource::InstanceAccessor("device", &OCResource::get_device, &OCResource::set_device),
    OCResource::InstanceAccessor("get_handler", &OCResource::get_get_handler, &OCResource::set_get_handler),
    OCResource::InstanceAccessor("get_properties", &OCResource::get_get_properties, &OCResource::set_get_properties),
    OCResource::InstanceAccessor("interfaces", &OCResource::get_interfaces, &OCResource::set_interfaces),
    OCResource::InstanceAccessor("name", &OCResource::get_name, &OCResource::set_name),
#if defined(OC_COLLECTIONS)
    OCResource::InstanceAccessor("num_links", &OCResource::get_num_links, &OCResource::set_num_links),
#endif
    OCResource::InstanceAccessor("num_observers", &OCResource::get_num_observers, &OCResource::set_num_observers),
    OCResource::InstanceAccessor("observe_period_seconds", &OCResource::get_observe_period_seconds, &OCResource::set_observe_period_seconds),
    OCResource::InstanceAccessor("post_handler", &OCResource::get_post_handler, &OCResource::set_post_handler),
    OCResource::InstanceAccessor("properties", &OCResource::get_properties, &OCResource::set_properties),
    OCResource::InstanceAccessor("put_handler", &OCResource::get_put_handler, &OCResource::set_put_handler),
    OCResource::InstanceAccessor("set_properties", &OCResource::get_set_properties, &OCResource::set_set_properties),
    OCResource::InstanceAccessor("tag_func_desc", &OCResource::get_tag_func_desc, &OCResource::set_tag_func_desc),
    OCResource::InstanceAccessor("tag_pos_desc", &OCResource::get_tag_pos_desc, &OCResource::set_tag_pos_desc),
    OCResource::InstanceAccessor("tag_pos_rel", &OCResource::get_tag_pos_rel, &OCResource::set_tag_pos_rel),
    OCResource::InstanceAccessor("types", &OCResource::get_types, &OCResource::set_types),
    OCResource::InstanceAccessor("uri", &OCResource::get_uri, &OCResource::set_uri),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}

OCResource::OCResource(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 4) {
     std::string name_ = info[0].As<Napi::String>().Utf8Value();
     const char* name = name_.c_str();
     std::string uri_ = info[1].As<Napi::String>().Utf8Value();
     const char* uri = uri_.c_str();
     uint8_t num_resource_types = static_cast<uint8_t>(info[2].As<Napi::Number>().Uint32Value());
     size_t device = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());

     m_pvalue = std::shared_ptr<oc_resource_s>( oc_new_resource(name, uri, num_resource_types, device), oc_delete_resource);
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_resource_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}


Napi::Value OCResource::bind_resource_interface(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_bind_resource_interface(resource, iface_mask);
  return info.Env().Undefined();
}

Napi::Value OCResource::bind_resource_type(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_bind_resource_type(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  std::string type_ = info[1].As<Napi::String>().Utf8Value();
  const char* type = type_.c_str();
  (void)oc_resource_bind_resource_type(resource, type);
  return info.Env().Undefined();
}

#if defined(OC_SECURITY)
Napi::Value OCResource::make_public(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_make_public(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_resource_make_public(resource);
  return info.Env().Undefined();
}
#endif


Napi::Value OCResource::set_discoverable(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_set_discoverable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_discoverable(resource, state);
  return info.Env().Undefined();
}

Napi::Value OCResource::set_observable(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_set_observable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  bool state = info[1].As<Napi::Boolean>().Value();
  (void)oc_resource_set_observable(resource, state);
  return info.Env().Undefined();
}


Napi::Value OCResource::set_periodic_observable(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_set_periodic_observable(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  uint16_t seconds = static_cast<uint16_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_periodic_observable(resource, seconds);
  return info.Env().Undefined();
}

Napi::Value OCResource::set_properties_cbs(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_set_properties_cbs(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_get_properties_cb_t get_properties = oc_resource_set_properties_cbs_get_helper;
//
  callback_helper_t* get_propr_user_data = new_callback_helper_t(info, 1, 2);
  if(!get_propr_user_data) get_properties = nullptr;
  oc_set_properties_cb_t set_properties = oc_resource_set_properties_cbs_set_helper;
//
  callback_helper_t* set_props_user_data = new_callback_helper_t(info, 3, 4);
  if(!set_props_user_data) set_properties = nullptr;
  (void)oc_resource_set_properties_cbs(resource, get_properties, get_propr_user_data, set_properties, set_props_user_data);
  return info.Env().Undefined();
}

Napi::Value OCResource::set_request_handler(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_set_request_handler(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[1].As<Napi::Number>().Uint32Value());
  oc_request_callback_t callback = oc_resource_set_request_handler_helper;

  Napi::Value helper = CallbackHelper::constructor.New({ info[2], info[3] });
//callback_helper_t* user_data = new_callback_helper_t(info, 2, 3);
//if(!user_data) callback = nullptr;
  (void)oc_resource_set_request_handler(resource, method, callback, helper);
  return info.Env().Undefined();
}

/*
Napi::Value OCResource::tag_func_desc(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_tag_func_desc(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_enum_t func = static_cast<oc_enum_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_func_desc(resource, func);
  return info.Env().Undefined();
}

Napi::Value OCResource::tag_pos_desc(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_tag_pos_desc(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_pos_desc(resource, pos);
  return info.Env().Undefined();
}

Napi::Value OCResource::tag_pos_rel(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_tag_pos_rel(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  double x = info[1].As<Napi::Number>().DoubleValue();
  double y = info[2].As<Napi::Number>().DoubleValue();
  double z = info[3].As<Napi::Number>().DoubleValue();
  (void)oc_resource_tag_pos_rel(resource, x, y, z);
  return info.Env().Undefined();
}
*/



Napi::Value OCResource::get_default_interface(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->default_interface);
}

void OCResource::set_default_interface(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->default_interface = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}
/*
Napi::Value OCResource::set_default_interface(const Napi::CallbackInfo& info) {
//Napi::Value N_oc_resource_set_default_interface(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_set_default_interface(resource, iface_mask);
  return info.Env().Undefined();
}
*/
Napi::Value OCResource::get_delete_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->delete_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_delete_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->delete_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_device(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->device);
}

void OCResource::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->device = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_get_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->get_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_get_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCPropertiesCb::constructor.New({accessor});
}

void OCResource::set_get_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_properties = *(*(value.As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCResource::get_interfaces(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interfaces);
}



void OCResource::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCResource::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

#if defined(OC_COLLECTIONS)
Napi::Value OCResource::get_num_links(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num_links);
}

void OCResource::set_num_links(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num_links = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCResource::get_num_observers(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num_observers);
}

void OCResource::set_num_observers(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num_observers = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_observe_period_seconds(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_period_seconds);
}

void OCResource::set_observe_period_seconds(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_period_seconds = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_post_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->post_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_post_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->post_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_properties(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->properties);
}

void OCResource::set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->properties = static_cast<oc_resource_properties_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_put_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->put_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->put_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_set_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCPropertiesCb::constructor.New({accessor});
}

void OCResource::set_set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->set_properties = *(*(value.As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCResource::get_tag_func_desc(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->tag_func_desc);
}

void OCResource::set_tag_func_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->tag_func_desc = static_cast<oc_enum_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_tag_pos_desc(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->tag_pos_desc);
}

void OCResource::set_tag_pos_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->tag_pos_desc = static_cast<oc_pos_description_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_tag_pos_rel(const Napi::CallbackInfo& info)
{
auto array = Napi::Float64Array::New(info.Env(), 3);
array[0] = m_pvalue->tag_pos_rel[0];
array[1] = m_pvalue->tag_pos_rel[1];
array[2] = m_pvalue->tag_pos_rel[2];
return array;
}

void OCResource::set_tag_pos_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->tag_pos_rel[0] = value.As<Napi::Float64Array>()[0];
m_pvalue->tag_pos_rel[1] = value.As<Napi::Float64Array>()[1];
m_pvalue->tag_pos_rel[2] = value.As<Napi::Float64Array>()[2];
}


Napi::Value OCResource::get_types(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->types);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCResource::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCResource::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCResource::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}














callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, const Napi::FunctionReference& f)
{
  callback_helper_t* helper = new callback_helper_t(info);
  helper->function.Reset(f.Value());
  return helper;
}

callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, int idx_func, int idx_val)
{
  if(info.Length() < idx_func || !info[idx_func].IsFunction() ) return nullptr;
  callback_helper_t* helper = new callback_helper_t(info);
  helper->function = Napi::Persistent(info[idx_func].As<Napi::Function>());
  if(info.Length() > idx_val) {
    //helper->value = Napi::Persistent(info[idx_val].As<Napi::Object>());
  }

  return helper;
}

void oc_init_platform_helper(void* param)
{
printf("oc_init_platform_helper");
/*
  callback_helper_t* helper = (callback_helper_t*)param;
//  Napi::HandleScope(helper->function.Env());
//  Napi::CallbackScope scope(helper->function.Env(), helper->async_context);
  helper->function.MakeCallback(helper->function.Env().Null(), {helper->value.Value()});
printf("end oc_init_platform_helper\n");
*/
}

void oc_add_device_helper(void* param)
{
printf("oc_add_device_helper\n");
  callback_helper_t* helper = (callback_helper_t*)param;
  Napi::CallbackScope scope(helper->function.Env(), helper->async_context);
  helper->function.MakeCallback(helper->function.Env().Null(), {helper->value.Value()});
printf("end oc_add_device_helper\n");
}

oc_discovery_flags_t
oc_do_ip_discovery_helper(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  callback_helper_t* helper = (callback_helper_t*)user_data;
  auto         di_ = Napi::String::New(helper->function.Env(), di);
  auto        uri_ = Napi::String::New(helper->function.Env(), uri);
  //?
  std::shared_ptr<oc_endpoint_t> endpoint_sp(endpoint, nop_deleter);
  auto   endpoint_ = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(helper->function.Env(), &endpoint_sp);
  auto iface_mask_ = Napi::Number::New(helper->function.Env(), iface_mask);
  auto         bm_ = Napi::Number::New(helper->function.Env(), bm);

  Napi::CallbackScope scope(helper->function.Env(), helper->async_context);
  Napi::Value ret = helper->function.MakeCallback(helper->function.Env().Null(), {di_, uri_, nullptr, iface_mask_, endpoint_, bm_, helper->value.Value()});

  if(ret.IsNumber()) {
    return static_cast<oc_discovery_flags_t>(ret.As<Napi::Number>().Uint32Value());
  }
  return OC_STOP_DISCOVERY;
}

int oc_swupdate_cb_validate_purl_helper(const char *url)
{
  Napi::String Nurl = Napi::String::New(oc_swupdate_cb_validate_purl_ref.Env(), url);
  Napi::Value ret = oc_swupdate_cb_validate_purl_ref.Call({Nurl});
  if(ret.IsNumber()) {
    return ret.As<Napi::Number>().Int32Value();
  }
  return 0;
}

int oc_swupdate_cb_check_new_version_helper(size_t device, const char *url, const char *version)
{
  Napi::Number Ndevice = Napi::Number::New(oc_swupdate_cb_check_new_version_ref.Env(), device);
  Napi::String Nurl = Napi::String::New(oc_swupdate_cb_check_new_version_ref.Env(), url);
  Napi::String Nversion = Napi::String::New(oc_swupdate_cb_check_new_version_ref.Env(), version);
  Napi::Value ret = oc_swupdate_cb_check_new_version_ref.Call({Ndevice, Nurl, Nversion});
  if(ret.IsNumber()) {
    return ret.As<Napi::Number>().Int32Value();
  }
  return 0;
}

int oc_swupdate_cb_download_update_helper(size_t device, const char *url)
{
  Napi::Number Ndevice = Napi::Number::New(oc_swupdate_cb_download_update_ref.Env(), device);
  Napi::String Nurl = Napi::String::New(oc_swupdate_cb_download_update_ref.Env(), url);
  Napi::Value ret = oc_swupdate_cb_download_update_ref.Call({Ndevice, Nurl});
  if(ret.IsNumber()) {
    return ret.As<Napi::Number>().Int32Value();
  }
  return 0;
}

int oc_swupdate_cb_perform_upgrade_helper(size_t device, const char *url)
{
  Napi::Number Ndevice = Napi::Number::New(oc_swupdate_cb_perform_upgrade_ref.Env(), device);
  Napi::String Nurl = Napi::String::New(oc_swupdate_cb_perform_upgrade_ref.Env(), url);
  Napi::Value ret = oc_swupdate_cb_perform_upgrade_ref.Call({Ndevice, Nurl});
  if(ret.IsNumber()) {
    return ret.As<Napi::Number>().Int32Value();
  }
  return 0;
}

void oc_resource_set_properties_cbs_get_helper(oc_resource_t* res, oc_interface_mask_t mask, void* data) { }
bool oc_resource_set_properties_cbs_set_helper(oc_resource_t* res, oc_rep_t* rep, void* data) { return true; }
void oc_resource_set_request_handler_helper(oc_request_t* req, oc_interface_mask_t mask, void* data) { }

void finalizer(const Napi::Env& e) {
    printf("env");
}

void NopFunc(const Napi::CallbackInfo& info) {
  OC_DBG("JNI: - resolve %s", __func__);
  main_loop->deferred.Resolve(info.Env().Undefined() );
  delete main_loop;
  main_loop = nullptr;
}

Napi::Value N_helper_main_loop(const Napi::CallbackInfo& info) {
  main_loop = new main_loop_t{ Napi::Promise::Deferred::New(info.Env()),
                               Napi::ThreadSafeFunction::New(info.Env(), Napi::Function::New(info.Env(), NopFunc), "TSFN", 0, 1, finalizer) };
  return main_loop->deferred.Promise();
}

void terminate_main_loop() {
  if (main_context) {
    main_context->helper_cv.notify_all();
    main_context->jni_quit = 1;
  }
}

void helper_poll_event_thread(struct main_context_t* mainctx)
{
  delete main_context;
  main_context = mainctx;

  OC_DBG("inside the JNI jni_poll_event\n");
  oc_clock_time_t next_event;
  while (main_context->jni_quit != 1) {
    OC_DBG("JNI: - lock %s\n", __func__);
    main_context->helper_sync_lock.lock();
    OC_DBG("calling oc_main_poll from JNI code\n");
    next_event = oc_main_poll();
    main_context->helper_sync_lock.unlock();
    OC_DBG("JNI: - unlock %s\n", __func__);

    if (next_event == 0) {
      std::unique_lock<std::mutex> helper_cs(main_context->helper_cs_mutex);
      main_context->helper_cv.wait(helper_cs);
    }
    else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
	    std::chrono::milliseconds duration((next_event - now) * 1000 / OC_CLOCK_SECOND);
        std::unique_lock<std::mutex> helper_cs(main_context->helper_cs_mutex);
        main_context->helper_cv.wait_for(helper_cs, duration);
      }
    }
  }

  OC_DBG("jni_quit\n");
  napi_status status = main_loop->tsfn.BlockingCall();
  main_loop->tsfn.Release();

  OC_DBG("JNI: - oc_main_shutdown %s", __func__);
  oc_main_shutdown();
  OC_DBG("end oc_main_shutdown");
  delete main_context;
  main_context = nullptr;
}





#include <stdint.h>		// Use the C99 official header


#include "port/oc_log.h"


#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include "oc_helpers.h"
#include "port/oc_log.h"


uint8_t *g_new_rep_buffer = NULL;
struct oc_memb g_rep_objects;

int g_err;

void helper_rep_delete_buffer() {
  free(g_new_rep_buffer);
  g_new_rep_buffer = NULL;
}

void helper_rep_new_buffer(int size) {
  if (g_new_rep_buffer) {
    helper_rep_delete_buffer();
  }
  g_new_rep_buffer = (uint8_t *)malloc(size);
  oc_rep_new(g_new_rep_buffer, size);
  g_rep_objects.size = sizeof(oc_rep_t);
  g_rep_objects.num = 0;
  g_rep_objects.count = NULL;
  g_rep_objects.mem = NULL;
  g_rep_objects.buffers_avail_cb = NULL;
  oc_rep_set_pool(&g_rep_objects);
}


/* Alt implementation of oc_rep_set_double macro*/
void helper_rep_set_double(CborEncoder * object, const char* key, double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_double(object, value);
}


/* Alt implementation of oc_rep_set_int macro */
void helper_rep_set_long(CborEncoder * object, const char* key, int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_int(object, value);
}


/* Alt implementation of oc_rep_set_uint macro */
void helper_rep_set_uint(CborEncoder * object, const char* key, unsigned int value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_uint(object, value);
}


/* Alt implementation of oc_rep_set_boolean macro */
void helper_rep_set_boolean(CborEncoder * object, const char* key, bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_boolean(object, value);
}


/* Alt implementation of oc_rep_set_text_string macro */
void helper_rep_set_text_string(CborEncoder * object, const char* key, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_text_string(object, value, strlen(value));
}


/* Alt implementation of oc_rep_set_byte_string macro */
void helper_rep_set_byte_string(CborEncoder * object, const char* key, const unsigned char *value, size_t length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_byte_string(object, value, length);
}


/* Alt implementation of oc_rep_start_array macro */
CborEncoder * helper_rep_start_array(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __func__);
  CborEncoder *cbor_encoder_array = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_array(parent, cbor_encoder_array, CborIndefiniteLength);
  return cbor_encoder_array;
}


/* Alt implementation of oc_rep_end_array macro */
void helper_rep_end_array(CborEncoder *parent, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_close_container(parent, arrayObject);
  free(arrayObject);
  arrayObject = NULL;
}


/* Alt implementation of oc_rep_start_links_array macro */
CborEncoder* helper_rep_start_links_array() {
  OC_DBG("JNI: %s\n", __func__);
  cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength);
  return &links_array;
}


/* Alt implementation of oc_rep_end_links_array macro */
void helper_rep_end_links_array() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_links_array();
}


/* Alt implementation of oc_rep_start_root_object macro */
CborEncoder* helper_rep_start_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength);
  return &root_map;
}


void helper_rep_end_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_root_object();
}


/* Alt implementation of oc_rep_add_byte_string macro */
void helper_rep_add_byte_string(CborEncoder *arrayObject, const unsigned char* value, const size_t length) {
  OC_DBG("JNI: %s\n", __func__);
  if (value != NULL) {
    g_err |= cbor_encode_byte_string(arrayObject, value, length);
  }
}


/* Alt implementation of oc_rep_add_text_string macro */
void helper_rep_add_text_string(CborEncoder *arrayObject, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  if (value != NULL) {
    g_err |= cbor_encode_text_string(arrayObject, value, strlen(value));
  }
}


/* Alt implementation of oc_rep_add_double macro */
void helper_rep_add_double(CborEncoder *arrayObject, const double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_double(arrayObject, value);
}


/* Alt implementation of oc_rep_add_int macro */
void helper_rep_add_int(CborEncoder *arrayObject, const int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_int(arrayObject, value);
}


/* Alt implementation of oc_rep_add_boolean macro */
void helper_rep_add_boolean(CborEncoder *arrayObject, const bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_boolean(arrayObject, value);
}


/* Alt implementation of oc_rep_set_key macro */
void helper_rep_set_key(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
}


/* Alt implementation of oc_rep_set_array macro */
CborEncoder * helper_rep_set_array(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return helper_rep_start_array(parent);
}


/* Alt implementation of oc_rep_close_array macro */
void helper_rep_close_array(CborEncoder *object, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  helper_rep_end_array(object, arrayObject);
}


/* Alt implementation of oc_rep_start_object macro */
CborEncoder * helper_rep_start_object(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __func__);
  CborEncoder *cbor_encoder_map = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_map(parent, cbor_encoder_map, CborIndefiniteLength);
  return cbor_encoder_map;
}


/* Alt implementation of oc_rep_end_object macro */
void helper_rep_end_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_close_container(parent, object);
  free(object);
  object = NULL;
}


/* Alt implementation of oc_rep_object_array_start_item macro */
CborEncoder * helper_rep_object_array_start_item(CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  return helper_rep_start_object(arrayObject);
}


/* Alt implementation of oc_rep_object_array_end_item macro */
void helper_rep_object_array_end_item(CborEncoder *parentArrayObject, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  helper_rep_end_object(parentArrayObject, arrayObject);
}


/* Alt implementation of oc_rep_set_object macro */
CborEncoder * helper_rep_open_object(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return helper_rep_start_object(parent);
}


/* Alt implementation of oc_rep_close_object macro */
void helper_rep_close_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __func__);
  helper_rep_end_object(parent, object);
}


/* Alt implementation of oc_rep_set_int_array macro */
void helper_rep_set_long_array(CborEncoder *object, const char* key, int64_t *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_int(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/* Alt implementation of oc_rep_set_bool_array macro */
void helper_rep_set_bool_array(CborEncoder *object, const char* key, bool *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_boolean(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/* Alt implementation of oc_rep_set_double_array macro */
void helper_rep_set_double_array(CborEncoder *object, const char* key, double *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_floating_point(&value_array, CborDoubleType, &values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/* Alt implementation of oc_rep_set_string_array macro */
void helper_rep_rep_set_string_array(CborEncoder *object, const char* key, oc_string_array_t values) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, CborIndefiniteLength);
  int i;
    for (i = 0; i < (int)oc_string_array_get_allocated_size(values); i++) {
      if (oc_string_array_get_item_size(values, i) > 0) {
        g_err |= cbor_encode_text_string(&value_array, oc_string_array_get_item(values, i),
                                         oc_string_array_get_item_size(values, i));
      }
    }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/*
 * Java only helper function to convert the root CborEncoder object to an oc_rep_t this is needed
 * to enable encode/decode unit testing. This function is not expected to be used in typical
 * use case. It should only be called after calling oc_rep_end_root_object.
 */
oc_rep_t * helper_rep_get_rep_from_root_object() {
  oc_rep_t * rep = (oc_rep_t *)malloc(sizeof(oc_rep_t));
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  oc_parse_rep(payload, payload_len, &rep);
  return rep;
}


int helper_rep_get_cbor_errno() {
  return (int)oc_rep_get_cbor_errno();
}


void helper_rep_clear_cbor_errno() {
  g_err = CborNoError;
}

CborEncoder * helper_rep_open_array(CborEncoder *parent, const char* key) {
  return helper_rep_set_array(parent, key);
}


