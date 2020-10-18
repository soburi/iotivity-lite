#include "helper.h"
#include <thread>


Napi::FunctionReference oc_handler_init_ref;
//Napi::FunctionReference oc_handler_signal_event_loop_ref;
Napi::ThreadSafeFunction oc_handler_signal_event_loop_ref;
Napi::FunctionReference oc_handler_register_resources_ref;
Napi::FunctionReference oc_handler_requests_entry_ref;

Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
Napi::FunctionReference oc_swupdate_cb_download_update_ref;
Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;

callback_helper_t* oc_handler_init_helper_data;


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

int oc_handler_init_helper()
{
  Napi::Value ret = oc_handler_init_ref.Call({});
  if(ret.IsNumber()) {
    return ret.As<Napi::Number>().Int32Value();
  }
  return 0;
}

void oc_handler_signal_event_loop_helper()
{
  napi_status status = oc_handler_signal_event_loop_ref.NonBlockingCall();

  if (status != napi_ok) {
    Napi::Error::Fatal("ThreadEntry", "Napi::ThreadSafeNapi::Function.BlockingCall() failed");
  }
}

void oc_handler_register_resources_helper()
{
  oc_handler_register_resources_ref.Call({});
}

void oc_handler_requests_entry_helper()
{
  oc_handler_requests_entry_ref.Call({});
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


