#include "helper.h"

Napi::FunctionReference oc_handler_init_ref;
Napi::FunctionReference oc_handler_signal_event_loop_ref;
Napi::FunctionReference oc_handler_register_resources_ref;
Napi::FunctionReference oc_handler_requests_entry_ref;

Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
Napi::FunctionReference oc_swupdate_cb_download_update_ref;
Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;



void oc_init_platform_helper(void* param)
{
	callback_helper_t* helper = (callback_helper_t*)param;
	helper->function.Call({helper->value.Value()});
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
  oc_handler_signal_event_loop_ref.Call({});
}

void oc_handler_register_resources_helper()
{
  oc_handler_register_resources_ref.Call({});
}

void oc_handler_requests_entry_helper()
{
  oc_handler_requests_entry_ref.Call({});
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


