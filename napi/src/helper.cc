#include "helper.h"

Napi::FunctionReference oc_handler_init_ref;
Napi::FunctionReference oc_handler_signal_event_loop_ref;
Napi::FunctionReference oc_handler_register_resources_ref;
Napi::FunctionReference oc_handler_requests_entry_ref;


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
  else {
    return 0;
  }
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

