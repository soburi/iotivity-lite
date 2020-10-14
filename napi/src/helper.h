#pragma once

#include "structs.h"

struct callback_helper_t {
public:
  Napi::FunctionReference function;
  Napi::Reference<Napi::Value> value;
  callback_helper_t(Napi::Function& f, Napi::Value& v)
  {
    function.Reset(f);
    value.Reset(v);
  }
};

extern Napi::FunctionReference oc_handler_init_ref;
extern Napi::FunctionReference oc_handler_signal_event_loop_ref;
extern Napi::FunctionReference oc_handler_register_resources_ref;
extern Napi::FunctionReference oc_handler_requests_entry_ref;

#ifdef __cplusplus
extern "C" {
#endif

void oc_init_platform_helper(void* param);

int oc_handler_init_helper();
void oc_handler_signal_event_loop_helper();
void oc_handler_register_resources_helper();
void oc_handler_requests_entry_helper();

#ifdef __cplusplus
}
#endif
