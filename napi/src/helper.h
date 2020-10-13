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

void oc_init_platform_helper(void* param);
