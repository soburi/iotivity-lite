#pragma once

#include "structs.h"

struct callback_helper_t {
public:
  Napi::FunctionReference function;
  Napi::ObjectReference value;
  Napi::AsyncContext async_context;

  callback_helper_t(const Napi::CallbackInfo& info) : async_context(info.Env(), "") { }
};

callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, const Napi::FunctionReference& f);
callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, int idx_func, int idx_val);

extern callback_helper_t* oc_handler_init_helper_data;


extern Napi::FunctionReference oc_handler_init_ref;
//extern Napi::FunctionReference oc_handler_signal_event_loop_ref;
extern Napi::ThreadSafeFunction oc_handler_signal_event_loop_ref;
extern Napi::FunctionReference oc_handler_register_resources_ref;
extern Napi::FunctionReference oc_handler_requests_entry_ref;

extern Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
extern Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
extern Napi::FunctionReference oc_swupdate_cb_download_update_ref;
extern Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;

#ifdef __cplusplus
extern "C" {
#endif

void oc_init_platform_helper(void* param);
void oc_add_device_helper(void* param);

int oc_handler_init_helper();
void oc_handler_signal_event_loop_helper();
void oc_handler_register_resources_helper();
void oc_handler_requests_entry_helper();

int oc_swupdate_cb_validate_purl_helper(const char *url);
int oc_swupdate_cb_check_new_version_helper(size_t device, const char *url, const char *version);
int oc_swupdate_cb_download_update_helper(size_t device, const char *url);
int oc_swupdate_cb_perform_upgrade_helper(size_t device, const char *url);

void oc_resource_set_properties_cbs_get_helper(oc_resource_t *, oc_interface_mask_t, void *);
bool oc_resource_set_properties_cbs_set_helper(oc_resource_t *, oc_rep_t *, void *);
void oc_resource_set_request_handler_helper(oc_request_t *, oc_interface_mask_t, void *);

#ifdef __cplusplus
}
#endif
