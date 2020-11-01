#pragma once

#include "structs.h"
#if defined(_WIN32)
#include <windows.h>
#endif


#if defined(_WIN32)
#define jni_mutex_lock(m) EnterCriticalSection(&m)
#define jni_mutex_unlock(m) LeaveCriticalSection(&m)
extern HANDLE jni_poll_event_thread;
extern CRITICAL_SECTION jni_sync_lock;
extern CONDITION_VARIABLE jni_cv;
extern CRITICAL_SECTION jni_cs;

#elif defined(__linux__)
#define jni_mutex_lock(m) pthread_mutex_lock(&m)
#define jni_mutex_unlock(m) pthread_mutex_unlock(&m)
extern pthread_t jni_poll_event_thread;
#elif defined(__linux__)
#endif

class main_context_t {
public:
	Napi::ThreadSafeFunction tsfn;
	Napi::Promise::Deferred deferred;
	main_context_t(const Napi::Env& env) : deferred(env) { }
};

extern main_context_t* main_context;

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

Napi::Value N_helper_main_loop(const Napi::CallbackInfo& info);

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


void helper_rep_set_double(CborEncoder * object, const char* key, double value);
void helper_rep_set_long(CborEncoder * object, const char* key, int64_t value);
void helper_rep_set_uint(CborEncoder * object, const char* key, unsigned int value);
void helper_rep_set_boolean(CborEncoder * object, const char* key, bool value);
void helper_rep_set_text_string(CborEncoder * object, const char* key, const char* value);
void helper_rep_set_byte_string(CborEncoder * object, const char* key, const unsigned char *value, size_t length);
CborEncoder * helper_rep_start_array(CborEncoder *parent);
void helper_rep_end_array(CborEncoder *parent, CborEncoder *arrayObject);
CborEncoder * helper_rep_start_links_array();
void helper_rep_end_links_array();
CborEncoder * helper_rep_start_root_object();
void helper_rep_end_root_object();
void helper_rep_add_byte_string(CborEncoder *arrayObject, const unsigned char* value, const size_t length);
void helper_rep_add_text_string(CborEncoder *arrayObject, const char* value);
void helper_rep_add_double(CborEncoder *arrayObject, const double value);
void helper_rep_add_int(CborEncoder *arrayObject, const int64_t value);
void helper_rep_add_boolean(CborEncoder *arrayObject, const bool value);
void helper_rep_set_key(CborEncoder *parent, const char* key);
CborEncoder * helper_rep_set_array(CborEncoder *parent, const char* key);
void helper_rep_close_array(CborEncoder *object, CborEncoder *arrayObject);
CborEncoder * helper_rep_start_object(CborEncoder *parent);
void helper_rep_end_object(CborEncoder *parent, CborEncoder *object);
CborEncoder * helper_rep_open_array(CborEncoder *parent, const char* key);
CborEncoder * helper_rep_object_array_start_item(CborEncoder *arrayObject);
void helper_rep_object_array_end_item(CborEncoder *parentArrayObject, CborEncoder *arrayObject);
CborEncoder * helper_rep_open_object(CborEncoder *parent, const char* key);
void helper_rep_close_object(CborEncoder *parent, CborEncoder *object);
void helper_rep_set_long_array(CborEncoder *object, const char* key, int64_t *values, int length);
void helper_rep_set_bool_array(CborEncoder *object, const char* key, bool *values, int length);
void helper_rep_set_double_array(CborEncoder *object, const char* key, double *values, int length);
void helper_rep_rep_set_string_array(CborEncoder *object, const char* key, oc_string_array_t values);
oc_rep_t * helper_rep_get_rep_from_root_object();
int helper_rep_get_cbor_errno();
void helper_rep_clear_cbor_errno();
void helper_rep_delete_buffer();
void helper_rep_new_buffer(int size);

#if defined(_WIN32)
DWORD WINAPI
jni_poll_event(LPVOID lpParam);
#elif defined(__linux__)
void *
jni_poll_event(void *data)
#endif

#ifdef __cplusplus
}
#endif
