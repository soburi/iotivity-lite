#pragma once

#include "structs.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <system_error>
#include <napi-thread-safe-callback.hpp>

static void nop_deleter(void*) { }

struct main_context_t {
  std::thread helper_poll_event_thread;
  std::mutex helper_sync_lock;
  std::mutex helper_cs_mutex;
  std::unique_lock<std::mutex> helper_cs;
  std::condition_variable helper_cv;
  Napi::FunctionReference oc_handler_init_ref;
  Napi::FunctionReference oc_handler_register_resources_ref;
  Napi::FunctionReference oc_handler_requests_entry_ref;
  int jni_quit;
};

class main_loop_t {
public:
  Napi::Promise::Deferred deferred;
  Napi::ThreadSafeFunction tsfn;
};

struct callback_helper_t {
public:
  Napi::FunctionReference function;
  Napi::ObjectReference value;
  Napi::AsyncContext async_context;

  callback_helper_t(const Napi::CallbackInfo& info) : async_context(info.Env(), "") { }
};

struct safecallback_helper_t {
public:
    ThreadSafeCallback function;
    Napi::Value value;
    Napi::Env env;

    //callback_helper_t(const Napi::CallbackInfo& info) : async_context(info.Env(), "") { }
};

class SafeCallbackHelper {
public:
    ThreadSafeCallback function;
    Napi::Value value;
    Napi::Env env;

    SafeCallbackHelper(const Napi::Function&, const Napi::Value&);
    virtual ~SafeCallbackHelper() {}
};



callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, const Napi::FunctionReference& f);
callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, int idx_func, int idx_val);

extern callback_helper_t* oc_handler_init_helper_data;


//extern Napi::FunctionReference oc_handler_init_ref;
//extern Napi::FunctionReference oc_handler_register_resources_ref;
//extern Napi::FunctionReference oc_handler_requests_entry_ref;

extern Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
extern Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
extern Napi::FunctionReference oc_swupdate_cb_download_update_ref;
extern Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;

Napi::Value N_helper_main_loop(const Napi::CallbackInfo& info);

void terminate_main_loop();

#ifdef __cplusplus
extern "C" {
#endif

int  helper_oc_handler_init();
void helper_oc_handler_signal_event_loop();
void helper_oc_handler_register_resources();
void helper_oc_handler_requests_entry();


void oc_init_platform_helper(void* param);
void oc_add_device_helper(void* param);

oc_discovery_flags_t
helper_oc_do_ip_discovery(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data);


int oc_swupdate_cb_validate_purl_helper(const char *url);
int oc_swupdate_cb_check_new_version_helper(size_t device, const char *url, const char *version);
int oc_swupdate_cb_download_update_helper(size_t device, const char *url);
int oc_swupdate_cb_perform_upgrade_helper(size_t device, const char *url);

void oc_resource_set_properties_cbs_get_helper(oc_resource_t *, oc_interface_mask_t, void *);
bool oc_resource_set_properties_cbs_set_helper(oc_resource_t *, oc_rep_t *, void *);
void helper_oc_resource_set_request_handler(oc_request_t *, oc_interface_mask_t, void *);


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

void helper_poll_event_thread(struct main_context_t* ctx);

#ifdef __cplusplus
}
#endif
