#pragma once

#include "structs.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <system_error>
#include <napi-thread-safe-callback.hpp>

static void nop_deleter(void*) { }
extern struct main_context_t* main_context;

class SafeCallbackHelper {
public:
    ThreadSafeCallback function;
    Napi::Value value;
    Napi::Env env;

    SafeCallbackHelper(const Napi::Function&f, const Napi::Value&v) : function(f), value(v), env(f.Env()) {
    }
    virtual ~SafeCallbackHelper() {}
};


class TestHelper {
public:
    ThreadSafeCallback function;
    Napi::Env env;
    Napi::ObjectReference objref;

    TestHelper(const Napi::Function& f, const Napi::Object& v) : function(f), env(v.Env()) {
        objref = Napi::Persistent(v);
    }

    Napi::Value Value() { return objref.Get("v"); }

    virtual ~TestHelper() {}
};

struct main_context_t {
    Napi::Promise::Deferred deferred;
    Napi::ThreadSafeFunction tsfn;

    std::thread helper_poll_event_thread;
    std::mutex helper_sync_lock;
    std::mutex helper_cs_mutex;
    std::unique_lock<std::mutex> helper_cs;
    std::condition_variable helper_cv;

    Napi::FunctionReference oc_handler_init_ref;
    Napi::FunctionReference oc_handler_register_resources_ref;
    Napi::FunctionReference oc_handler_requests_entry_ref;

    Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
    Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
    Napi::FunctionReference oc_swupdate_cb_download_update_ref;
    Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;

    std::vector< std::shared_ptr<SafeCallbackHelper> > callback_helper_array;

    int jni_quit;
};



void terminate_main_loop();

#ifdef __cplusplus
extern "C" {
#endif

int  helper_oc_handler_init();
void helper_oc_handler_signal_event_loop();
void helper_oc_handler_register_resources();
void helper_oc_handler_requests_entry();

void helper_oc_init_platform_cb(void* param);
void helper_oc_add_device_cb(void* param);

oc_discovery_flags_t
helper_oc_discovery_handler(const char *di, const char *uri, oc_string_array_t types,
                            oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
                            oc_resource_properties_t bm, void *user_data);

oc_discovery_flags_t
helper_oc_discovery_all_handler(const char*, const char*, oc_string_array_t, oc_interface_mask_t,
                                oc_endpoint_t*, oc_resource_properties_t, bool, void*);

void helper_oc_response_handler(oc_client_response_t* response);

void helper_oc_ownership_status_cb(const oc_uuid_t* device_uuid,
                                   size_t device_index, bool owned, void* user_data);
oc_event_callback_retval_t helper_oc_trigger(void* data);

void helper_oc_factory_presets_cb(size_t device, void* data);
void helper_oc_random_pin_cb(const unsigned char* pin, size_t pin_len, void* data);

int oc_swupdate_cb_validate_purl_helper(const char *url);
int oc_swupdate_cb_check_new_version_helper(size_t device, const char *url, const char *version);
int oc_swupdate_cb_download_update_helper(size_t device, const char *url);
int oc_swupdate_cb_perform_upgrade_helper(size_t device, const char *url);

void oc_resource_set_properties_cbs_get_helper(oc_resource_t *, oc_interface_mask_t, void *);
bool oc_resource_set_properties_cbs_set_helper(oc_resource_t *, oc_rep_t *, void *);
void helper_oc_resource_set_request_handler(oc_request_t *, oc_interface_mask_t, void *);

void helper_poll_event_thread(struct main_context_t* ctx);


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


#ifdef __cplusplus
}
#endif
