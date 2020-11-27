#pragma once

#include <thread>
#include <mutex>
#include <condition_variable>
#include <system_error>
#include <napi-thread-safe-callback.hpp>
#include <napi.h>

extern "C" {
#include <oc_api.h>
#include <oc_base64.h>
#include <oc_blockwise.h>
#include <oc_buffer.h>
#include <oc_buffer_settings.h>
#include <oc_client_state.h>
#include <oc_clock_util.h>
#include <oc_cloud.h>
#include <oc_collection.h>
#include <oc_core_res.h>
#include <oc_cred.h>
#include <oc_discovery.h>
#include <oc_endpoint.h>
#include <oc_enums.h>
#include <oc_helpers.h>
#include <oc_introspection.h>
#include <oc_network_events.h>
#include <oc_network_monitor.h>
#include <oc_obt.h>
#include <oc_pki.h>
#include <oc_rep.h>
#include <oc_ri.h>
#include <oc_session_events.h>
#include <oc_signal_event_loop.h>
#include <oc_swupdate.h>
#include <oc_uuid.h>
#include <oc_connectivity.h>
#include <oc_assert.h>
#include <oc_mem_trace.h>
}

struct oc_separate_response_iterator_t {
    oc_separate_response_t* current;
};
struct oc_collection_iterator_t {
    oc_collection_s* current;
};
struct oc_link_iterator_t {
    oc_link_s* current;
};
struct oc_sec_ace_iterator_t {
    oc_sec_ace_t* current;
};
struct oc_ace_res_iterator_t {
    oc_ace_res_t* current;
};
struct oc_cloud_context_iterator_t {
    oc_cloud_context_t* current;
};
struct oc_link_params_iterator_t {
    oc_link_params_t* current;
};
struct oc_rt_iterator_t {
    oc_rt_t* current;
};
struct oc_etimer_iterator_t {
    oc_etimer* current;
};
struct oc_event_callback_iterator_t {
    oc_event_callback_t* current;
};
struct oc_message_iterator_t {
    oc_message_t* current;
};
struct oc_role_iterator_t {
    oc_role_t* current;
};
struct oc_blockwise_state_iterator_t {
    oc_blockwise_state_s* current;
};
struct oc_session_event_cb_iterator_t {
    oc_session_event_cb* current;
};
struct oc_rep_iterator_t {
    oc_rep_s* current;
};
struct oc_endpoint_iterator_t {
    oc_endpoint_t* current;
};

struct oc_string_array_iterator_t {
    oc_string_array_t array;
    uint32_t index;
};



static void nop_deleter(void*) { }
extern struct main_context_t* main_context;

class SafeCallbackHelper {
public:
    ThreadSafeCallback function;
    Napi::ObjectReference objref;

    SafeCallbackHelper(const Napi::Function& f, const Napi::Value& v) : function(f) {
        Napi::Object obj = Napi::Object::New(v.Env());
        obj.Set("v", v);

        objref = Napi::Persistent(obj);
    }

    Napi::Value Value() {
        return objref.Get("v");
    }
    virtual ~SafeCallbackHelper() {}
};


template<typename FPTR>
FPTR check_callback_func(const Napi::CallbackInfo& info, uint32_t order, FPTR cbfunc) {
    return ((info.Length() >= order && info[order].IsFunction()) ? cbfunc : nullptr);
}

SafeCallbackHelper* check_callback_context(const Napi::CallbackInfo& info, uint32_t fn_order, uint32_t ctx_order);

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

void helper_endpoint_list_delete(oc_endpoint_t* eps);

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


void helper_oc_obt_discovery_cb(oc_uuid_t* uuid, oc_endpoint_t* eps, void* data);
void helper_oc_obt_device_status_cb(oc_uuid_t* uuid, int status, void* data);
void helper_oc_obt_status_cb(int status, void* data);

void helper_oc_obt_creds_cb(struct oc_sec_creds_t* creds, void* data);
void helper_oc_obt_acl_cb(oc_sec_acl_t* acl, void* data);


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
