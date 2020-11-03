#pragma once

#include "structs.h"
#include <thread>
#include <mutex>
#include <condition_variable>
#include <system_error>


static void nop_deleter(void*) { }

struct main_context_t {
	std::thread helper_poll_event_thread;
	std::mutex helper_sync_lock;
	std::mutex helper_cs_mutex;
	std::unique_lock<std::mutex> helper_cs;
	std::condition_variable helper_cv;
	int jni_quit;
        Napi::FunctionReference oc_handler_init_ref;
	Napi::FunctionReference oc_handler_register_resources_ref;
	Napi::FunctionReference oc_handler_requests_entry_ref;
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

class CallbackHelper: public Napi::ObjectWrap<CallbackHelper>
{
public:
  CallbackHelper(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;

  Napi::FunctionReference function;
  Napi::ObjectReference value;
};



class OCResource : public Napi::ObjectWrap<OCResource>
{
public:
  OCResource(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator oc_resource_s*() { return m_pvalue.get(); }
  Napi::Value get_default_interface(const Napi::CallbackInfo&);
         void set_default_interface(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_delete_handler(const Napi::CallbackInfo&);
         void set_delete_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_device(const Napi::CallbackInfo&);
         void set_device(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_get_handler(const Napi::CallbackInfo&);
         void set_get_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_get_properties(const Napi::CallbackInfo&);
         void set_get_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_interfaces(const Napi::CallbackInfo&);
         void set_interfaces(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_name(const Napi::CallbackInfo&);
         void set_name(const Napi::CallbackInfo&, const Napi::Value&);
#if defined(OC_COLLECTIONS)
  Napi::Value get_num_links(const Napi::CallbackInfo&);
         void set_num_links(const Napi::CallbackInfo&, const Napi::Value&);
#endif
  Napi::Value get_num_observers(const Napi::CallbackInfo&);
         void set_num_observers(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_observe_period_seconds(const Napi::CallbackInfo&);
         void set_observe_period_seconds(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_post_handler(const Napi::CallbackInfo&);
         void set_post_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_properties(const Napi::CallbackInfo&);
         void set_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_put_handler(const Napi::CallbackInfo&);
         void set_put_handler(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_set_properties(const Napi::CallbackInfo&);
         void set_set_properties(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_func_desc(const Napi::CallbackInfo&);
         void set_tag_func_desc(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_desc(const Napi::CallbackInfo&);
         void set_tag_pos_desc(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_tag_pos_rel(const Napi::CallbackInfo&);
         void set_tag_pos_rel(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_types(const Napi::CallbackInfo&);
         void set_types(const Napi::CallbackInfo&, const Napi::Value&);
  Napi::Value get_uri(const Napi::CallbackInfo&);
         void set_uri(const Napi::CallbackInfo&, const Napi::Value&);

  Napi::Value bind_resource_interface(const Napi::CallbackInfo&);
  Napi::Value bind_resource_type(const Napi::CallbackInfo&);
  Napi::Value make_public(const Napi::CallbackInfo&);
  Napi::Value set_discoverable(const Napi::CallbackInfo&);
  Napi::Value set_observable(const Napi::CallbackInfo&);
  Napi::Value set_periodic_observable(const Napi::CallbackInfo&);
  Napi::Value set_properties_cbs(const Napi::CallbackInfo&);
  Napi::Value set_request_handler(const Napi::CallbackInfo&);

         //void set_tag_pos_desc(const Napi::CallbackInfo&, const Napi::Value&);
         //void set_tag_pos_rel(const Napi::CallbackInfo&, const Napi::Value&);
         //void set_tag_func_desc(const Napi::CallbackInfo&, const Napi::Value&);

  std::shared_ptr<oc_resource_s> m_pvalue;
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
oc_do_ip_discovery_helper(const char *di, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data);


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

void helper_poll_event_thread(struct main_context_t* ctx);

#ifdef __cplusplus
}
#endif
