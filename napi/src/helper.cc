#include "helper.h"
#include <thread>
#if defined(_WIN32)
#include <windows.h>
#endif

std::thread helper_poll_event_thread;
int jni_quit = 0;

#if defined(_WIN32)
CRITICAL_SECTION jni_sync_lock;
CONDITION_VARIABLE jni_cv;
CRITICAL_SECTION jni_cs;
#endif

main_context_t* main_context;

Napi::FunctionReference oc_handler_init_ref;
//Napi::FunctionReference oc_handler_signal_event_loop_ref;
Napi::ThreadSafeFunction oc_handler_signal_event_loop_ref;
Napi::FunctionReference oc_handler_register_resources_ref;
Napi::FunctionReference oc_handler_requests_entry_ref;

Napi::FunctionReference oc_swupdate_cb_validate_purl_ref;
Napi::FunctionReference oc_swupdate_cb_check_new_version_ref;
Napi::FunctionReference oc_swupdate_cb_download_update_ref;
Napi::FunctionReference oc_swupdate_cb_perform_upgrade_ref;

callback_helper_t* oc_handler_init_helper_data;


callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, const Napi::FunctionReference& f)
{
  callback_helper_t* helper = new callback_helper_t(info);
  helper->function.Reset(f.Value());
  return helper;
}

callback_helper_t* new_callback_helper_t(const Napi::CallbackInfo& info, int idx_func, int idx_val)
{
  if(info.Length() < idx_func || !info[idx_func].IsFunction() ) return nullptr;
  callback_helper_t* helper = new callback_helper_t(info);
  helper->function = Napi::Persistent(info[idx_func].As<Napi::Function>());
  if(info.Length() > idx_val) {
    //helper->value = Napi::Persistent(info[idx_val].As<Napi::Object>());
  }

  return helper;
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
#if 0
  napi_status status = oc_handler_signal_event_loop_ref.NonBlockingCall();

  if (status != napi_ok) {
    Napi::Error::Fatal("ThreadEntry", "Napi::ThreadSafeNapi::Function.BlockingCall() failed");
  }
#endif

  OC_DBG("JNI: %s\n", __func__);
#if defined(_WIN32)
  WakeConditionVariable(&jni_cv);
#elif defined(__linux__)
  jni_mutex_lock(jni_cs);
  pthread_cond_signal(&jni_cv);
  jni_mutex_unlock(jni_cs);
#endif
}

void oc_handler_register_resources_helper()
{
  oc_handler_register_resources_ref.Call({});
}

void oc_handler_requests_entry_helper()
{
  oc_handler_requests_entry_ref.Call({});
}


void oc_init_platform_helper(void* param)
{
printf("oc_init_platform_helper");
/*
  callback_helper_t* helper = (callback_helper_t*)param;
//  Napi::HandleScope(helper->function.Env());
//  Napi::CallbackScope scope(helper->function.Env(), helper->async_context);
  helper->function.MakeCallback(helper->function.Env().Null(), {helper->value.Value()});
printf("end oc_init_platform_helper\n");
*/
}

void oc_add_device_helper(void* param)
{
printf("oc_add_device_helper\n");
  callback_helper_t* helper = (callback_helper_t*)param;
  Napi::CallbackScope scope(helper->function.Env(), helper->async_context);
  helper->function.MakeCallback(helper->function.Env().Null(), {helper->value.Value()});
printf("end oc_add_device_helper\n");
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

void oc_resource_set_properties_cbs_get_helper(oc_resource_t* res, oc_interface_mask_t mask, void* data) { }
bool oc_resource_set_properties_cbs_set_helper(oc_resource_t* res, oc_rep_t* rep, void* data) { return true; }
void oc_resource_set_request_handler_helper(oc_request_t* req, oc_interface_mask_t mask, void* data) { }

void NopFunc(const Napi::CallbackInfo& info) {
  OC_DBG("JNI: - resolve %s\n", __func__);
  main_context->deferred.Resolve(info.Env().Undefined() );
  OC_DBG("JNI: - oc_main_shutdown %s\n", __func__);
}

Napi::Value N_helper_main_loop(const Napi::CallbackInfo& info) {
  main_context = new main_context_t(info.Env());
  main_context->tsfn = Napi::ThreadSafeFunction::New(info.Env(), Napi::Function::New(info.Env(), NopFunc), "TSFN", 0, 1);
  return main_context->deferred.Promise();
}

void terminate_main_loop() {
  jni_quit = 1;
  WakeConditionVariable(&jni_cv);
  //oc_main_poll();
}

void helper_poll_event()
{
  OC_DBG("inside the JNI jni_poll_event\n");
  oc_clock_time_t next_event;
#if defined(_WIN32)
  while (jni_quit != 1) {
      OC_DBG("JNI: - lock %s\n", __func__);
      jni_mutex_lock(jni_sync_lock);
      OC_DBG("calling oc_main_poll from JNI code\n");
      next_event = oc_main_poll();
      jni_mutex_unlock(jni_sync_lock);
      OC_DBG("JNI: - unlock %s\n", __func__);

      if (next_event == 0) {
          SleepConditionVariableCS(&jni_cv, &jni_cs, INFINITE);
      }
      else {
          oc_clock_time_t now = oc_clock_time();
          if (now < next_event) {
              SleepConditionVariableCS(&jni_cv, &jni_cs,
                  (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
          }
      }
  }
#elif defined(__linux__)
  while (jni_quit != 1) {
    OC_DBG("JNI: - lock %s\n", __func__);
    jni_mutex_lock(jni_sync_lock);
    OC_DBG("calling oc_main_poll from JNI code\n");
    next_event = oc_main_poll();
    jni_mutex_unlock(jni_sync_lock);
    OC_DBG("JNI: - unlock %s\n", __func__);

    jni_mutex_lock(jni_cs);
    if (next_event == 0) {
      pthread_cond_wait(&jni_cv, &jni_cs);
    } else {
      struct timespec ts;
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&jni_cv, &jni_cs, &ts);
    }
    jni_mutex_unlock(jni_cs);
  }
#endif

  napi_status status = main_context->tsfn.BlockingCall();

  oc_main_shutdown();
}





#include <stdint.h>		// Use the C99 official header


#include "port/oc_log.h"


#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include "oc_helpers.h"
#include "port/oc_log.h"


uint8_t *g_new_rep_buffer = NULL;
struct oc_memb g_rep_objects;

int g_err;

void helper_rep_delete_buffer() {
  free(g_new_rep_buffer);
  g_new_rep_buffer = NULL;
}

void helper_rep_new_buffer(int size) {
  if (g_new_rep_buffer) {
    helper_rep_delete_buffer();
  }
  g_new_rep_buffer = (uint8_t *)malloc(size);
  oc_rep_new(g_new_rep_buffer, size);
  g_rep_objects.size = sizeof(oc_rep_t);
  g_rep_objects.num = 0;
  g_rep_objects.count = NULL;
  g_rep_objects.mem = NULL;
  g_rep_objects.buffers_avail_cb = NULL;
  oc_rep_set_pool(&g_rep_objects);
}


/* Alt implementation of oc_rep_set_double macro*/
void helper_rep_set_double(CborEncoder * object, const char* key, double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_double(object, value);
}


/* Alt implementation of oc_rep_set_int macro */
void helper_rep_set_long(CborEncoder * object, const char* key, int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_int(object, value);
}


/* Alt implementation of oc_rep_set_uint macro */
void helper_rep_set_uint(CborEncoder * object, const char* key, unsigned int value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_uint(object, value);
}


/* Alt implementation of oc_rep_set_boolean macro */
void helper_rep_set_boolean(CborEncoder * object, const char* key, bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_boolean(object, value);
}


/* Alt implementation of oc_rep_set_text_string macro */
void helper_rep_set_text_string(CborEncoder * object, const char* key, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_text_string(object, value, strlen(value));
}


/* Alt implementation of oc_rep_set_byte_string macro */
void helper_rep_set_byte_string(CborEncoder * object, const char* key, const unsigned char *value, size_t length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_byte_string(object, value, length);
}


/* Alt implementation of oc_rep_start_array macro */
CborEncoder * helper_rep_start_array(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __func__);
  CborEncoder *cbor_encoder_array = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_array(parent, cbor_encoder_array, CborIndefiniteLength);
  return cbor_encoder_array;
}


/* Alt implementation of oc_rep_end_array macro */
void helper_rep_end_array(CborEncoder *parent, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_close_container(parent, arrayObject);
  free(arrayObject);
  arrayObject = NULL;
}


/* Alt implementation of oc_rep_start_links_array macro */
CborEncoder* helper_rep_start_links_array() {
  OC_DBG("JNI: %s\n", __func__);
  cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength);
  return &links_array;
}


/* Alt implementation of oc_rep_end_links_array macro */
void helper_rep_end_links_array() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_links_array();
}


/* Alt implementation of oc_rep_start_root_object macro */
CborEncoder* helper_rep_start_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength);
  return &root_map;
}


void helper_rep_end_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_root_object();
}


/* Alt implementation of oc_rep_add_byte_string macro */
void helper_rep_add_byte_string(CborEncoder *arrayObject, const unsigned char* value, const size_t length) {
  OC_DBG("JNI: %s\n", __func__);
  if (value != NULL) {
    g_err |= cbor_encode_byte_string(arrayObject, value, length);
  }
}


/* Alt implementation of oc_rep_add_text_string macro */
void helper_rep_add_text_string(CborEncoder *arrayObject, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  if (value != NULL) {
    g_err |= cbor_encode_text_string(arrayObject, value, strlen(value));
  }
}


/* Alt implementation of oc_rep_add_double macro */
void helper_rep_add_double(CborEncoder *arrayObject, const double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_double(arrayObject, value);
}


/* Alt implementation of oc_rep_add_int macro */
void helper_rep_add_int(CborEncoder *arrayObject, const int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_int(arrayObject, value);
}


/* Alt implementation of oc_rep_add_boolean macro */
void helper_rep_add_boolean(CborEncoder *arrayObject, const bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_boolean(arrayObject, value);
}


/* Alt implementation of oc_rep_set_key macro */
void helper_rep_set_key(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
}


/* Alt implementation of oc_rep_set_array macro */
CborEncoder * helper_rep_set_array(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return helper_rep_start_array(parent);
}


/* Alt implementation of oc_rep_close_array macro */
void helper_rep_close_array(CborEncoder *object, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  helper_rep_end_array(object, arrayObject);
}


/* Alt implementation of oc_rep_start_object macro */
CborEncoder * helper_rep_start_object(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __func__);
  CborEncoder *cbor_encoder_map = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_map(parent, cbor_encoder_map, CborIndefiniteLength);
  return cbor_encoder_map;
}


/* Alt implementation of oc_rep_end_object macro */
void helper_rep_end_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_close_container(parent, object);
  free(object);
  object = NULL;
}


/* Alt implementation of oc_rep_object_array_start_item macro */
CborEncoder * helper_rep_object_array_start_item(CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  return helper_rep_start_object(arrayObject);
}


/* Alt implementation of oc_rep_object_array_end_item macro */
void helper_rep_object_array_end_item(CborEncoder *parentArrayObject, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  helper_rep_end_object(parentArrayObject, arrayObject);
}


/* Alt implementation of oc_rep_set_object macro */
CborEncoder * helper_rep_open_object(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return helper_rep_start_object(parent);
}


/* Alt implementation of oc_rep_close_object macro */
void helper_rep_close_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __func__);
  helper_rep_end_object(parent, object);
}


/* Alt implementation of oc_rep_set_int_array macro */
void helper_rep_set_long_array(CborEncoder *object, const char* key, int64_t *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_int(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/* Alt implementation of oc_rep_set_bool_array macro */
void helper_rep_set_bool_array(CborEncoder *object, const char* key, bool *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_boolean(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/* Alt implementation of oc_rep_set_double_array macro */
void helper_rep_set_double_array(CborEncoder *object, const char* key, double *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_floating_point(&value_array, CborDoubleType, &values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/* Alt implementation of oc_rep_set_string_array macro */
void helper_rep_rep_set_string_array(CborEncoder *object, const char* key, oc_string_array_t values) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, CborIndefiniteLength);
  int i;
    for (i = 0; i < (int)oc_string_array_get_allocated_size(values); i++) {
      if (oc_string_array_get_item_size(values, i) > 0) {
        g_err |= cbor_encode_text_string(&value_array, oc_string_array_get_item(values, i),
                                         oc_string_array_get_item_size(values, i));
      }
    }
  g_err |= cbor_encoder_close_container(object, &value_array);
}


/*
 * Java only helper function to convert the root CborEncoder object to an oc_rep_t this is needed
 * to enable encode/decode unit testing. This function is not expected to be used in typical
 * use case. It should only be called after calling oc_rep_end_root_object.
 */
oc_rep_t * helper_rep_get_rep_from_root_object() {
  oc_rep_t * rep = (oc_rep_t *)malloc(sizeof(oc_rep_t));
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  oc_parse_rep(payload, payload_len, &rep);
  return rep;
}


int helper_rep_get_cbor_errno() {
  return (int)oc_rep_get_cbor_errno();
}


void helper_rep_clear_cbor_errno() {
  g_err = CborNoError;
}

CborEncoder * helper_rep_open_array(CborEncoder *parent, const char* key) {
  return helper_rep_set_array(parent, key);
}


