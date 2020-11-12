#include "helper.h"
#include "structs.h"
#include "iotivity_lite.h"
#include <chrono>

using namespace std;
using namespace Napi;

struct main_context_t* main_context;

Value OCAceResource::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_ace_res_t>>::New(info.Env(), &m_pvalue);
    return OCAceResourceIterator::constructor.New({ args });
}

Value OCCloudContext::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_cloud_context_t>>::New(info.Env(), &m_pvalue);
    return OCCloudContextIterator::constructor.New({ args });
}

Value OCCollection::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_collection_s>>::New(info.Env(), &m_pvalue);
    return OCCollectionIterator::constructor.New({ args });
}

Value OCEtimer::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_etimer>>::New(info.Env(), &m_pvalue);
    return OCStringArrayIterator::constructor.New({ args });
}

Value OCEventCallback::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_event_callback_s>>::New(info.Env(), &m_pvalue);
    return OCEventCallbackIterator::constructor.New({ args });
}

Value OCLinkParams::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_link_params_t>>::New(info.Env(), &m_pvalue);
    return OCLinkParamsIterator::constructor.New({ args });
}

Value OCLink::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_link_s>>::New(info.Env(), &m_pvalue);
    return OCLinkIterator::constructor.New({ args });
}

Value OCMessage::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_message_s>>::New(info.Env(), &m_pvalue);
    return OCMessageIterator::constructor.New({ args });
}

Value OCRepresentation::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_rep_s>>::New(info.Env(), &m_pvalue);
    return OCRepresentationIterator::constructor.New({ args });
}

Value OCRole::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_role_t>>::New(info.Env(), &m_pvalue);
    return OCRoleIterator::constructor.New({ args });
}

Value OCResourceType::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_rt_t>>::New(info.Env(), &m_pvalue);
    return OCResourceTypeIterator::constructor.New({ args });
}

Value OCSecurityAce::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_sec_ace_t>>::New(info.Env(), &m_pvalue);
    return OCSecurityAceIterator::constructor.New({ args });
}

Value OCSessionEventCb::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_session_event_cb>>::New(info.Env(), &m_pvalue);
    return OCSessionEventCbIterator::constructor.New({ args });
}

Value OCEndpoint::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_endpoint_t>>::New(info.Env(), &m_pvalue);
    return OCEndpointIterator::constructor.New({ args });
}

Value OCStringArray::get_iterator(const CallbackInfo& info)
{
    auto args = External<shared_ptr<oc_string_array_t>>::New(info.Env(), &m_pvalue);
    return OCStringArrayIterator::constructor.New({ args });
}

Value OCCollectionIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCLinkIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCSecurityAceIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCAceResourceIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCCloudContextIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCLinkParamsIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCResourceTypeIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCEtimerIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCEventCallbackIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCMessageIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCRoleIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCBlockwiseStateIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCSessionEventCbIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCRepresentationIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}
Value OCEndpointIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->current = m_pvalue->current->next;
    return info.This();
}

Value OCStringArrayIterator::get_next(const CallbackInfo& info)
{
    m_pvalue->index++;
    return info.This();
}


int helper_oc_handler_init()
{
    Value ret = main_context->oc_handler_init_ref.Call({});
    if (ret.IsNumber()) return ret.As<Number>().Int32Value();
    return 0;
}

void helper_oc_handler_signal_event_loop()
{
    main_context->helper_cv.notify_all();
}

void helper_oc_handler_register_resources()
{
    main_context->oc_handler_register_resources_ref.Call({});
}

void helper_oc_handler_requests_entry()
{
    main_context->oc_handler_requests_entry_ref.Call({});
}

void helper_oc_init_platform_cb(void* param)
{
    printf("oc_init_platform_helper");
    /*
      callback_helper_t* helper = (callback_helper_t*)param;
    //  HandleScope(helper->function.Env());
    //  CallbackScope scope(helper->function.Env(), helper->async_context);
      helper->function.MakeCallback(helper->function.Env().Null(), {helper->value.Value()});
    printf("end oc_init_platform_helper\n");
    */
}

void helper_oc_add_device_cb(void* param)
{
    printf("oc_add_device_helper\n");
//   callback_helper_t* helper = (callback_helper_t*)param;
//   CallbackScope scope(helper->function.Env(), helper->async_context);
//   helper->function.MakeCallback(helper->function.Env().Null(), {helper->value.Value()});
    printf("end oc_add_device_helper\n");
}

void oc_resource_set_properties_cbs_get_helper(oc_resource_t* res, oc_interface_mask_t mask, void* data) { }
bool oc_resource_set_properties_cbs_set_helper(oc_resource_t* res, oc_rep_t* rep, void* data) {
    return true;
}

void helper_oc_resource_set_request_handler(oc_request_t* req, oc_interface_mask_t mask, void* data)
{

}


oc_discovery_flags_t
helper_oc_discovery_handler(const char *di, const char *uri, oc_string_array_t types,
                            oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
                            oc_resource_properties_t bm, void *user_data)
{
    TestHelper* helper = reinterpret_cast<TestHelper*>(user_data);

    auto future = helper->function.call<oc_discovery_flags_t>(
    [&](Env env, vector<napi_value>& args) {
        auto obj = helper->objref.Value().As<Object>();

        auto v = obj.Get("v");

        auto         di_ = String::New(helper->env, di);
        auto        uri_ = String::New(helper->env, uri);
        shared_ptr<oc_string_array_t> types_sp(&types, nop_deleter);
        auto      types_ = OCStringArray::constructor.New({ External<shared_ptr<oc_string_array_t>>::New(helper->env, &types_sp) });
        shared_ptr<oc_endpoint_t> endpoint_sp(endpoint, nop_deleter);
        auto   endpoint_ = OCEndpoint::constructor.New({ External<shared_ptr<oc_endpoint_t>>::New(helper->env, &endpoint_sp) });
        auto iface_mask_ = Number::New(helper->env, iface_mask);
        auto         bm_ = Number::New(helper->env, bm);
        args = {di_, uri_, types_, iface_mask_, endpoint_, bm_, v };
    },
    [&](const Value& val) {
        if (val.IsNumber()) {
            return static_cast<oc_discovery_flags_t>(val.As<Number>().Uint32Value());
        }
        else {
            helper->function.callError("invalid return type");
        }
        return OC_STOP_DISCOVERY;
    });

    try {
        return future.get();
    }
    catch (exception e) {
        helper->function.callError(e.what());
        return OC_STOP_DISCOVERY;
    }
}

oc_discovery_flags_t
helper_oc_discovery_all_handler(const char* di, const char* uri, oc_string_array_t types, oc_interface_mask_t iface_mask,
                                oc_endpoint_t* endpoint, oc_resource_properties_t bm, bool more, void* user_data)
{
    SafeCallbackHelper* helper = reinterpret_cast<SafeCallbackHelper*>(user_data);

    auto future = helper->function.call<oc_discovery_flags_t>(
    [&](Env env, vector<napi_value>& args) {
        auto         di_ = String::New(helper->env, di);
        auto        uri_ = String::New(helper->env, uri);
        shared_ptr<oc_string_array_t> types_sp(&types, nop_deleter);
        auto      types_ = OCStringArray::constructor.New({ External<shared_ptr<oc_string_array_t>>::New(helper->env, &types_sp) });
        shared_ptr<oc_endpoint_t> endpoint_sp(endpoint, nop_deleter);
        auto   endpoint_ = OCEndpoint::constructor.New({ External<shared_ptr<oc_endpoint_t>>::New(helper->env, &endpoint_sp) });
        auto iface_mask_ = Number::New(helper->env, iface_mask);
        auto       more_ = Boolean::New(helper->env, more);
        auto         bm_ = Number::New(helper->env, bm);
        args = { di_, uri_, types_, iface_mask_, endpoint_, bm_, more_, helper->value };
    },
    [&](const Value& val) {
        if (val.IsNumber()) {
            return static_cast<oc_discovery_flags_t>(val.As<Number>().Uint32Value());
        }
        else {
            helper->function.callError("invalid return type");
        }
        return OC_STOP_DISCOVERY;
    });

    try {
        return future.get();
    }
    catch (exception e) {
        helper->function.callError(e.what());
        return OC_STOP_DISCOVERY;
    }
}

void helper_oc_response_handler(oc_client_response_t* response)
{
    SafeCallbackHelper* helper = reinterpret_cast<SafeCallbackHelper*>(response->user_data);
    try {
        helper->function.call(
            [&](Env env, vector<napi_value>& args)
        {
            shared_ptr<oc_client_response_t> sp(response, nop_deleter);
            auto accessor = External<shared_ptr<oc_client_response_t>>::New(helper->env, &sp);
            args = { OCClientResponse::constructor.New({ accessor }) };
        });
    }
    catch (exception e) {
        helper->function.callError(e.what());
    }
}

void helper_oc_ownership_status_cb(const oc_uuid_t* device_uuid,
                                   size_t device_index, bool owned, void* user_data)
{
    SafeCallbackHelper* helper = reinterpret_cast<SafeCallbackHelper*>(user_data);

    try {
        helper->function.call(
            [&](Env env, vector<napi_value>& args)
        {
            shared_ptr<oc_uuid_t> uuid_sp(const_cast<oc_uuid_t*>(device_uuid), nop_deleter);
            auto  device_uuid_ = OCUuid::constructor.New({ External<shared_ptr<oc_uuid_t>>::New(helper->env, &uuid_sp) });
            auto device_index_ = Number::New(helper->env, device_index);
            auto        owned_ = Boolean::New(helper->env, owned);
            args = { device_uuid_, device_index_, owned_, helper->value };
        });
    }
    catch (exception e) {
        helper->function.callError(e.what());
    }
}

oc_event_callback_retval_t helper_oc_trigger(void* data)
{
    SafeCallbackHelper* helper = reinterpret_cast<SafeCallbackHelper*>(data);
    auto future = helper->function.call< oc_event_callback_retval_t>(
                      [&](Env env, vector<napi_value>& args)
    {
        args = { helper->value };
    },
    [&](const Value& val) {
        if (val.IsNumber()) {
            return static_cast<oc_event_callback_retval_t>(val.As<Number>().Uint32Value());
        }
        else {
            helper->function.callError("invalid return type");
        }
        return OC_EVENT_DONE;
    });

    try {
        return future.get();
    }
    catch (exception e) {
        helper->function.callError(e.what());
        return OC_EVENT_DONE;
    }
}

void helper_oc_factory_presets_cb(size_t device, void* data)
{
    SafeCallbackHelper* helper = reinterpret_cast<SafeCallbackHelper*>(data);
    try {
        helper->function.call(
            [&](Env env, vector<napi_value>& args)
        {
            auto device_ = Number::New(helper->env, device);
            args = { device_, helper->value };
        });
    }
    catch (exception e) {
        helper->function.callError(e.what());
    }
}

void helper_oc_random_pin_cb(const unsigned char* pin, size_t pin_len, void* data)
{
    SafeCallbackHelper* helper = reinterpret_cast<SafeCallbackHelper*>(data);

    try {
        helper->function.call(
            [&](Env env, vector<napi_value>& args)
        {
            auto pin_ = Uint8Array::New(helper->env, pin_len);
            for (uint32_t i = 0; i < pin_len; i++)
            {
                pin_[i] = pin[i];
            }
            args = { pin_, helper->value };
        });
    }
    catch (exception e) {
        helper->function.callError(e.what());
    }
}

int oc_swupdate_cb_validate_purl_helper(const char *url)
{
    String Nurl = String::New(main_context->oc_swupdate_cb_validate_purl_ref.Env(), url);
    Value ret = main_context->oc_swupdate_cb_validate_purl_ref.Call({Nurl});
    if(ret.IsNumber()) {
        return ret.As<Number>().Int32Value();
    }
    return 0;
}

int oc_swupdate_cb_check_new_version_helper(size_t device, const char *url, const char *version)
{
    Number Ndevice = Number::New(main_context->oc_swupdate_cb_check_new_version_ref.Env(), device);
    String Nurl = String::New(main_context->oc_swupdate_cb_check_new_version_ref.Env(), url);
    String Nversion = String::New(main_context->oc_swupdate_cb_check_new_version_ref.Env(), version);
    Value ret = main_context->oc_swupdate_cb_check_new_version_ref.Call({Ndevice, Nurl, Nversion});
    if(ret.IsNumber()) {
        return ret.As<Number>().Int32Value();
    }
    return 0;
}

int oc_swupdate_cb_download_update_helper(size_t device, const char *url)
{
    Number Ndevice = Number::New(main_context->oc_swupdate_cb_download_update_ref.Env(), device);
    String Nurl = String::New(main_context->oc_swupdate_cb_download_update_ref.Env(), url);
    Value ret = main_context->oc_swupdate_cb_download_update_ref.Call({Ndevice, Nurl});
    if(ret.IsNumber()) {
        return ret.As<Number>().Int32Value();
    }
    return 0;
}

int oc_swupdate_cb_perform_upgrade_helper(size_t device, const char *url)
{
    Number Ndevice = Number::New(main_context->oc_swupdate_cb_perform_upgrade_ref.Env(), device);
    String Nurl = String::New(main_context->oc_swupdate_cb_perform_upgrade_ref.Env(), url);
    Value ret = main_context->oc_swupdate_cb_perform_upgrade_ref.Call({Ndevice, Nurl});
    if(ret.IsNumber()) {
        return ret.As<Number>().Int32Value();
    }
    return 0;
}


void terminate_main_loop() {
    if (main_context) {
        main_context->helper_cv.notify_all();
        main_context->jni_quit = 1;
    }
}

void helper_poll_event_thread(struct main_context_t* mainctx)
{
    delete main_context;
    main_context = mainctx;

    OC_DBG("inside the JNI jni_poll_event\n");
    oc_clock_time_t next_event;
    while (main_context->jni_quit != 1) {
        OC_DBG("JNI: - lock %s\n", __func__);
        main_context->helper_sync_lock.lock();
        OC_DBG("calling oc_main_poll from JNI code\n");
        next_event = oc_main_poll();
        main_context->helper_sync_lock.unlock();
        OC_DBG("JNI: - unlock %s\n", __func__);

        if (next_event == 0) {
            unique_lock<mutex> helper_cs(main_context->helper_cs_mutex);
            main_context->helper_cv.wait(helper_cs);
        }
        else {
            oc_clock_time_t now = oc_clock_time();
            if (now < next_event) {
                chrono::milliseconds duration((next_event - now) * 1000 / OC_CLOCK_SECOND);
                unique_lock<mutex> helper_cs(main_context->helper_cs_mutex);
                main_context->helper_cv.wait_for(helper_cs, duration);
            }
        }
    }

    OC_DBG("jni_quit\n");
    napi_status status = main_context->tsfn.BlockingCall();
    main_context->tsfn.Release();

    OC_DBG("JNI: - oc_main_shutdown %s", __func__);
    oc_main_shutdown();
    OC_DBG("end oc_main_shutdown");
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


