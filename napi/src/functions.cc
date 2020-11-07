#include "functions.h"
#include "iotivity_lite.h"
#include "helper.h"
Napi::Value N_handle_coap_signal_message(const Napi::CallbackInfo& info) {
  void* packet = info[0];
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  return Napi::Number::New(info.Env(), handle_coap_signal_message(packet, endpoint));
}

#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_add_rt_factory(const Napi::CallbackInfo& info) {
  std::string rt_ = info[0].As<Napi::String>().Utf8Value();
  const char* rt = rt_.c_str();
// 1 get_instance, oc_resource_get_instance_t
// 2 free_instance, oc_resource_free_instance_t
  return Napi::Boolean::New(info.Env(), 0);
}
#endif

Napi::Value N_oc_set_immutable_device_identifier(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  OCUuid& piid = *OCUuid::Unwrap(info[1].As<Napi::Object>());
  (void)oc_set_immutable_device_identifier(device, piid);
  return info.Env().Undefined();
}

Napi::Value N_oc_get_diagnostic_message(const Napi::CallbackInfo& info) {
  OCClientResponse& response = *OCClientResponse::Unwrap(info[0].As<Napi::Object>());
// 1 msg, const char**
  size_t* size = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_get_query_value(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_get_request_payload_raw(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
// 1 payload, const uint8_t**
  size_t* size = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
// 3 content_format, oc_content_format_t*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_get_response_payload_raw(const Napi::CallbackInfo& info) {
  OCClientResponse& response = *OCClientResponse::Unwrap(info[0].As<Napi::Object>());
// 1 payload, const uint8_t**
  size_t* size = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
// 3 content_format, oc_content_format_t*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_init_query_iterator(const Napi::CallbackInfo& info) {
  (void)oc_init_query_iterator();
  return info.Env().Undefined();
}

Napi::Value N_oc_iterate_query(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
// 1 key, char**
  size_t* key_len = reinterpret_cast<size_t*>(info[2].As<Napi::Uint32Array>().Data());
// 3 value, char**
  size_t* value_len = reinterpret_cast<size_t*>(info[4].As<Napi::Uint32Array>().Data());
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_iterate_query_get_values(const Napi::CallbackInfo& info) {
  OCRequest& request = *OCRequest::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, char**
// 3 value_len, int*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_resource_tag_func_desc(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_enum_t func = static_cast<oc_enum_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_func_desc(resource, func);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_pos_desc(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  oc_pos_description_t pos = static_cast<oc_pos_description_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_resource_tag_pos_desc(resource, pos);
  return info.Env().Undefined();
}

Napi::Value N_oc_resource_tag_pos_rel(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  double x = info[1].As<Napi::Number>().DoubleValue();
  double y = info[2].As<Napi::Number>().DoubleValue();
  double z = info[3].As<Napi::Number>().DoubleValue();
  (void)oc_resource_tag_pos_rel(resource, x, y, z);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_expired(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_timer_expired(t));
}

Napi::Value N_oc_timer_remaining(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_timer_remaining(t));
}

Napi::Value N_oc_timer_reset(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  (void)oc_timer_reset(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_restart(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  (void)oc_timer_restart(t);
  return info.Env().Undefined();
}

Napi::Value N_oc_timer_set(const Napi::CallbackInfo& info) {
  OCTimer& t = *OCTimer::Unwrap(info[0].As<Napi::Object>());
  oc_clock_time_t interval = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
  (void)oc_timer_set(t, interval);
  return info.Env().Undefined();
}

Napi::Value N_oc_main_poll(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_main_poll());
}

Napi::Value N_abort_impl(const Napi::CallbackInfo& info) {
  (void)abort_impl();
  return info.Env().Undefined();
}

Napi::Value N_exit_impl(const Napi::CallbackInfo& info) {
  int status = static_cast<int>(info[0].As<Napi::Number>());
  (void)exit_impl(status);
  return info.Env().Undefined();
}

Napi::Value N_oc_abort(const Napi::CallbackInfo& info) {
  std::string msg_ = info[0].As<Napi::String>().Utf8Value();
  const char* msg = msg_.c_str();
  (void)oc_abort(msg);
  return info.Env().Undefined();
}

Napi::Value N_oc_exit(const Napi::CallbackInfo& info) {
  int status = static_cast<int>(info[0].As<Napi::Number>());
  (void)oc_exit(status);
  return info.Env().Undefined();
}

Napi::Value N_oc_base64_decode(const Napi::CallbackInfo& info) {
  uint8_t* str = info[0].As<Napi::Buffer<uint8_t>>().Data();
  size_t len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_base64_decode(str, len));
}

Napi::Value N_oc_base64_encode(const Napi::CallbackInfo& info) {
  const uint8_t* input = info[0].As<Napi::Buffer<const uint8_t>>().Data();
  size_t input_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  uint8_t* output_buffer = info[2].As<Napi::Buffer<uint8_t>>().Data();
  size_t output_buffer_len = static_cast<size_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_base64_encode(input, input_len, output_buffer, output_buffer_len));
}

Napi::Value N_oc_blockwise_alloc_request_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[4].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_alloc_request_buffer(href, href_len, endpoint, method, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_alloc_response_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[4].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_alloc_response_buffer(href, href_len, endpoint, method, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

#if defined(XXX)
Napi::Value N_oc_blockwise_dispatch_block(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  uint32_t block_offset = static_cast<uint32_t>(info[1].As<Napi::Number>().Uint32Value());
  uint32_t requested_block_size = static_cast<uint32_t>(info[2].As<Napi::Number>().Uint32Value());
// 3 payload_size, uint32_t*
  //func return const void*
}
#endif

Napi::Value N_oc_blockwise_find_request_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  std::string query_ = info[4].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[5].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[6].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer(href, href_len, endpoint, method, query, query_len, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_client_cb(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  void* client_cb = info[1];
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer_by_client_cb(endpoint, client_cb));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer_by_mid(mid));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_request_buffer_by_token(const Napi::CallbackInfo& info) {
  uint8_t* token = info[0].As<Napi::Buffer<uint8_t>>().Data();
  uint8_t token_len = static_cast<uint8_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_request_buffer_by_token(token, token_len));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer(const Napi::CallbackInfo& info) {
  std::string href_ = info[0].As<Napi::String>().Utf8Value();
  const char* href = href_.c_str();
  size_t href_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[2].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[3].As<Napi::Number>().Uint32Value());
  std::string query_ = info[4].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[5].As<Napi::Number>().Uint32Value());
  oc_blockwise_role_t role = static_cast<oc_blockwise_role_t>(info[6].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer(href, href_len, endpoint, method, query, query_len, role));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_client_cb(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  void* client_cb = info[1];
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer_by_client_cb(endpoint, client_cb));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer_by_mid(mid));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_find_response_buffer_by_token(const Napi::CallbackInfo& info) {
  uint8_t* token = info[0].As<Napi::Buffer<uint8_t>>().Data();
  uint8_t token_len = static_cast<uint8_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_blockwise_state_t> sp(oc_blockwise_find_response_buffer_by_token(token, token_len));
  auto args = Napi::External<std::shared_ptr<oc_blockwise_state_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({args});
}

Napi::Value N_oc_blockwise_free_request_buffer(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  (void)oc_blockwise_free_request_buffer(buffer);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_free_response_buffer(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  (void)oc_blockwise_free_response_buffer(buffer);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_handle_block(const Napi::CallbackInfo& info) {
  OCBlockwiseState& buffer = *OCBlockwiseState::Unwrap(info[0].As<Napi::Object>());
  uint32_t incoming_block_offset = static_cast<uint32_t>(info[1].As<Napi::Number>().Uint32Value());
  const uint8_t* incoming_block = info[2].As<Napi::Buffer<const uint8_t>>().Data();
  uint32_t incoming_block_size = static_cast<uint32_t>(info[3].As<Napi::Number>().Uint32Value());
  return Napi::Boolean::New(info.Env(), oc_blockwise_handle_block(buffer, incoming_block_offset, incoming_block, incoming_block_size));
}

Napi::Value N_oc_blockwise_scrub_buffers(const Napi::CallbackInfo& info) {
  bool all = info[0].As<Napi::Boolean>().Value();
  (void)oc_blockwise_scrub_buffers(all);
  return info.Env().Undefined();
}

Napi::Value N_oc_blockwise_scrub_buffers_for_client_cb(const Napi::CallbackInfo& info) {
  void* cb = info[0];
  (void)oc_blockwise_scrub_buffers_for_client_cb(cb);
  return info.Env().Undefined();
}

Napi::Value N_oc_allocate_message(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_message_t> sp(oc_allocate_message());
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

Napi::Value N_oc_allocate_message_from_pool(const Napi::CallbackInfo& info) {
  OCMemb& pool = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  std::shared_ptr<oc_message_t> sp(oc_allocate_message_from_pool(pool));
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions(const Napi::CallbackInfo& info) {
  (void)oc_close_all_tls_sessions();
  return info.Env().Undefined();
}
#endif

#if defined(OC_SECURITY)
Napi::Value N_oc_close_all_tls_sessions_for_device(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_close_all_tls_sessions_for_device(device);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_internal_allocate_outgoing_message(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_message_t> sp(oc_internal_allocate_outgoing_message());
  auto args = Napi::External<std::shared_ptr<oc_message_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({args});
}

Napi::Value N_oc_message_add_ref(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_message_add_ref(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_message_unref(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_message_unref(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_recv_message(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_recv_message(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_send_message(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_send_message(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_set_buffers_avail_cb(const Napi::CallbackInfo& info) {
  oc_memb_buffers_avail_callback_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  (void)oc_set_buffers_avail_cb(cb);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_alloc_client_cb(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[2].As<Napi::Number>().Uint32Value());
  std::string query_ = info[3].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
// 4 handler, oc_client_handler_t
  oc_qos_t qos = static_cast<oc_qos_t>(info[5].As<Napi::Number>().Uint32Value());
  void* user_data = info[6];
  std::shared_ptr<oc_client_cb_t> sp(0);
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_find_client_cb_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_find_client_cb_by_mid(mid));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_find_client_cb_by_token(const Napi::CallbackInfo& info) {
  uint8_t* token = info[0].As<Napi::Buffer<uint8_t>>().Data();
  uint8_t token_len = static_cast<uint8_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_find_client_cb_by_token(token, token_len));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_free_client_cbs_by_endpoint(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_ri_free_client_cbs_by_endpoint(endpoint);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_free_client_cbs_by_mid(const Napi::CallbackInfo& info) {
  uint16_t mid = static_cast<uint16_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_ri_free_client_cbs_by_mid(mid);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_get_client_cb(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  oc_method_t method = static_cast<oc_method_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_client_cb_t> sp(oc_ri_get_client_cb(uri, endpoint, method));
  auto args = Napi::External<std::shared_ptr<oc_client_cb_t>>::New(info.Env(), &sp);
  return OCClientCallback::constructor.New({args});
}

Napi::Value N_oc_ri_invoke_client_cb(const Napi::CallbackInfo& info) {
  void* response = info[0];
// 1 response_state, oc_blockwise_state_t**
  OCClientCallback& cb = *OCClientCallback::Unwrap(info[2].As<Napi::Object>());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[3].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_ri_is_client_cb_valid(const Napi::CallbackInfo& info) {
  OCClientCallback& client_cb = *OCClientCallback::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_is_client_cb_valid(client_cb));
}

Napi::Value N_oc_ri_process_discovery_payload(const Napi::CallbackInfo& info) {
  uint8_t* payload = info[0].As<Napi::Buffer<uint8_t>>().Data();
  int len = static_cast<int>(info[1].As<Napi::Number>());
// 2 handler, oc_client_handler_t
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[3].As<Napi::Object>());
  void* user_data = info[4];
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_clock_encode_time_rfc3339(const Napi::CallbackInfo& info) {
  oc_clock_time_t time = static_cast<uint64_t>(info[0].As<Napi::Number>().Int64Value());
  char* out_buf = const_cast<char*>(info[1].As<Napi::String>().Utf8Value().c_str());
  size_t out_buf_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_encode_time_rfc3339(time, out_buf, out_buf_len));
}

Napi::Value N_oc_clock_parse_time_rfc3339(const Napi::CallbackInfo& info) {
  std::string in_buf_ = info[0].As<Napi::String>().Utf8Value();
  const char* in_buf = in_buf_.c_str();
  size_t in_buf_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_parse_time_rfc3339(in_buf, in_buf_len));
}

Napi::Value N_oc_clock_time_rfc3339(const Napi::CallbackInfo& info) {
  char* out_buf = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  size_t out_buf_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_clock_time_rfc3339(out_buf, out_buf_len));
}

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_deregister(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_deregister(ctx, cb, data));
}
#endif

#if defined(OC_CLOUD)
Napi::Value N_oc_cloud_register(const Napi::CallbackInfo& info) {
  OCCloudContext& ctx = *OCCloudContext::Unwrap(info[0].As<Napi::Object>());
  oc_cloud_cb_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  void* data = info[2];
  return Napi::Number::New(info.Env(), oc_cloud_register(ctx, cb, data));
}
#endif

Napi::Value N_oc_check_if_collection(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_check_if_collection(resource));
}

Napi::Value N_oc_collection_add(const Napi::CallbackInfo& info) {
  OCCollection& collection = *OCCollection::Unwrap(info[0].As<Napi::Object>());
  (void)oc_collection_add(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_alloc(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_collection_t> sp(oc_collection_alloc());
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_collection_free(const Napi::CallbackInfo& info) {
  OCCollection& collection = *OCCollection::Unwrap(info[0].As<Napi::Object>());
  (void)oc_collection_free(collection);
  return info.Env().Undefined();
}

Napi::Value N_oc_collection_get_all(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_collection_t> sp(oc_collection_get_all());
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

#if defined(OC_COLLECTIONS_IF_CREATE)
Napi::Value N_oc_collections_free_rt_factories(const Napi::CallbackInfo& info) {
  (void)oc_collections_free_rt_factories();
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_get_collection_by_uri(const Napi::CallbackInfo& info) {
  std::string uri_path_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri_path = uri_path_.c_str();
  size_t uri_path_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_collection_t> sp(oc_get_collection_by_uri(uri_path, uri_path_len, device));
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_get_link_by_uri(const Napi::CallbackInfo& info) {
  OCCollection& collection = *OCCollection::Unwrap(info[0].As<Napi::Object>());
  std::string uri_path_ = info[1].As<Napi::String>().Utf8Value();
  const char* uri_path = uri_path_.c_str();
  int uri_path_len = static_cast<int>(info[2].As<Napi::Number>());
  std::shared_ptr<oc_link_t> sp(oc_get_link_by_uri(collection, uri_path, uri_path_len));
  auto args = Napi::External<std::shared_ptr<oc_link_t>>::New(info.Env(), &sp);
  return OCLink::constructor.New({args});
}

Napi::Value N_oc_get_next_collection_with_link(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  OCCollection& start = *OCCollection::Unwrap(info[1].As<Napi::Object>());
  std::shared_ptr<oc_collection_t> sp(oc_get_next_collection_with_link(resource, start));
  auto args = Napi::External<std::shared_ptr<oc_collection_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({args});
}

Napi::Value N_oc_handle_collection_request(const Napi::CallbackInfo& info) {
  oc_method_t method = static_cast<oc_method_t>(info[0].As<Napi::Number>().Uint32Value());
  OCRequest& request = *OCRequest::Unwrap(info[1].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[2].As<Napi::Number>().Uint32Value());
  OCResource& notify_resource = *OCResource::Unwrap(info[3].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_handle_collection_request(method, request, iface_mask, notify_resource));
}

Napi::Value N_oc_link_set_interfaces(const Napi::CallbackInfo& info) {
  OCLink& link = *OCLink::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t new_interfaces = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_link_set_interfaces(link, new_interfaces);
  return info.Env().Undefined();
}

Napi::Value N_handle_network_interface_event_callback(const Napi::CallbackInfo& info) {
  oc_interface_event_t event = static_cast<oc_interface_event_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)handle_network_interface_event_callback(event);
  return info.Env().Undefined();
}

Napi::Value N_handle_session_event_callback(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  oc_session_state_t state = static_cast<oc_session_state_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)handle_session_event_callback(endpoint, state);
  return info.Env().Undefined();
}

#if defined(OC_TCP)
Napi::Value N_oc_connectivity_end_session(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  (void)oc_connectivity_end_session(endpoint);
  return info.Env().Undefined();
}
#endif

Napi::Value N_oc_connectivity_get_endpoints(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_endpoint_t> sp(oc_connectivity_get_endpoints(device));
  auto args = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({args});
}

Napi::Value N_oc_connectivity_init(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_connectivity_init(device));
}

Napi::Value N_oc_connectivity_shutdown(const Napi::CallbackInfo& info) {
  size_t device = static_cast<size_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_connectivity_shutdown(device);
  return info.Env().Undefined();
}

Napi::Value N_oc_dns_lookup(const Napi::CallbackInfo& info) {
  std::string domain_ = info[0].As<Napi::String>().Utf8Value();
  const char* domain = domain_.c_str();
  OCMmem& addr = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  enum transport_flags flags = static_cast<enum transport_flags>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_dns_lookup(domain, addr, flags));
}

Napi::Value N_oc_send_buffer(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_send_buffer(message));
}

Napi::Value N_oc_send_discovery_request(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_send_discovery_request(message);
  return info.Env().Undefined();
}

#if defined(OC_TCP)
Napi::Value N_oc_tcp_get_csm_state(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_tcp_get_csm_state(endpoint));
}
#endif

#if defined(OC_TCP)
Napi::Value N_oc_tcp_update_csm_state(const Napi::CallbackInfo& info) {
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[0].As<Napi::Object>());
  tcp_csm_state_t csm = static_cast<tcp_csm_state_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_tcp_update_csm_state(endpoint, csm));
}
#endif

Napi::Value N_oc_core_encode_interfaces_mask(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_core_encode_interfaces_mask(parent, iface_mask);
  return info.Env().Undefined();
}

Napi::Value N_oc_core_get_resource_by_index(const Napi::CallbackInfo& info) {
  int type = static_cast<int>(info[0].As<Napi::Number>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_core_get_resource_by_index(type, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_core_populate_resource(const Napi::CallbackInfo& info) {
  int core_resource = static_cast<int>(info[0].As<Napi::Number>());
  size_t device_index = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::string uri_ = info[2].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[3].As<Napi::Number>().Uint32Value());
  oc_interface_mask_t default_interface = static_cast<oc_interface_mask_t>(info[4].As<Napi::Number>().Uint32Value());
  int properties = static_cast<int>(info[5].As<Napi::Number>());
  oc_request_callback_t get_cb = nullptr;
  Napi::Function get_cb_ = info[6].As<Napi::Function>();
  oc_request_callback_t put_cb = nullptr;
  Napi::Function put_cb_ = info[7].As<Napi::Function>();
  oc_request_callback_t post_cb = nullptr;
  Napi::Function post_cb_ = info[8].As<Napi::Function>();
  oc_request_callback_t delete_cb = nullptr;
  Napi::Function delete_cb_ = info[9].As<Napi::Function>();
  int num_resource_types = static_cast<int>(info[10].As<Napi::Number>());
  (void)oc_core_populate_resource(core_resource, device_index, uri, iface_mask, default_interface, properties, get_cb, put_cb, post_cb, delete_cb, num_resource_types);
  return info.Env().Undefined();
}

Napi::Value N_oc_store_uri(const Napi::CallbackInfo& info) {
  std::string s_uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* s_uri = s_uri_.c_str();
  OCMmem& d_uri = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  (void)oc_store_uri(s_uri, d_uri);
  return info.Env().Undefined();
}

Napi::Value N_oc_create_discovery_resource(const Napi::CallbackInfo& info) {
  int resource_idx = static_cast<int>(info[0].As<Napi::Number>());
  size_t device = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)oc_create_discovery_resource(resource_idx, device);
  return info.Env().Undefined();
}

Napi::Value N_oc_endpoint_list_copy(const Napi::CallbackInfo& info) {
// 0 dst, oc_endpoint_t**
  OCEndpoint& src = *OCEndpoint::Unwrap(info[1].As<Napi::Object>());
  (void)0;
  return info.Env().Undefined();
}

Napi::Value N__oc_alloc_string(const Napi::CallbackInfo& info) {
  OCMmem& ocstring = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_alloc_string(ocstring, size);
  return info.Env().Undefined();
}

Napi::Value N__oc_alloc_string_array(const Napi::CallbackInfo& info) {
  OCStringArray& ocstringarray = *OCStringArray::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_alloc_string_array(ocstringarray, size);
  return info.Env().Undefined();
}

Napi::Value N__oc_free_array(const Napi::CallbackInfo& info) {
  OCArray& ocarray = *OCArray::Unwrap(info[0].As<Napi::Object>());
  pool type = static_cast<pool>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_free_array(ocarray, type);
  return info.Env().Undefined();
}

Napi::Value N__oc_free_string(const Napi::CallbackInfo& info) {
  OCMmem& ocstring = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  (void)_oc_free_string(ocstring);
  return info.Env().Undefined();
}

Napi::Value N__oc_new_array(const Napi::CallbackInfo& info) {
  OCArray& ocarray = *OCArray::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  pool type = static_cast<pool>(info[2].As<Napi::Number>().Uint32Value());
  (void)_oc_new_array(ocarray, size, type);
  return info.Env().Undefined();
}

Napi::Value N__oc_new_string(const Napi::CallbackInfo& info) {
  OCMmem& ocstring = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  std::string str_ = info[1].As<Napi::String>().Utf8Value();
  const char* str = str_.c_str();
  size_t str_len = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  (void)_oc_new_string(ocstring, str, str_len);
  return info.Env().Undefined();
}

Napi::Value N_oc_concat_strings(const Napi::CallbackInfo& info) {
  OCMmem& concat = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  std::string str1_ = info[1].As<Napi::String>().Utf8Value();
  const char* str1 = str1_.c_str();
  std::string str2_ = info[2].As<Napi::String>().Utf8Value();
  const char* str2 = str2_.c_str();
  (void)oc_concat_strings(concat, str1, str2);
  return info.Env().Undefined();
}

Napi::Value N_oc_join_string_array(const Napi::CallbackInfo& info) {
  OCStringArray& ocstringarray = *OCStringArray::Unwrap(info[0].As<Napi::Object>());
  OCMmem& ocstring = *OCMmem::Unwrap(info[1].As<Napi::Object>());
  (void)oc_join_string_array(ocstringarray, ocstring);
  return info.Env().Undefined();
}

Napi::Value N_oc_memb_init(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  (void)oc_memb_init(m);
  return info.Env().Undefined();
}

Napi::Value N_oc_memb_inmemb(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  void* ptr = info[1];
  return Napi::Number::New(info.Env(), oc_memb_inmemb(m, ptr));
}

Napi::Value N_oc_memb_numfree(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  return Napi::Number::New(info.Env(), oc_memb_numfree(m));
}

Napi::Value N_oc_memb_set_buffers_avail_cb(const Napi::CallbackInfo& info) {
  OCMemb& m = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  oc_memb_buffers_avail_callback_t cb = nullptr;
  Napi::Function cb_ = info[1].As<Napi::Function>();
  (void)oc_memb_set_buffers_avail_cb(m, cb);
  return info.Env().Undefined();
}

#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_add_pace(const Napi::CallbackInfo& info) {
  std::string func_ = info[0].As<Napi::String>().Utf8Value();
  const char* func = func_.c_str();
  int size = static_cast<int>(info[1].As<Napi::Number>());
  int type = static_cast<int>(info[2].As<Napi::Number>());
  void* address = info[3];
  (void)oc_mem_trace_add_pace(func, size, type, address);
  return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_init(const Napi::CallbackInfo& info) {
  (void)oc_mem_trace_init();
  return info.Env().Undefined();
}
#endif

#if defined(OC_MEMORY_TRACE)
Napi::Value N_oc_mem_trace_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_mem_trace_shutdown();
  return info.Env().Undefined();
}
#endif

Napi::Value N__oc_mmem_alloc(const Napi::CallbackInfo& info) {
  OCMmem& m = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  size_t size = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  pool pool_type = static_cast<pool>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), _oc_mmem_alloc(m, size, pool_type));
}

Napi::Value N__oc_mmem_free(const Napi::CallbackInfo& info) {
  OCMmem& m = *OCMmem::Unwrap(info[0].As<Napi::Object>());
  pool pool_type = static_cast<pool>(info[1].As<Napi::Number>().Uint32Value());
  (void)_oc_mmem_free(m, pool_type);
  return info.Env().Undefined();
}

Napi::Value N_oc_mmem_init(const Napi::CallbackInfo& info) {
  (void)oc_mmem_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event(const Napi::CallbackInfo& info) {
  OCMessage& message = *OCMessage::Unwrap(info[0].As<Napi::Object>());
  (void)oc_network_event(message);
  return info.Env().Undefined();
}

Napi::Value N_oc_network_interface_event(const Napi::CallbackInfo& info) {
  oc_interface_event_t event = static_cast<oc_interface_event_t>(info[0].As<Napi::Number>().Uint32Value());
  (void)oc_network_interface_event(event);
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_destroy(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_destroy();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_init(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_lock(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_lock();
  return info.Env().Undefined();
}

Napi::Value N_oc_network_event_handler_mutex_unlock(const Napi::CallbackInfo& info) {
  (void)oc_network_event_handler_mutex_unlock();
  return info.Env().Undefined();
}

Napi::Value N_oc_add_network_interface_event_callback(const Napi::CallbackInfo& info) {
  interface_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_add_network_interface_event_callback(cb));
}

Napi::Value N_oc_add_session_event_callback(const Napi::CallbackInfo& info) {
  session_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_add_session_event_callback(cb));
}

Napi::Value N_oc_remove_network_interface_event_callback(const Napi::CallbackInfo& info) {
  interface_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_remove_network_interface_event_callback(cb));
}

Napi::Value N_oc_remove_session_event_callback(const Napi::CallbackInfo& info) {
  session_event_handler_t cb = nullptr;
  Napi::Function cb_ = info[0].As<Napi::Function>();
  return Napi::Number::New(info.Env(), oc_remove_session_event_callback(cb));
}

Napi::Value N_oc_free_rep(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  (void)oc_free_rep(rep);
  return info.Env().Undefined();
}

Napi::Value N_oc_parse_rep(const Napi::CallbackInfo& info) {
  const uint8_t* payload = info[0].As<Napi::Buffer<const uint8_t>>().Data();
  int payload_size = static_cast<int>(info[1].As<Napi::Number>());
// 2 value_list, oc_rep_t**
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_encoded_payload_size(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), oc_rep_get_encoded_payload_size());
}

Napi::Value N_oc_rep_get_encoder_buf(const Napi::CallbackInfo& info) {
return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(oc_rep_get_encoder_buf()), oc_rep_get_encoded_payload_size() );
}

Napi::Value N_oc_rep_get_int(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, int64_t*
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_get_int_array(const Napi::CallbackInfo& info) {
  OCRepresentation& rep = *OCRepresentation::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 2 value, int64_t**
  size_t* size = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
  return Napi::Boolean::New(info.Env(), 0);
}

Napi::Value N_oc_rep_new(const Napi::CallbackInfo& info) {
  uint8_t* payload = info[0].As<Napi::Buffer<uint8_t>>().Data();
  int size = static_cast<int>(info[1].As<Napi::Number>());
  (void)oc_rep_new(payload, size);
  return info.Env().Undefined();
}

Napi::Value N_oc_rep_set_pool(const Napi::CallbackInfo& info) {
  OCMemb& rep_objects_pool = *OCMemb::Unwrap(info[0].As<Napi::Object>());
  (void)oc_rep_set_pool(rep_objects_pool);
  return info.Env().Undefined();
}

#if defined(OC_SERVER)
Napi::Value N_oc_ri_add_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_add_resource(resource));
}
#endif

Napi::Value N_oc_ri_add_timed_event_callback_ticks(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t event_callback = nullptr;
  Napi::Function event_callback_ = info[1].As<Napi::Function>();
  oc_clock_time_t ticks = static_cast<uint64_t>(info[2].As<Napi::Number>().Int64Value());
  (void)oc_ri_add_timed_event_callback_ticks(cb_data, event_callback, ticks);
  return info.Env().Undefined();
}

#if defined(OC_SERVER)
Napi::Value N_oc_ri_alloc_resource(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_ri_alloc_resource());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}
#endif

#if defined(OC_SERVER)
Napi::Value N_oc_ri_delete_resource(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  return Napi::Boolean::New(info.Env(), oc_ri_delete_resource(resource));
}
#endif

Napi::Value N_oc_ri_free_resource_properties(const Napi::CallbackInfo& info) {
  OCResource& resource = *OCResource::Unwrap(info[0].As<Napi::Object>());
  (void)oc_ri_free_resource_properties(resource);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_get_app_resource_by_uri(const Napi::CallbackInfo& info) {
  std::string uri_ = info[0].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
  size_t uri_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  size_t device = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  std::shared_ptr<oc_resource_t> sp(oc_ri_get_app_resource_by_uri(uri, uri_len, device));
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_ri_get_app_resources(const Napi::CallbackInfo& info) {
  std::shared_ptr<oc_resource_t> sp(oc_ri_get_app_resources());
  auto args = Napi::External<std::shared_ptr<oc_resource_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({args});
}

Napi::Value N_oc_ri_get_interface_mask(const Napi::CallbackInfo& info) {
  char* iface = const_cast<char*>(info[0].As<Napi::String>().Utf8Value().c_str());
  size_t if_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_ri_get_interface_mask(iface, if_len));
}

Napi::Value N_oc_ri_get_query_nth_key_value(const Napi::CallbackInfo& info) {
  std::string query_ = info[0].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
// 2 key, char**
  size_t* key_len = reinterpret_cast<size_t*>(info[3].As<Napi::Uint32Array>().Data());
// 4 value, char**
  size_t* value_len = reinterpret_cast<size_t*>(info[5].As<Napi::Uint32Array>().Data());
  size_t n = static_cast<size_t>(info[6].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_ri_get_query_value(const Napi::CallbackInfo& info) {
  std::string query_ = info[0].As<Napi::String>().Utf8Value();
  const char* query = query_.c_str();
  size_t query_len = static_cast<size_t>(info[1].As<Napi::Number>().Uint32Value());
  std::string key_ = info[2].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
// 3 value, char**
  return Napi::Number::New(info.Env(), 0);
}

Napi::Value N_oc_ri_init(const Napi::CallbackInfo& info) {
  (void)oc_ri_init();
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_remove_timed_event_callback(const Napi::CallbackInfo& info) {
  void* cb_data = info[0];
  oc_trigger_t event_callback = nullptr;
  Napi::Function event_callback_ = info[1].As<Napi::Function>();
  (void)oc_ri_remove_timed_event_callback(cb_data, event_callback);
  return info.Env().Undefined();
}

Napi::Value N_oc_ri_shutdown(const Napi::CallbackInfo& info) {
  (void)oc_ri_shutdown();
  return info.Env().Undefined();
}

Napi::Value N_oc_status_code(const Napi::CallbackInfo& info) {
  oc_status_t key = static_cast<oc_status_t>(info[0].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_status_code(key));
}

Napi::Value N__oc_signal_event_loop(const Napi::CallbackInfo& info) {
  (void)_oc_signal_event_loop();
  return info.Env().Undefined();
}

Napi::Value N_oc_storage_read(const Napi::CallbackInfo& info) {
  std::string store_ = info[0].As<Napi::String>().Utf8Value();
  const char* store = store_.c_str();
  uint8_t* buf = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_storage_read(store, buf, size));
}

Napi::Value N_oc_storage_write(const Napi::CallbackInfo& info) {
  std::string store_ = info[0].As<Napi::String>().Utf8Value();
  const char* store = store_.c_str();
  uint8_t* buf = info[1].As<Napi::Buffer<uint8_t>>().Data();
  size_t size = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
  return Napi::Number::New(info.Env(), oc_storage_write(store, buf, size));
}

Napi::Value N_helper_rep_add_int(const Napi::CallbackInfo& info) {
  OCCborEncoder& arrayObject = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  const int64_t value = static_cast<const int64_t>(info[1].As<Napi::Number>());
  (void)helper_rep_add_int(arrayObject, value);
  return info.Env().Undefined();
}

Napi::Value N_helper_rep_set_array(const Napi::CallbackInfo& info) {
  OCCborEncoder& parent = *OCCborEncoder::Unwrap(info[0].As<Napi::Object>());
  std::string key_ = info[1].As<Napi::String>().Utf8Value();
  const char* key = key_.c_str();
  std::shared_ptr<CborEncoder> sp(helper_rep_set_array(parent, key));
  auto args = Napi::External<std::shared_ptr<CborEncoder>>::New(info.Env(), &sp);
  return OCCborEncoder::constructor.New({args});
}

Napi::Value N_helper_rep_get_cbor_errno(const Napi::CallbackInfo& info) {
  return Napi::Number::New(info.Env(), helper_rep_get_cbor_errno());
}

Napi::Value N_helper_oc_do_ip_discovery(const Napi::CallbackInfo& info) {
  std::string di_ = info[0].As<Napi::String>().Utf8Value();
  const char* di = di_.c_str();
  std::string uri_ = info[1].As<Napi::String>().Utf8Value();
  const char* uri = uri_.c_str();
// 2 types, oc_string_array_t
  oc_interface_mask_t iface_mask = static_cast<oc_interface_mask_t>(info[3].As<Napi::Number>().Uint32Value());
  OCEndpoint& endpoint = *OCEndpoint::Unwrap(info[4].As<Napi::Object>());
  oc_resource_properties_t bm = static_cast<oc_resource_properties_t>(info[5].As<Napi::Number>().Uint32Value());
  void* user_data = info[6];
  return Napi::Number::New(info.Env(), 0);
}

