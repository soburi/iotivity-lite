#include "structs.h"
Napi::Function OCAceRes::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceRes", {
    OCAceRes::InstanceAccessor("href", &OCAceRes::get_href, &OCAceRes::set_href),
    OCAceRes::InstanceAccessor("interfaces", &OCAceRes::get_interfaces, &OCAceRes::set_interfaces),
    OCAceRes::InstanceAccessor("types", &OCAceRes::get_types, &OCAceRes::set_types),
    OCAceRes::InstanceAccessor("wildcard", &OCAceRes::get_wildcard, &OCAceRes::set_wildcard),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAceRes::OCAceRes(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ace_res_t>(new oc_ace_res_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ace_res_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCAceRes::get_href(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->href);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCAceRes::constructor.New({accessor});
}

void OCAceRes::set_href(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->href = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCAceRes::get_interfaces(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interfaces);
}

void OCAceRes::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCAceRes::get_types(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->types);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCAceRes::constructor.New({accessor});
}

void OCAceRes::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCAceRes::get_wildcard(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->wildcard);
}

void OCAceRes::set_wildcard(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->wildcard = static_cast<oc_ace_wildcard_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCBlockwiseRequestState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseRequestState", {
    OCBlockwiseRequestState::InstanceAccessor("base", &OCBlockwiseRequestState::get_base, &OCBlockwiseRequestState::set_base),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCBlockwiseRequestState::OCBlockwiseRequestState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_blockwise_request_state_s>(new oc_blockwise_request_state_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_blockwise_request_state_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCBlockwiseRequestState::get_base(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_blockwise_state_s> sp(&m_pvalue->base);
  auto accessor = Napi::External<std::shared_ptr<oc_blockwise_state_s>>::New(info.Env(), &sp);
  return OCBlockwiseRequestState::constructor.New({accessor});
}

void OCBlockwiseRequestState::set_base(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->base = *(*(value.As<Napi::External<std::shared_ptr<oc_blockwise_state_s>>>().Data()));
}

Napi::Function OCBlockwiseResponseState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseResponseState", {
    OCBlockwiseResponseState::InstanceAccessor("base", &OCBlockwiseResponseState::get_base, &OCBlockwiseResponseState::set_base),
    OCBlockwiseResponseState::InstanceAccessor("etag", &OCBlockwiseResponseState::get_etag, &OCBlockwiseResponseState::set_etag),
    OCBlockwiseResponseState::InstanceAccessor("observe_seq", &OCBlockwiseResponseState::get_observe_seq, &OCBlockwiseResponseState::set_observe_seq),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCBlockwiseResponseState::OCBlockwiseResponseState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_blockwise_response_state_s>(new oc_blockwise_response_state_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_blockwise_response_state_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCBlockwiseResponseState::get_base(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_blockwise_state_s> sp(&m_pvalue->base);
  auto accessor = Napi::External<std::shared_ptr<oc_blockwise_state_s>>::New(info.Env(), &sp);
  return OCBlockwiseResponseState::constructor.New({accessor});
}

void OCBlockwiseResponseState::set_base(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->base = *(*(value.As<Napi::External<std::shared_ptr<oc_blockwise_state_s>>>().Data()));
}

Napi::Value OCBlockwiseResponseState::get_etag(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->etag, COAP_ETAG_LEN);
}

void OCBlockwiseResponseState::set_etag(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<COAP_ETAG_LEN; i++) { m_pvalue->etag[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}

#ifdef OC_CLIENT
Napi::Value OCBlockwiseResponseState::get_observe_seq(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_seq);
}

void OCBlockwiseResponseState::set_observe_seq(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_seq = value.As<Napi::Number>().Int32Value();
}
#endif

Napi::Function OCBlockwiseState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseState", {
    OCBlockwiseState::InstanceAccessor("buffer", &OCBlockwiseState::get_buffer, &OCBlockwiseState::set_buffer),
    OCBlockwiseState::InstanceAccessor("client_cb", &OCBlockwiseState::get_client_cb, &OCBlockwiseState::set_client_cb),
    OCBlockwiseState::InstanceAccessor("endpoint", &OCBlockwiseState::get_endpoint, &OCBlockwiseState::set_endpoint),
    OCBlockwiseState::InstanceAccessor("href", &OCBlockwiseState::get_href, &OCBlockwiseState::set_href),
    OCBlockwiseState::InstanceAccessor("method", &OCBlockwiseState::get_method, &OCBlockwiseState::set_method),
    OCBlockwiseState::InstanceAccessor("mid", &OCBlockwiseState::get_mid, &OCBlockwiseState::set_mid),
    OCBlockwiseState::InstanceAccessor("next_block_offset", &OCBlockwiseState::get_next_block_offset, &OCBlockwiseState::set_next_block_offset),
    OCBlockwiseState::InstanceAccessor("payload_size", &OCBlockwiseState::get_payload_size, &OCBlockwiseState::set_payload_size),
    OCBlockwiseState::InstanceAccessor("ref_count", &OCBlockwiseState::get_ref_count, &OCBlockwiseState::set_ref_count),
    OCBlockwiseState::InstanceAccessor("role", &OCBlockwiseState::get_role, &OCBlockwiseState::set_role),
    OCBlockwiseState::InstanceAccessor("token", &OCBlockwiseState::get_token, &OCBlockwiseState::set_token),
    OCBlockwiseState::InstanceAccessor("token_len", &OCBlockwiseState::get_token_len, &OCBlockwiseState::set_token_len),
    OCBlockwiseState::InstanceAccessor("uri_query", &OCBlockwiseState::get_uri_query, &OCBlockwiseState::set_uri_query),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCBlockwiseState::OCBlockwiseState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_blockwise_state_s>(new oc_blockwise_state_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_blockwise_state_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCBlockwiseState::get_buffer(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, OC_MAX_APP_DATA_SIZE);
}

void OCBlockwiseState::set_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->buffer[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}

#ifdef OC_CLEINT
Napi::Value OCBlockwiseState::get_client_cb(const Napi::CallbackInfo& info)
{
#error void* OCBlockwiseState::client_cb
}

void OCBlockwiseState::set_client_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
#error void* OCBlockwiseState::client_cb
}
#endif

Napi::Value OCBlockwiseState::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({accessor});
}

void OCBlockwiseState::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value OCBlockwiseState::get_href(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->href);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({accessor});
}

void OCBlockwiseState::set_href(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->href = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCBlockwiseState::get_method(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->method);
}

void OCBlockwiseState::set_method(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->method = static_cast<oc_method_t>(value.As<Napi::Number>().Uint32Value());
}

#ifdef OC_CLIENT
Napi::Value OCBlockwiseState::get_mid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->mid);
}

void OCBlockwiseState::set_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mid = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCBlockwiseState::get_next_block_offset(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->next_block_offset);
}

void OCBlockwiseState::set_next_block_offset(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->next_block_offset = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value OCBlockwiseState::get_payload_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->payload_size);
}

void OCBlockwiseState::set_payload_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->payload_size = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value OCBlockwiseState::get_ref_count(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->ref_count);
}

void OCBlockwiseState::set_ref_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ref_count = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCBlockwiseState::get_role(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->role);
}

void OCBlockwiseState::set_role(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->role = static_cast<oc_blockwise_role_t>(value.As<Napi::Number>().Uint32Value());
}

#ifdef OC_CLIENT
Napi::Value OCBlockwiseState::get_token(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);
}

void OCBlockwiseState::set_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) { m_pvalue->token[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}
#endif

#ifdef OC_CLIENT
Napi::Value OCBlockwiseState::get_token_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->token_len);
}

void OCBlockwiseState::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->token_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCBlockwiseState::get_uri_query(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri_query);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCBlockwiseState::constructor.New({accessor});
}

void OCBlockwiseState::set_uri_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri_query = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCClientCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCClientCb", {
    OCClientCb::InstanceAccessor("discovery", &OCClientCb::get_discovery, &OCClientCb::set_discovery),
    OCClientCb::InstanceAccessor("handler", &OCClientCb::get_handler, &OCClientCb::set_handler),
    OCClientCb::InstanceAccessor("method", &OCClientCb::get_method, &OCClientCb::set_method),
    OCClientCb::InstanceAccessor("mid", &OCClientCb::get_mid, &OCClientCb::set_mid),
    OCClientCb::InstanceAccessor("multicast", &OCClientCb::get_multicast, &OCClientCb::set_multicast),
    OCClientCb::InstanceAccessor("observe_seq", &OCClientCb::get_observe_seq, &OCClientCb::set_observe_seq),
    OCClientCb::InstanceAccessor("qos", &OCClientCb::get_qos, &OCClientCb::set_qos),
    OCClientCb::InstanceAccessor("query", &OCClientCb::get_query, &OCClientCb::set_query),
    OCClientCb::InstanceAccessor("ref_count", &OCClientCb::get_ref_count, &OCClientCb::set_ref_count),
    OCClientCb::InstanceAccessor("separate", &OCClientCb::get_separate, &OCClientCb::set_separate),
    OCClientCb::InstanceAccessor("stop_multicast_receive", &OCClientCb::get_stop_multicast_receive, &OCClientCb::set_stop_multicast_receive),
    OCClientCb::InstanceAccessor("timestamp", &OCClientCb::get_timestamp, &OCClientCb::set_timestamp),
    OCClientCb::InstanceAccessor("token", &OCClientCb::get_token, &OCClientCb::set_token),
    OCClientCb::InstanceAccessor("token_len", &OCClientCb::get_token_len, &OCClientCb::set_token_len),
    OCClientCb::InstanceAccessor("uri", &OCClientCb::get_uri, &OCClientCb::set_uri),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCClientCb::OCClientCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_client_cb_t>(new oc_client_cb_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_client_cb_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCClientCb::get_discovery(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->discovery);
}

void OCClientCb::set_discovery(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->discovery = value.As<Napi::Boolean>().Value();
}

Napi::Value OCClientCb::get_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_client_handler_t> sp(&m_pvalue->handler);
  auto accessor = Napi::External<std::shared_ptr<oc_client_handler_t>>::New(info.Env(), &sp);
  return OCClientCb::constructor.New({accessor});
}

void OCClientCb::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->handler = *(*(value.As<Napi::External<std::shared_ptr<oc_client_handler_t>>>().Data()));
}

Napi::Value OCClientCb::get_method(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->method);
}

void OCClientCb::set_method(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->method = static_cast<oc_method_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_mid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->mid);
}

void OCClientCb::set_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mid = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_multicast(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->multicast);
}

void OCClientCb::set_multicast(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->multicast = value.As<Napi::Boolean>().Value();
}

Napi::Value OCClientCb::get_observe_seq(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_seq);
}

void OCClientCb::set_observe_seq(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_seq = value.As<Napi::Number>().Int32Value();
}

Napi::Value OCClientCb::get_qos(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->qos);
}

void OCClientCb::set_qos(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->qos = static_cast<oc_qos_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_query(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->query);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCClientCb::constructor.New({accessor});
}

void OCClientCb::set_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->query = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCClientCb::get_ref_count(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->ref_count);
}

void OCClientCb::set_ref_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ref_count = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_separate(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->separate);
}

void OCClientCb::set_separate(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->separate = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_stop_multicast_receive(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->stop_multicast_receive);
}

void OCClientCb::set_stop_multicast_receive(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->stop_multicast_receive = value.As<Napi::Boolean>().Value();
}

Napi::Value OCClientCb::get_timestamp(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->timestamp);
}

void OCClientCb::set_timestamp(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->timestamp = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_token(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);
}

void OCClientCb::set_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) { m_pvalue->token[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}

Napi::Value OCClientCb::get_token_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->token_len);
}

void OCClientCb::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->token_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCb::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCClientCb::constructor.New({accessor});
}

void OCClientCb::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCClientHandler::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCClientHandler", {
    OCClientHandler::InstanceAccessor("discovery", &OCClientHandler::get_discovery, &OCClientHandler::set_discovery),
    OCClientHandler::InstanceAccessor("discovery_all", &OCClientHandler::get_discovery_all, &OCClientHandler::set_discovery_all),
    OCClientHandler::InstanceAccessor("response", &OCClientHandler::get_response, &OCClientHandler::set_response),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCClientHandler::OCClientHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_client_handler_t>(new oc_client_handler_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_client_handler_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCClientHandler::get_discovery(const Napi::CallbackInfo& info)
{
return discovery_function;
}

void OCClientHandler::set_discovery(const Napi::CallbackInfo& info, const Napi::Value& value)
{
discovery_function = value;
}

Napi::Value OCClientHandler::get_discovery_all(const Napi::CallbackInfo& info)
{
return discovery_all_function;
}

void OCClientHandler::set_discovery_all(const Napi::CallbackInfo& info, const Napi::Value& value)
{
discovery_all_function = value;
}

Napi::Value OCClientHandler::get_response(const Napi::CallbackInfo& info)
{
return response_function;
}

void OCClientHandler::set_response(const Napi::CallbackInfo& info, const Napi::Value& value)
{
response_function = value;
}

Napi::Function OCClientResponse::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCClientResponse", {
    OCClientResponse::InstanceAccessor("code", &OCClientResponse::get_code, &OCClientResponse::set_code),
    OCClientResponse::InstanceAccessor("content_format", &OCClientResponse::get_content_format, &OCClientResponse::set_content_format),
    OCClientResponse::InstanceAccessor("observe_option", &OCClientResponse::get_observe_option, &OCClientResponse::set_observe_option),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCClientResponse::OCClientResponse(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_client_response_t>(new oc_client_response_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_client_response_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCClientResponse::get_code(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->code);
}

void OCClientResponse::set_code(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->code = static_cast<oc_status_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientResponse::get_content_format(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->content_format);
}

void OCClientResponse::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->content_format = static_cast<oc_content_format_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientResponse::get_observe_option(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_option);
}

void OCClientResponse::set_observe_option(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_option = static_cast<int>(value.As<Napi::Number>());
}

Napi::Function OCCloudContext::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudContext", {
    OCCloudContext::InstanceAccessor("callback", &OCCloudContext::get_callback, &OCCloudContext::set_callback),
    OCCloudContext::InstanceAccessor("cloud_manager", &OCCloudContext::get_cloud_manager, &OCCloudContext::set_cloud_manager),
    OCCloudContext::InstanceAccessor("device", &OCCloudContext::get_device, &OCCloudContext::set_device),
    OCCloudContext::InstanceAccessor("expires_in", &OCCloudContext::get_expires_in, &OCCloudContext::set_expires_in),
    OCCloudContext::InstanceAccessor("last_error", &OCCloudContext::get_last_error, &OCCloudContext::set_last_error),
    OCCloudContext::InstanceAccessor("rd_delete_all", &OCCloudContext::get_rd_delete_all, &OCCloudContext::set_rd_delete_all),
    OCCloudContext::InstanceAccessor("retry_count", &OCCloudContext::get_retry_count, &OCCloudContext::set_retry_count),
    OCCloudContext::InstanceAccessor("retry_refresh_token_count", &OCCloudContext::get_retry_refresh_token_count, &OCCloudContext::set_retry_refresh_token_count),
    OCCloudContext::InstanceAccessor("store", &OCCloudContext::get_store, &OCCloudContext::set_store),
    OCCloudContext::InstanceAccessor("user_data", &OCCloudContext::get_user_data, &OCCloudContext::set_user_data),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCloudContext::OCCloudContext(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_cloud_context_t>(new oc_cloud_context_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_cloud_context_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCloudContext::get_callback(const Napi::CallbackInfo& info)
{
  return callback_function;
}

void OCCloudContext::set_callback(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  callback_function = value;
}

Napi::Value OCCloudContext::get_cloud_manager(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->cloud_manager);
}

void OCCloudContext::set_cloud_manager(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->cloud_manager = value.As<Napi::Boolean>().Value();
}

Napi::Value OCCloudContext::get_device(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->device);
}

void OCCloudContext::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->device = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudContext::get_expires_in(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->expires_in);
}

void OCCloudContext::set_expires_in(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->expires_in = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudContext::get_last_error(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->last_error);
}

void OCCloudContext::set_last_error(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->last_error = static_cast<oc_cloud_error_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudContext::get_rd_delete_all(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->rd_delete_all);
}

void OCCloudContext::set_rd_delete_all(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rd_delete_all = value.As<Napi::Boolean>().Value();
}

Napi::Value OCCloudContext::get_retry_count(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->retry_count);
}

void OCCloudContext::set_retry_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->retry_count = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudContext::get_retry_refresh_token_count(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->retry_refresh_token_count);
}

void OCCloudContext::set_retry_refresh_token_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->retry_refresh_token_count = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudContext::get_store(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_cloud_store_t> sp(&m_pvalue->store);
  auto accessor = Napi::External<std::shared_ptr<oc_cloud_store_t>>::New(info.Env(), &sp);
  return OCCloudContext::constructor.New({accessor});
}

void OCCloudContext::set_store(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->store = *(*(value.As<Napi::External<std::shared_ptr<oc_cloud_store_t>>>().Data()));
}

Napi::Value OCCloudContext::get_user_data(const Napi::CallbackInfo& info)
{
return callback_data;
}

void OCCloudContext::set_user_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
callback_data = value;
}

Napi::Function OCCloudStore::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudStore", {
    OCCloudStore::InstanceAccessor("access_token", &OCCloudStore::get_access_token, &OCCloudStore::set_access_token),
    OCCloudStore::InstanceAccessor("auth_provider", &OCCloudStore::get_auth_provider, &OCCloudStore::set_auth_provider),
    OCCloudStore::InstanceAccessor("ci_server", &OCCloudStore::get_ci_server, &OCCloudStore::set_ci_server),
    OCCloudStore::InstanceAccessor("cps", &OCCloudStore::get_cps, &OCCloudStore::set_cps),
    OCCloudStore::InstanceAccessor("device", &OCCloudStore::get_device, &OCCloudStore::set_device),
    OCCloudStore::InstanceAccessor("refresh_token", &OCCloudStore::get_refresh_token, &OCCloudStore::set_refresh_token),
    OCCloudStore::InstanceAccessor("sid", &OCCloudStore::get_sid, &OCCloudStore::set_sid),
    OCCloudStore::InstanceAccessor("status", &OCCloudStore::get_status, &OCCloudStore::set_status),
    OCCloudStore::InstanceAccessor("uid", &OCCloudStore::get_uid, &OCCloudStore::set_uid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCloudStore::OCCloudStore(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_cloud_store_t>(new oc_cloud_store_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_cloud_store_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCloudStore::get_access_token(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->access_token);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCloudStore::constructor.New({accessor});
}

void OCCloudStore::set_access_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->access_token = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_auth_provider(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->auth_provider);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCloudStore::constructor.New({accessor});
}

void OCCloudStore::set_auth_provider(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->auth_provider = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_ci_server(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->ci_server);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCloudStore::constructor.New({accessor});
}

void OCCloudStore::set_ci_server(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ci_server = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_cps(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->cps);
}

void OCCloudStore::set_cps(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->cps = static_cast<oc_cps_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudStore::get_device(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->device);
}

void OCCloudStore::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->device = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudStore::get_refresh_token(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->refresh_token);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCloudStore::constructor.New({accessor});
}

void OCCloudStore::set_refresh_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->refresh_token = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_sid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->sid);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCloudStore::constructor.New({accessor});
}

void OCCloudStore::set_sid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->sid = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_status(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->status);
}

void OCCloudStore::set_status(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->status = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCloudStore::get_uid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uid);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCloudStore::constructor.New({accessor});
}

void OCCloudStore::set_uid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uid = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCCollection::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCollection", {
    OCCollection::InstanceAccessor("default_interface", &OCCollection::get_default_interface, &OCCollection::set_default_interface),
    OCCollection::InstanceAccessor("delete_handler", &OCCollection::get_delete_handler, &OCCollection::set_delete_handler),
    OCCollection::InstanceAccessor("device", &OCCollection::get_device, &OCCollection::set_device),
    OCCollection::InstanceAccessor("get_handler", &OCCollection::get_get_handler, &OCCollection::set_get_handler),
    OCCollection::InstanceAccessor("get_properties", &OCCollection::get_get_properties, &OCCollection::set_get_properties),
    OCCollection::InstanceAccessor("interfaces", &OCCollection::get_interfaces, &OCCollection::set_interfaces),
    OCCollection::InstanceAccessor("name", &OCCollection::get_name, &OCCollection::set_name),
    OCCollection::InstanceAccessor("num_links", &OCCollection::get_num_links, &OCCollection::set_num_links),
    OCCollection::InstanceAccessor("num_observers", &OCCollection::get_num_observers, &OCCollection::set_num_observers),
    OCCollection::InstanceAccessor("post_handler", &OCCollection::get_post_handler, &OCCollection::set_post_handler),
    OCCollection::InstanceAccessor("properties", &OCCollection::get_properties, &OCCollection::set_properties),
    OCCollection::InstanceAccessor("put_handler", &OCCollection::get_put_handler, &OCCollection::set_put_handler),
    OCCollection::InstanceAccessor("set_properties", &OCCollection::get_set_properties, &OCCollection::set_set_properties),
    OCCollection::InstanceAccessor("tag_pos_desc", &OCCollection::get_tag_pos_desc, &OCCollection::set_tag_pos_desc),
    OCCollection::InstanceAccessor("tag_pos_func", &OCCollection::get_tag_pos_func, &OCCollection::set_tag_pos_func),
    OCCollection::InstanceAccessor("tag_pos_rel", &OCCollection::get_tag_pos_rel, &OCCollection::set_tag_pos_rel),
    OCCollection::InstanceAccessor("types", &OCCollection::get_types, &OCCollection::set_types),
    OCCollection::InstanceAccessor("uri", &OCCollection::get_uri, &OCCollection::set_uri),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCollection::OCCollection(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_collection_s>(new oc_collection_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_collection_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCollection::get_default_interface(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->default_interface);
}

void OCCollection::set_default_interface(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->default_interface = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_delete_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->delete_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_delete_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->delete_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_device(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->device);
}

void OCCollection::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->device = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_get_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->get_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_get_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_get_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_properties = *(*(value.As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCCollection::get_interfaces(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interfaces);
}

void OCCollection::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCollection::get_num_links(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num_links);
}

void OCCollection::set_num_links(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num_links = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_num_observers(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num_observers);
}

void OCCollection::set_num_observers(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num_observers = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_post_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->post_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_post_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->post_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_properties(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->properties);
}

void OCCollection::set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->properties = static_cast<oc_resource_properties_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_put_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->put_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->put_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_set_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->set_properties = *(*(value.As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCCollection::get_tag_pos_desc(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->tag_pos_desc);
}

void OCCollection::set_tag_pos_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->tag_pos_desc = static_cast<oc_pos_description_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_tag_pos_func(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->tag_pos_func);
}

void OCCollection::set_tag_pos_func(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->tag_pos_func = static_cast<oc_enum_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCCollection::get_tag_pos_rel(const Napi::CallbackInfo& info)
{
auto array = Napi::Float64Array::New(info.Env(), 3);
array[0] = m_pvalue->tag_pos_rel[0];
array[1] = m_pvalue->tag_pos_rel[1];
array[2] = m_pvalue->tag_pos_rel[2];
}

void OCCollection::set_tag_pos_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->tag_pos_rel[0] = value.As<Napi::Float64Array>()[0];
m_pvalue->tag_pos_rel[1] = value.As<Napi::Float64Array>()[1];
m_pvalue->tag_pos_rel[2] = value.As<Napi::Float64Array>()[2];
}

Napi::Value OCCollection::get_types(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->types);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCollection::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCollection::constructor.New({accessor});
}

void OCCollection::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCCredData::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCredData", {
    OCCredData::InstanceAccessor("data", &OCCredData::get_data, &OCCredData::set_data),
    OCCredData::InstanceAccessor("encoding", &OCCredData::get_encoding, &OCCredData::set_encoding),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCredData::OCCredData(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_cred_data_t>(new oc_cred_data_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_cred_data_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCredData::get_data(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->data);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCCredData::constructor.New({accessor});
}

void OCCredData::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->data = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCredData::get_encoding(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->encoding);
}

void OCCredData::set_encoding(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->encoding = static_cast<oc_sec_encoding_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCDeviceInfo::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCDeviceInfo", {
    OCDeviceInfo::InstanceAccessor("add_device_cb", &OCDeviceInfo::get_add_device_cb, &OCDeviceInfo::set_add_device_cb),
    OCDeviceInfo::InstanceAccessor("data", &OCDeviceInfo::get_data, &OCDeviceInfo::set_data),
    OCDeviceInfo::InstanceAccessor("di", &OCDeviceInfo::get_di, &OCDeviceInfo::set_di),
    OCDeviceInfo::InstanceAccessor("dmv", &OCDeviceInfo::get_dmv, &OCDeviceInfo::set_dmv),
    OCDeviceInfo::InstanceAccessor("icv", &OCDeviceInfo::get_icv, &OCDeviceInfo::set_icv),
    OCDeviceInfo::InstanceAccessor("name", &OCDeviceInfo::get_name, &OCDeviceInfo::set_name),
    OCDeviceInfo::InstanceAccessor("piid", &OCDeviceInfo::get_piid, &OCDeviceInfo::set_piid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCDeviceInfo::OCDeviceInfo(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_device_info_t>(new oc_device_info_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_device_info_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCDeviceInfo::get_add_device_cb(const Napi::CallbackInfo& info)
{
  return add_device_cb_function;
}

void OCDeviceInfo::set_add_device_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  add_device_cb_function = value;
}

Napi::Value OCDeviceInfo::get_data(const Napi::CallbackInfo& info)
{
return add_device_cb_data;
}

void OCDeviceInfo::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
add_device_cb_data = value;
}

Napi::Value OCDeviceInfo::get_di(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->di);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({accessor});
}

void OCDeviceInfo::set_di(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->di = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Value OCDeviceInfo::get_dmv(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->dmv);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({accessor});
}

void OCDeviceInfo::set_dmv(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->dmv = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_icv(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->icv);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({accessor});
}

void OCDeviceInfo::set_icv(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->icv = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({accessor});
}

void OCDeviceInfo::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_piid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->piid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCDeviceInfo::constructor.New({accessor});
}

void OCDeviceInfo::set_piid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->piid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Function OCEndpoint::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEndpoint", {
    OCEndpoint::InstanceAccessor("addr", &OCEndpoint::get_addr, &OCEndpoint::set_addr),
    OCEndpoint::InstanceAccessor("addr_local", &OCEndpoint::get_addr_local, &OCEndpoint::set_addr_local),
    OCEndpoint::InstanceAccessor("device", &OCEndpoint::get_device, &OCEndpoint::set_device),
    OCEndpoint::InstanceAccessor("di", &OCEndpoint::get_di, &OCEndpoint::set_di),
    OCEndpoint::InstanceAccessor("flags", &OCEndpoint::get_flags, &OCEndpoint::set_flags),
    OCEndpoint::InstanceAccessor("interface_index", &OCEndpoint::get_interface_index, &OCEndpoint::set_interface_index),
    OCEndpoint::InstanceAccessor("priority", &OCEndpoint::get_priority, &OCEndpoint::set_priority),
    OCEndpoint::InstanceAccessor("version", &OCEndpoint::get_version, &OCEndpoint::set_version),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEndpoint::OCEndpoint(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_endpoint_t>(new oc_endpoint_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCEndpoint::get_addr(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t::dev_addr> sp(&m_pvalue->addr);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCEndpoint::set_addr(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->addr = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>>().Data()));
}

Napi::Value OCEndpoint::get_addr_local(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t::dev_addr> sp(&m_pvalue->addr_local);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCEndpoint::set_addr_local(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->addr_local = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>>().Data()));
}

Napi::Value OCEndpoint::get_device(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->device);
}

void OCEndpoint::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->device = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCEndpoint::get_di(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->di);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCEndpoint::set_di(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->di = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Value OCEndpoint::get_flags(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->flags);
}

void OCEndpoint::set_flags(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->flags = static_cast<transport_flags>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCEndpoint::get_interface_index(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interface_index);
}

void OCEndpoint::set_interface_index(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interface_index = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCEndpoint::get_priority(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->priority);
}

void OCEndpoint::set_priority(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->priority = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCEndpoint::get_version(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->version);
}

void OCEndpoint::set_version(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->version = static_cast<ocf_version_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCEtimer::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEtimer", {
    OCEtimer::InstanceAccessor("timer", &OCEtimer::get_timer, &OCEtimer::set_timer),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEtimer::OCEtimer(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_etimer>(new oc_etimer());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_etimer>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCEtimer::get_timer(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_timer> sp(&m_pvalue->timer);
  auto accessor = Napi::External<std::shared_ptr<oc_timer>>::New(info.Env(), &sp);
  return OCEtimer::constructor.New({accessor});
}

void OCEtimer::set_timer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->timer = *(*(value.As<Napi::External<std::shared_ptr<oc_timer>>>().Data()));
}

Napi::Function OCEventCallback::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEventCallback", {
    OCEventCallback::InstanceAccessor("callback", &OCEventCallback::get_callback, &OCEventCallback::set_callback),
    OCEventCallback::InstanceAccessor("data", &OCEventCallback::get_data, &OCEventCallback::set_data),
    OCEventCallback::InstanceAccessor("timer", &OCEventCallback::get_timer, &OCEventCallback::set_timer),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEventCallback::OCEventCallback(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_event_callback_s>(new oc_event_callback_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_event_callback_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCEventCallback::get_callback(const Napi::CallbackInfo& info)
{
  return callback_function;
}

void OCEventCallback::set_callback(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  callback_function = value;
}

Napi::Value OCEventCallback::get_data(const Napi::CallbackInfo& info)
{
return callback_data;
}

void OCEventCallback::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
callback_data = value;
}

Napi::Value OCEventCallback::get_timer(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_etimer> sp(&m_pvalue->timer);
  auto accessor = Napi::External<std::shared_ptr<oc_etimer>>::New(info.Env(), &sp);
  return OCEventCallback::constructor.New({accessor});
}

void OCEventCallback::set_timer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->timer = *(*(value.As<Napi::External<std::shared_ptr<oc_etimer>>>().Data()));
}

Napi::Function OCHandler::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCHandler", {
    OCHandler::InstanceAccessor("init", &OCHandler::get_init, &OCHandler::set_init),
    OCHandler::InstanceAccessor("register_resources", &OCHandler::get_register_resources, &OCHandler::set_register_resources),
    OCHandler::InstanceAccessor("requests_entry", &OCHandler::get_requests_entry, &OCHandler::set_requests_entry),
    OCHandler::InstanceAccessor("signal_event_loop", &OCHandler::get_signal_event_loop, &OCHandler::set_signal_event_loop),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCHandler::OCHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_handler_t>(new oc_handler_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_handler_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCHandler::get_init(const Napi::CallbackInfo& info)
{
return init_function;
}

void OCHandler::set_init(const Napi::CallbackInfo& info, const Napi::Value& value)
{
init_function = value;
}

Napi::Value OCHandler::get_register_resources(const Napi::CallbackInfo& info)
{
return register_resources_function ;
}

void OCHandler::set_register_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
register_resources_function = value;
}

Napi::Value OCHandler::get_requests_entry(const Napi::CallbackInfo& info)
{
return requests_entry_function;
}

void OCHandler::set_requests_entry(const Napi::CallbackInfo& info, const Napi::Value& value)
{
requests_entry_function = value;
}

Napi::Value OCHandler::get_signal_event_loop(const Napi::CallbackInfo& info)
{
return signal_event_loop_function;
}

void OCHandler::set_signal_event_loop(const Napi::CallbackInfo& info, const Napi::Value& value)
{
signal_event_loop_function = value;
}

Napi::Function OCIPv4Addr::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCIPv4Addr", {
    OCIPv4Addr::InstanceAccessor("address", &OCIPv4Addr::get_address, &OCIPv4Addr::set_address),
    OCIPv4Addr::InstanceAccessor("port", &OCIPv4Addr::get_port, &OCIPv4Addr::set_port),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCIPv4Addr::OCIPv4Addr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ipv4_addr_t>(new oc_ipv4_addr_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ipv4_addr_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCIPv4Addr::get_address(const Napi::CallbackInfo& info)
{
auto array = Napi::Uint8Array::New(info.Env(), 4);
array[0] = m_pvalue->address[0];
array[1] = m_pvalue->address[1];
array[2] = m_pvalue->address[2];
array[3] = m_pvalue->address[3];
return array;
}

void OCIPv4Addr::set_address(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->address[0] = value.As<Napi::Uint8Array>()[0];
m_pvalue->address[1] = value.As<Napi::Uint8Array>()[1];
m_pvalue->address[2] = value.As<Napi::Uint8Array>()[2];
m_pvalue->address[3] = value.As<Napi::Uint8Array>()[3];
}

Napi::Value OCIPv4Addr::get_port(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->port);
}

void OCIPv4Addr::set_port(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->port = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCIPv6Addr::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCIPv6Addr", {
    OCIPv6Addr::InstanceAccessor("address", &OCIPv6Addr::get_address, &OCIPv6Addr::set_address),
    OCIPv6Addr::InstanceAccessor("port", &OCIPv6Addr::get_port, &OCIPv6Addr::set_port),
    OCIPv6Addr::InstanceAccessor("scope", &OCIPv6Addr::get_scope, &OCIPv6Addr::set_scope),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCIPv6Addr::OCIPv6Addr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ipv6_addr_t>(new oc_ipv6_addr_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ipv6_addr_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCIPv6Addr::get_address(const Napi::CallbackInfo& info)
{
auto array = Napi::Uint16Array::New(info.Env(), 8);
array[0] = m_pvalue->address[0];
array[1] = m_pvalue->address[1];
array[2] = m_pvalue->address[2];
array[3] = m_pvalue->address[3];
array[4] = m_pvalue->address[4];
array[5] = m_pvalue->address[5];
array[6] = m_pvalue->address[6];
array[7] = m_pvalue->address[7];
return array;
}

void OCIPv6Addr::set_address(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->address[0] = value.As<Napi::Uint16Array>()[0];
m_pvalue->address[1] = value.As<Napi::Uint16Array>()[1];
m_pvalue->address[2] = value.As<Napi::Uint16Array>()[2];
m_pvalue->address[3] = value.As<Napi::Uint16Array>()[3];
m_pvalue->address[4] = value.As<Napi::Uint16Array>()[4];
m_pvalue->address[5] = value.As<Napi::Uint16Array>()[5];
m_pvalue->address[6] = value.As<Napi::Uint16Array>()[6];
m_pvalue->address[7] = value.As<Napi::Uint16Array>()[7];
}

Napi::Value OCIPv6Addr::get_port(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->port);
}

void OCIPv6Addr::set_port(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->port = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCIPv6Addr::get_scope(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->scope);
}

void OCIPv6Addr::set_scope(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->scope = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCLEAddr::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCLEAddr", {
    OCLEAddr::InstanceAccessor("address", &OCLEAddr::get_address, &OCLEAddr::set_address),
    OCLEAddr::InstanceAccessor("type", &OCLEAddr::get_type, &OCLEAddr::set_type),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCLEAddr::OCLEAddr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_le_addr_t>(new oc_le_addr_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_le_addr_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCLEAddr::get_address(const Napi::CallbackInfo& info)
{
auto array = Napi::Uint8Array::New(info.Env(), 6);
array[0] = m_pvalue->address[0];
array[1] = m_pvalue->address[1];
array[2] = m_pvalue->address[2];
array[3] = m_pvalue->address[3];
array[4] = m_pvalue->address[4];
array[5] = m_pvalue->address[5];
return array;
}

void OCLEAddr::set_address(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->address[0] = value.As<Napi::Uint8Array>()[0];
m_pvalue->address[1] = value.As<Napi::Uint8Array>()[1];
m_pvalue->address[2] = value.As<Napi::Uint8Array>()[2];
m_pvalue->address[3] = value.As<Napi::Uint8Array>()[3];
m_pvalue->address[4] = value.As<Napi::Uint8Array>()[4];
m_pvalue->address[5] = value.As<Napi::Uint8Array>()[5];
}

Napi::Value OCLEAddr::get_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->type);
}

void OCLEAddr::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->type = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCLinkParams::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCLinkParams", {
    OCLinkParams::InstanceAccessor("key", &OCLinkParams::get_key, &OCLinkParams::set_key),
    OCLinkParams::InstanceAccessor("value", &OCLinkParams::get_value, &OCLinkParams::set_value),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCLinkParams::OCLinkParams(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_link_params_t>(new oc_link_params_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_link_params_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCLinkParams::get_key(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->key);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCLinkParams::constructor.New({accessor});
}

void OCLinkParams::set_key(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->key = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCLinkParams::get_value(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->value);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCLinkParams::constructor.New({accessor});
}

void OCLinkParams::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->value = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCLink::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCLink", {
    OCLink::InstanceAccessor("ins", &OCLink::get_ins, &OCLink::set_ins),
    OCLink::InstanceAccessor("interfaces", &OCLink::get_interfaces, &OCLink::set_interfaces),
    OCLink::InstanceAccessor("rel", &OCLink::get_rel, &OCLink::set_rel),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCLink::OCLink(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_link_s>(new oc_link_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_link_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCLink::get_ins(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->ins);
}

void OCLink::set_ins(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ins = value.As<Napi::Number>().Int64Value();
}

Napi::Value OCLink::get_interfaces(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interfaces);
}

void OCLink::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCLink::get_rel(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->rel);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCLink::constructor.New({accessor});
}

void OCLink::set_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rel = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCMemb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCMemb", {
    OCMemb::InstanceAccessor("count", &OCMemb::get_count, &OCMemb::set_count),
    OCMemb::InstanceAccessor("num", &OCMemb::get_num, &OCMemb::set_num),
    OCMemb::InstanceAccessor("size", &OCMemb::get_size, &OCMemb::set_size),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCMemb::OCMemb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_memb>(new oc_memb());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_memb>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCMemb::get_count(const Napi::CallbackInfo& info)
{
return Napi::Buffer<char>::New(info.Env(), m_pvalue->count, m_pvalue->num);
}

void OCMemb::set_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<m_pvalue->num; i++) { m_pvalue->count[i] = value.As<Napi::Buffer<int8_t>>().Data()[i]; }
}

Napi::Value OCMemb::get_num(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num);
}

void OCMemb::set_num(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num = static_cast<unsigned short>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCMemb::get_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->size);
}

void OCMemb::set_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->size = static_cast<unsigned short>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCMessage::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCMessage", {
    OCMessage::InstanceAccessor("data", &OCMessage::get_data, &OCMessage::set_data),
    OCMessage::InstanceAccessor("encrypted", &OCMessage::get_encrypted, &OCMessage::set_encrypted),
    OCMessage::InstanceAccessor("endpoint", &OCMessage::get_endpoint, &OCMessage::set_endpoint),
    OCMessage::InstanceAccessor("length", &OCMessage::get_length, &OCMessage::set_length),
    OCMessage::InstanceAccessor("read_offset", &OCMessage::get_read_offset, &OCMessage::set_read_offset),
    OCMessage::InstanceAccessor("ref_count", &OCMessage::get_ref_count, &OCMessage::set_ref_count),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCMessage::OCMessage(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_message_s>(new oc_message_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_message_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCMessage::get_data(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->data, OC_PDU_SIZE);
}

void OCMessage::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->data[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}

#ifdef OC_SECURITY
Napi::Value OCMessage::get_encrypted(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->encrypted);
}

void OCMessage::set_encrypted(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->encrypted = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCMessage::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({accessor});
}

void OCMessage::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value OCMessage::get_length(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->length);
}

void OCMessage::set_length(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->length = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

#ifdef OC_TCP
Napi::Value OCMessage::get_read_offset(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->read_offset);
}

void OCMessage::set_read_offset(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->read_offset = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCMessage::get_ref_count(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->ref_count);
}

void OCMessage::set_ref_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ref_count = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCMmem::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCMmem", {
    OCMmem::InstanceAccessor("size", &OCMmem::get_size, &OCMmem::set_size),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCMmem::OCMmem(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_mmem>(new oc_mmem());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_mmem>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCMmem::get_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->size);
}

void OCMmem::set_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->size = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCNetworkInterfaceCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCNetworkInterfaceCb", {

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCNetworkInterfaceCb::OCNetworkInterfaceCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_network_interface_cb>(new oc_network_interface_cb());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_network_interface_cb>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::Function OCPlatformInfo::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCPlatformInfo", {
    OCPlatformInfo::InstanceAccessor("data", &OCPlatformInfo::get_data, &OCPlatformInfo::set_data),
    OCPlatformInfo::InstanceAccessor("init_platform_cb", &OCPlatformInfo::get_init_platform_cb, &OCPlatformInfo::set_init_platform_cb),
    OCPlatformInfo::InstanceAccessor("mfg_name", &OCPlatformInfo::get_mfg_name, &OCPlatformInfo::set_mfg_name),
    OCPlatformInfo::InstanceAccessor("pi", &OCPlatformInfo::get_pi, &OCPlatformInfo::set_pi),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCPlatformInfo::OCPlatformInfo(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_platform_info_t>(new oc_platform_info_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_platform_info_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCPlatformInfo::get_data(const Napi::CallbackInfo& info)
{
return init_platform_cb_data;
}

void OCPlatformInfo::set_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
init_platform_cb_data = value;
}

Napi::Value OCPlatformInfo::get_init_platform_cb(const Napi::CallbackInfo& info)
{
  return init_platform_cb_function;
}

void OCPlatformInfo::set_init_platform_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  init_platform_cb_function = value;
}

Napi::Value OCPlatformInfo::get_mfg_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->mfg_name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({accessor});
}

void OCPlatformInfo::set_mfg_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mfg_name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCPlatformInfo::get_pi(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->pi);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCPlatformInfo::constructor.New({accessor});
}

void OCPlatformInfo::set_pi(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->pi = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Function OCProcess::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCProcess", {
    OCProcess::InstanceAccessor("name", &OCProcess::get_name, &OCProcess::set_name),
    OCProcess::InstanceAccessor("needspoll", &OCProcess::get_needspoll, &OCProcess::set_needspoll),
    OCProcess::InstanceAccessor("state", &OCProcess::get_state, &OCProcess::set_state),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCProcess::OCProcess(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_process>(new oc_process());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_process>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCProcess::get_name(const Napi::CallbackInfo& info)
{
  return Napi::String::New(info.Env(), m_pvalue->name);
}

void OCProcess::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = value.As<Napi::String>().Utf8Value().c_str();
}

Napi::Value OCProcess::get_needspoll(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->needspoll);
}

void OCProcess::set_needspoll(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->needspoll = static_cast<unsigned char>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCProcess::get_state(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->state);
}

void OCProcess::set_state(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->state = static_cast<unsigned char>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCPropertiesCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCPropertiesCb", {

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCPropertiesCb::OCPropertiesCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_properties_cb_t>(new oc_properties_cb_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::Function OCRep::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRep", {
    OCRep::InstanceAccessor("name", &OCRep::get_name, &OCRep::set_name),
    OCRep::InstanceAccessor("type", &OCRep::get_type, &OCRep::set_type),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRep::OCRep(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_rep_s>(new oc_rep_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_rep_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCRep::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCRep::constructor.New({accessor});
}

void OCRep::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCRep::get_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->type);
}

void OCRep::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->type = static_cast<oc_rep_value_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCRequestHandler::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRequestHandler", {
    OCRequestHandler::InstanceAccessor("cb", &OCRequestHandler::get_cb, &OCRequestHandler::set_cb),
    OCRequestHandler::InstanceAccessor("user_data", &OCRequestHandler::get_user_data, &OCRequestHandler::set_user_data),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRequestHandler::OCRequestHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_request_handler_s>(new oc_request_handler_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCRequestHandler::get_cb(const Napi::CallbackInfo& info)
{
  return cb_function;
}

void OCRequestHandler::set_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  cb_function = value;
}

Napi::Value OCRequestHandler::get_user_data(const Napi::CallbackInfo& info)
{
return cb_data;
}

void OCRequestHandler::set_user_data(const Napi::CallbackInfo& info, const Napi::Value& value)
{
cb_data = value;
}

Napi::Function OCRequest::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRequest", {
    OCRequest::InstanceAccessor("_payload", &OCRequest::get__payload, &OCRequest::set__payload),
    OCRequest::InstanceAccessor("_payload_len", &OCRequest::get__payload_len, &OCRequest::set__payload_len),
    OCRequest::InstanceAccessor("content_format", &OCRequest::get_content_format, &OCRequest::set_content_format),
    OCRequest::InstanceAccessor("query", &OCRequest::get_query, &OCRequest::set_query),
    OCRequest::InstanceAccessor("query_len", &OCRequest::get_query_len, &OCRequest::set_query_len),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRequest::OCRequest(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_request_t>(new oc_request_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_request_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCRequest::get__payload(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(m_pvalue->_payload), m_pvalue->_payload_len);
}

void OCRequest::set__payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
/* nop */
}

Napi::Value OCRequest::get__payload_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->_payload_len);
}

void OCRequest::set__payload_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->_payload_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCRequest::get_content_format(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->content_format);
}

void OCRequest::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->content_format = static_cast<oc_content_format_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCRequest::get_query(const Napi::CallbackInfo& info)
{
return Napi::Buffer<char>::New(info.Env(), const_cast<char*>(m_pvalue->query), m_pvalue->query_len);
}

void OCRequest::set_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
/* nop */
}

Napi::Value OCRequest::get_query_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->query_len);
}

void OCRequest::set_query_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->query_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCResource::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResource", {
    OCResource::InstanceAccessor("default_interface", &OCResource::get_default_interface, &OCResource::set_default_interface),
    OCResource::InstanceAccessor("delete_handler", &OCResource::get_delete_handler, &OCResource::set_delete_handler),
    OCResource::InstanceAccessor("device", &OCResource::get_device, &OCResource::set_device),
    OCResource::InstanceAccessor("get_handler", &OCResource::get_get_handler, &OCResource::set_get_handler),
    OCResource::InstanceAccessor("get_properties", &OCResource::get_get_properties, &OCResource::set_get_properties),
    OCResource::InstanceAccessor("interfaces", &OCResource::get_interfaces, &OCResource::set_interfaces),
    OCResource::InstanceAccessor("name", &OCResource::get_name, &OCResource::set_name),
    OCResource::InstanceAccessor("num_links", &OCResource::get_num_links, &OCResource::set_num_links),
    OCResource::InstanceAccessor("num_observers", &OCResource::get_num_observers, &OCResource::set_num_observers),
    OCResource::InstanceAccessor("observe_period_seconds", &OCResource::get_observe_period_seconds, &OCResource::set_observe_period_seconds),
    OCResource::InstanceAccessor("post_handler", &OCResource::get_post_handler, &OCResource::set_post_handler),
    OCResource::InstanceAccessor("properties", &OCResource::get_properties, &OCResource::set_properties),
    OCResource::InstanceAccessor("put_handler", &OCResource::get_put_handler, &OCResource::set_put_handler),
    OCResource::InstanceAccessor("set_properties", &OCResource::get_set_properties, &OCResource::set_set_properties),
    OCResource::InstanceAccessor("tag_func_desc", &OCResource::get_tag_func_desc, &OCResource::set_tag_func_desc),
    OCResource::InstanceAccessor("tag_pos_desc", &OCResource::get_tag_pos_desc, &OCResource::set_tag_pos_desc),
    OCResource::InstanceAccessor("tag_pos_rel", &OCResource::get_tag_pos_rel, &OCResource::set_tag_pos_rel),
    OCResource::InstanceAccessor("types", &OCResource::get_types, &OCResource::set_types),
    OCResource::InstanceAccessor("uri", &OCResource::get_uri, &OCResource::set_uri),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCResource::OCResource(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_resource_s>(new oc_resource_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_resource_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCResource::get_default_interface(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->default_interface);
}

void OCResource::set_default_interface(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->default_interface = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_delete_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->delete_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_delete_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->delete_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_device(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->device);
}

void OCResource::set_device(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->device = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_get_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->get_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_get_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_get_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_properties = *(*(value.As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCResource::get_interfaces(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interfaces);
}

void OCResource::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

#ifdef OC_COLLECTIONS
Napi::Value OCResource::get_num_links(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num_links);
}

void OCResource::set_num_links(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num_links = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCResource::get_num_observers(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->num_observers);
}

void OCResource::set_num_observers(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->num_observers = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_observe_period_seconds(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_period_seconds);
}

void OCResource::set_observe_period_seconds(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_period_seconds = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_post_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->post_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_post_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->post_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_properties(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->properties);
}

void OCResource::set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->properties = static_cast<oc_resource_properties_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_put_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_request_handler_s> sp(&m_pvalue->put_handler);
  auto accessor = Napi::External<std::shared_ptr<oc_request_handler_s>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->put_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_set_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_set_properties(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->set_properties = *(*(value.As<Napi::External<std::shared_ptr<oc_properties_cb_t>>>().Data()));
}

Napi::Value OCResource::get_tag_func_desc(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->tag_func_desc);
}

void OCResource::set_tag_func_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->tag_func_desc = static_cast<oc_enum_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_tag_pos_desc(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->tag_pos_desc);
}

void OCResource::set_tag_pos_desc(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->tag_pos_desc = static_cast<oc_pos_description_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResource::get_tag_pos_rel(const Napi::CallbackInfo& info)
{
auto array = Napi::Float64Array::New(info.Env(), 3);
array[0] = m_pvalue->tag_pos_rel[0];
array[1] = m_pvalue->tag_pos_rel[1];
array[2] = m_pvalue->tag_pos_rel[2];
}

void OCResource::set_tag_pos_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->tag_pos_rel[0] = value.As<Napi::Float64Array>()[0];
m_pvalue->tag_pos_rel[1] = value.As<Napi::Float64Array>()[1];
m_pvalue->tag_pos_rel[2] = value.As<Napi::Float64Array>()[2];
}

Napi::Value OCResource::get_types(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->types);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCResource::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCResource::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCResponse::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResponse", {

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCResponse::OCResponse(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_response_t>(new oc_response_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_response_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::Function OCRole::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRole", {
    OCRole::InstanceAccessor("authority", &OCRole::get_authority, &OCRole::set_authority),
    OCRole::InstanceAccessor("role", &OCRole::get_role, &OCRole::set_role),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRole::OCRole(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_role_t>(new oc_role_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_role_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCRole::get_authority(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->authority);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCRole::constructor.New({accessor});
}

void OCRole::set_authority(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->authority = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCRole::get_role(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->role);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCRole::constructor.New({accessor});
}

void OCRole::set_role(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->role = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCRt::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRt", {
    OCRt::InstanceAccessor("rt", &OCRt::get_rt, &OCRt::set_rt),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRt::OCRt(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_rt_t>(new oc_rt_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_rt_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCRt::get_rt(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->rt);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCRt::constructor.New({accessor});
}

void OCRt::set_rt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rt = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Function OCSecAce::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecAce", {
    OCSecAce::InstanceAccessor("aceid", &OCSecAce::get_aceid, &OCSecAce::set_aceid),
    OCSecAce::InstanceAccessor("permission", &OCSecAce::get_permission, &OCSecAce::set_permission),
    OCSecAce::InstanceAccessor("subject", &OCSecAce::get_subject, &OCSecAce::set_subject),
    OCSecAce::InstanceAccessor("subject_type", &OCSecAce::get_subject_type, &OCSecAce::set_subject_type),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecAce::OCSecAce(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_ace_t>(new oc_sec_ace_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_ace_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSecAce::get_aceid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->aceid);
}

void OCSecAce::set_aceid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->aceid = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCSecAce::get_permission(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->permission);
}

void OCSecAce::set_permission(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->permission = static_cast<oc_ace_permissions_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCSecAce::get_subject(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_ace_subject_t> sp(&m_pvalue->subject);
  auto accessor = Napi::External<std::shared_ptr<oc_ace_subject_t>>::New(info.Env(), &sp);
  return OCSecAce::constructor.New({accessor});
}

void OCSecAce::set_subject(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->subject = *(*(value.As<Napi::External<std::shared_ptr<oc_ace_subject_t>>>().Data()));
}

Napi::Value OCSecAce::get_subject_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->subject_type);
}

void OCSecAce::set_subject_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->subject_type = static_cast<oc_ace_subject_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCSecAcl::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecAcl", {
    OCSecAcl::InstanceAccessor("rowneruuid", &OCSecAcl::get_rowneruuid, &OCSecAcl::set_rowneruuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecAcl::OCSecAcl(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_acl_s>(new oc_sec_acl_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_acl_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSecAcl::get_rowneruuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->rowneruuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCSecAcl::constructor.New({accessor});
}

void OCSecAcl::set_rowneruuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rowneruuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Function OCSecCreds::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecCreds", {
    OCSecCreds::InstanceAccessor("rowneruuid", &OCSecCreds::get_rowneruuid, &OCSecCreds::set_rowneruuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecCreds::OCSecCreds(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_creds_t>(new oc_sec_creds_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_creds_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSecCreds::get_rowneruuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->rowneruuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCSecCreds::constructor.New({accessor});
}

void OCSecCreds::set_rowneruuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rowneruuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Function OCSecCred::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecCred", {
    OCSecCred::InstanceAccessor("chain", &OCSecCred::get_chain, &OCSecCred::set_chain),
    OCSecCred::InstanceAccessor("child", &OCSecCred::get_child, &OCSecCred::set_child),
    OCSecCred::InstanceAccessor("credid", &OCSecCred::get_credid, &OCSecCred::set_credid),
    OCSecCred::InstanceAccessor("credtype", &OCSecCred::get_credtype, &OCSecCred::set_credtype),
    OCSecCred::InstanceAccessor("credusage", &OCSecCred::get_credusage, &OCSecCred::set_credusage),
    OCSecCred::InstanceAccessor("owner_cred", &OCSecCred::get_owner_cred, &OCSecCred::set_owner_cred),
    OCSecCred::InstanceAccessor("privatedata", &OCSecCred::get_privatedata, &OCSecCred::set_privatedata),
    OCSecCred::InstanceAccessor("publicdata", &OCSecCred::get_publicdata, &OCSecCred::set_publicdata),
    OCSecCred::InstanceAccessor("subjectuuid", &OCSecCred::get_subjectuuid, &OCSecCred::set_subjectuuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecCred::OCSecCred(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_cred_t>(new oc_sec_cred_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_cred_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
#ifdef OC_PKI
Napi::Value OCSecCred::get_chain(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_sec_cred_t> sp(&m_pvalue->chain);
  auto accessor = Napi::External<std::shared_ptr<oc_sec_cred_t>>::New(info.Env(), &sp);
  return OCSecCred::constructor.New({accessor});
}

void OCSecCred::set_chain(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->chain = *(*(value.As<Napi::External<std::shared_ptr<oc_sec_cred_t>>>().Data()));
}
#endif

#ifdef OC_PKI
Napi::Value OCSecCred::get_child(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_sec_cred_t> sp(&m_pvalue->child);
  auto accessor = Napi::External<std::shared_ptr<oc_sec_cred_t>>::New(info.Env(), &sp);
  return OCSecCred::constructor.New({accessor});
}

void OCSecCred::set_child(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->child = *(*(value.As<Napi::External<std::shared_ptr<oc_sec_cred_t>>>().Data()));
}
#endif

Napi::Value OCSecCred::get_credid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->credid);
}

void OCSecCred::set_credid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->credid = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCSecCred::get_credtype(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->credtype);
}

void OCSecCred::set_credtype(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->credtype = static_cast<oc_sec_credtype_t>(value.As<Napi::Number>().Uint32Value());
}

#ifdef OC_PKI
Napi::Value OCSecCred::get_credusage(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->credusage);
}

void OCSecCred::set_credusage(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->credusage = static_cast<oc_sec_credusage_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCSecCred::get_owner_cred(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->owner_cred);
}

void OCSecCred::set_owner_cred(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->owner_cred = value.As<Napi::Boolean>().Value();
}

Napi::Value OCSecCred::get_privatedata(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_cred_data_t> sp(&m_pvalue->privatedata);
  auto accessor = Napi::External<std::shared_ptr<oc_cred_data_t>>::New(info.Env(), &sp);
  return OCSecCred::constructor.New({accessor});
}

void OCSecCred::set_privatedata(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->privatedata = *(*(value.As<Napi::External<std::shared_ptr<oc_cred_data_t>>>().Data()));
}

#ifdef OC_PKI
Napi::Value OCSecCred::get_publicdata(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_cred_data_t> sp(&m_pvalue->publicdata);
  auto accessor = Napi::External<std::shared_ptr<oc_cred_data_t>>::New(info.Env(), &sp);
  return OCSecCred::constructor.New({accessor});
}

void OCSecCred::set_publicdata(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->publicdata = *(*(value.As<Napi::External<std::shared_ptr<oc_cred_data_t>>>().Data()));
}
#endif

Napi::Value OCSecCred::get_subjectuuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->subjectuuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCSecCred::constructor.New({accessor});
}

void OCSecCred::set_subjectuuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->subjectuuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Function OCSessionEventCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSessionEventCb", {

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSessionEventCb::OCSessionEventCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_session_event_cb>(new oc_session_event_cb());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_session_event_cb>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::Function OCSwupdateCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSwupdateCb", {
    OCSwupdateCb::InstanceAccessor("check_new_version", &OCSwupdateCb::get_check_new_version, &OCSwupdateCb::set_check_new_version),
    OCSwupdateCb::InstanceAccessor("download_update", &OCSwupdateCb::get_download_update, &OCSwupdateCb::set_download_update),
    OCSwupdateCb::InstanceAccessor("perform_upgrade", &OCSwupdateCb::get_perform_upgrade, &OCSwupdateCb::set_perform_upgrade),
    OCSwupdateCb::InstanceAccessor("validate_purl", &OCSwupdateCb::get_validate_purl, &OCSwupdateCb::set_validate_purl),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSwupdateCb::OCSwupdateCb(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_swupdate_cb_t>(new oc_swupdate_cb_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_swupdate_cb_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSwupdateCb::get_check_new_version(const Napi::CallbackInfo& info)
{
return check_new_version_function ;
}

void OCSwupdateCb::set_check_new_version(const Napi::CallbackInfo& info, const Napi::Value& value)
{
check_new_version_function = value;
}

Napi::Value OCSwupdateCb::get_download_update(const Napi::CallbackInfo& info)
{
return download_update_function;
}

void OCSwupdateCb::set_download_update(const Napi::CallbackInfo& info, const Napi::Value& value)
{
download_update_function = value;
}

Napi::Value OCSwupdateCb::get_perform_upgrade(const Napi::CallbackInfo& info)
{
return perform_upgrade_function;
}

void OCSwupdateCb::set_perform_upgrade(const Napi::CallbackInfo& info, const Napi::Value& value)
{
perform_upgrade_function = value;
}

Napi::Value OCSwupdateCb::get_validate_purl(const Napi::CallbackInfo& info)
{
return validate_purl_function;
}

void OCSwupdateCb::set_validate_purl(const Napi::CallbackInfo& info, const Napi::Value& value)
{
validate_purl_function = value;
}

Napi::Function OCTimer::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCTimer", {
    OCTimer::InstanceAccessor("interval", &OCTimer::get_interval, &OCTimer::set_interval),
    OCTimer::InstanceAccessor("start", &OCTimer::get_start, &OCTimer::set_start),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCTimer::OCTimer(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_timer>(new oc_timer());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_timer>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCTimer::get_interval(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interval);
}

void OCTimer::set_interval(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interval = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCTimer::get_start(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->start);
}

void OCTimer::set_start(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->start = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Function OCUuid::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCUuid", {
    OCUuid::InstanceAccessor("id", &OCUuid::get_id, &OCUuid::set_id),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCUuid::OCUuid(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_uuid_t>(new oc_uuid_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCUuid::get_id(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->id, 16);
}

void OCUuid::set_id(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<16; i++) { m_pvalue->id[i] = info[0].As<Napi::Buffer<uint8_t>>().Data()[i]; }
}

Napi::Function OCAceSubject::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceSubject", {
    OCAceSubject::InstanceAccessor("conn", &OCAceSubject::get_conn, &OCAceSubject::set_conn),
    OCAceSubject::InstanceAccessor("uuid", &OCAceSubject::get_uuid, &OCAceSubject::set_uuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAceSubject::OCAceSubject(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ace_subject_t>(new oc_ace_subject_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ace_subject_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCAceSubject::get_conn(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->conn);
}

void OCAceSubject::set_conn(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->conn = static_cast<oc_ace_connection_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCAceSubject::get_uuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->uuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCAceSubject::constructor.New({accessor});
}

void OCAceSubject::set_uuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Function DevAddr::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "DevAddr", {
    DevAddr::InstanceAccessor("bt", &DevAddr::get_bt, &DevAddr::set_bt),
    DevAddr::InstanceAccessor("ipv4", &DevAddr::get_ipv4, &DevAddr::set_ipv4),
    DevAddr::InstanceAccessor("ipv6", &DevAddr::get_ipv6, &DevAddr::set_ipv6),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
DevAddr::DevAddr(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_endpoint_t::dev_addr>(new oc_endpoint_t::dev_addr());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value DevAddr::get_bt(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_le_addr_t> sp(&m_pvalue->bt);
  auto accessor = Napi::External<std::shared_ptr<oc_le_addr_t>>::New(info.Env(), &sp);
  return DevAddr::constructor.New({accessor});
}

void DevAddr::set_bt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->bt = *(*(value.As<Napi::External<std::shared_ptr<oc_le_addr_t>>>().Data()));
}

Napi::Value DevAddr::get_ipv4(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_ipv4_addr_t> sp(&m_pvalue->ipv4);
  auto accessor = Napi::External<std::shared_ptr<oc_ipv4_addr_t>>::New(info.Env(), &sp);
  return DevAddr::constructor.New({accessor});
}

void DevAddr::set_ipv4(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ipv4 = *(*(value.As<Napi::External<std::shared_ptr<oc_ipv4_addr_t>>>().Data()));
}

Napi::Value DevAddr::get_ipv6(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_ipv6_addr_t> sp(&m_pvalue->ipv6);
  auto accessor = Napi::External<std::shared_ptr<oc_ipv6_addr_t>>::New(info.Env(), &sp);
  return DevAddr::constructor.New({accessor});
}

void DevAddr::set_ipv6(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ipv6 = *(*(value.As<Napi::External<std::shared_ptr<oc_ipv6_addr_t>>>().Data()));
}


Napi::Function OCAceConnectionType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceConnectionType", {
    OCAceConnectionType::InstanceAccessor("OC_CONN_AUTH_CRYPT", &OCAceConnectionType::get_OC_CONN_AUTH_CRYPT, nullptr),
    OCAceConnectionType::InstanceAccessor("OC_CONN_ANON_CLEAR", &OCAceConnectionType::get_OC_CONN_ANON_CLEAR, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAceConnectionType::OCAceConnectionType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ace_connection_type_t>(new oc_ace_connection_type_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ace_connection_type_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCAceConnectionType::get_OC_CONN_AUTH_CRYPT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CONN_AUTH_CRYPT);
}

void OCAceConnectionType::set_OC_CONN_AUTH_CRYPT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceConnectionType::get_OC_CONN_ANON_CLEAR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CONN_ANON_CLEAR);
}

void OCAceConnectionType::set_OC_CONN_ANON_CLEAR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCAcePermissions::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAcePermissions", {
    OCAcePermissions::InstanceAccessor("OC_PERM_NONE", &OCAcePermissions::get_OC_PERM_NONE, nullptr),
    OCAcePermissions::InstanceAccessor("OC_PERM_CREATE", &OCAcePermissions::get_OC_PERM_CREATE, nullptr),
    OCAcePermissions::InstanceAccessor("OC_PERM_RETRIEVE", &OCAcePermissions::get_OC_PERM_RETRIEVE, nullptr),
    OCAcePermissions::InstanceAccessor("OC_PERM_UPDATE", &OCAcePermissions::get_OC_PERM_UPDATE, nullptr),
    OCAcePermissions::InstanceAccessor("OC_PERM_DELETE", &OCAcePermissions::get_OC_PERM_DELETE, nullptr),
    OCAcePermissions::InstanceAccessor("OC_PERM_NOTIFY", &OCAcePermissions::get_OC_PERM_NOTIFY, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAcePermissions::OCAcePermissions(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ace_permissions_t>(new oc_ace_permissions_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ace_permissions_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCAcePermissions::get_OC_PERM_NONE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERM_NONE);
}

void OCAcePermissions::set_OC_PERM_NONE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissions::get_OC_PERM_CREATE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERM_CREATE);
}

void OCAcePermissions::set_OC_PERM_CREATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissions::get_OC_PERM_RETRIEVE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERM_RETRIEVE);
}

void OCAcePermissions::set_OC_PERM_RETRIEVE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissions::get_OC_PERM_UPDATE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERM_UPDATE);
}

void OCAcePermissions::set_OC_PERM_UPDATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissions::get_OC_PERM_DELETE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERM_DELETE);
}

void OCAcePermissions::set_OC_PERM_DELETE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissions::get_OC_PERM_NOTIFY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERM_NOTIFY);
}

void OCAcePermissions::set_OC_PERM_NOTIFY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCAceSubjectType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceSubjectType", {
    OCAceSubjectType::InstanceAccessor("OC_SUBJECT_UUID", &OCAceSubjectType::get_OC_SUBJECT_UUID, nullptr),
    OCAceSubjectType::InstanceAccessor("OC_SUBJECT_ROLE", &OCAceSubjectType::get_OC_SUBJECT_ROLE, nullptr),
    OCAceSubjectType::InstanceAccessor("OC_SUBJECT_CONN", &OCAceSubjectType::get_OC_SUBJECT_CONN, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAceSubjectType::OCAceSubjectType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ace_subject_type_t>(new oc_ace_subject_type_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ace_subject_type_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCAceSubjectType::get_OC_SUBJECT_UUID(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SUBJECT_UUID);
}

void OCAceSubjectType::set_OC_SUBJECT_UUID(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceSubjectType::get_OC_SUBJECT_ROLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SUBJECT_ROLE);
}

void OCAceSubjectType::set_OC_SUBJECT_ROLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceSubjectType::get_OC_SUBJECT_CONN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SUBJECT_CONN);
}

void OCAceSubjectType::set_OC_SUBJECT_CONN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCAceWildcard::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceWildcard", {
    OCAceWildcard::InstanceAccessor("OC_ACE_NO_WC", &OCAceWildcard::get_OC_ACE_NO_WC, nullptr),
    OCAceWildcard::InstanceAccessor("OC_ACE_WC_ALL", &OCAceWildcard::get_OC_ACE_WC_ALL, nullptr),
    OCAceWildcard::InstanceAccessor("OC_ACE_WC_ALL_SECURED", &OCAceWildcard::get_OC_ACE_WC_ALL_SECURED, nullptr),
    OCAceWildcard::InstanceAccessor("OC_ACE_WC_ALL_PUBLIC", &OCAceWildcard::get_OC_ACE_WC_ALL_PUBLIC, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAceWildcard::OCAceWildcard(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_ace_wildcard_t>(new oc_ace_wildcard_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_ace_wildcard_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCAceWildcard::get_OC_ACE_NO_WC(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ACE_NO_WC);
}

void OCAceWildcard::set_OC_ACE_NO_WC(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceWildcard::get_OC_ACE_WC_ALL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ACE_WC_ALL);
}

void OCAceWildcard::set_OC_ACE_WC_ALL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceWildcard::get_OC_ACE_WC_ALL_SECURED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ACE_WC_ALL_SECURED);
}

void OCAceWildcard::set_OC_ACE_WC_ALL_SECURED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAceWildcard::get_OC_ACE_WC_ALL_PUBLIC(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ACE_WC_ALL_PUBLIC);
}

void OCAceWildcard::set_OC_ACE_WC_ALL_PUBLIC(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCBlockwiseRole::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseRole", {
    OCBlockwiseRole::InstanceAccessor("OC_BLOCKWISE_CLIENT", &OCBlockwiseRole::get_OC_BLOCKWISE_CLIENT, nullptr),
    OCBlockwiseRole::InstanceAccessor("OC_BLOCKWISE_SERVER", &OCBlockwiseRole::get_OC_BLOCKWISE_SERVER, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCBlockwiseRole::OCBlockwiseRole(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_blockwise_role_t>(new oc_blockwise_role_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_blockwise_role_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCBlockwiseRole::get_OC_BLOCKWISE_CLIENT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_BLOCKWISE_CLIENT);
}

void OCBlockwiseRole::set_OC_BLOCKWISE_CLIENT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCBlockwiseRole::get_OC_BLOCKWISE_SERVER(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_BLOCKWISE_SERVER);
}

void OCBlockwiseRole::set_OC_BLOCKWISE_SERVER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCDiscoveryFlags::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCDiscoveryFlags", {
    OCDiscoveryFlags::InstanceAccessor("OC_STOP_DISCOVERY", &OCDiscoveryFlags::get_OC_STOP_DISCOVERY, nullptr),
    OCDiscoveryFlags::InstanceAccessor("OC_CONTINUE_DISCOVERY", &OCDiscoveryFlags::get_OC_CONTINUE_DISCOVERY, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCDiscoveryFlags::OCDiscoveryFlags(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_discovery_flags_t>(new oc_discovery_flags_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_discovery_flags_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCDiscoveryFlags::get_OC_STOP_DISCOVERY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STOP_DISCOVERY);
}

void OCDiscoveryFlags::set_OC_STOP_DISCOVERY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCDiscoveryFlags::get_OC_CONTINUE_DISCOVERY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CONTINUE_DISCOVERY);
}

void OCDiscoveryFlags::set_OC_CONTINUE_DISCOVERY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCQos::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCQos", {
    OCQos::InstanceAccessor("HIGH_QOS", &OCQos::get_HIGH_QOS, nullptr),
    OCQos::InstanceAccessor("LOW_QOS", &OCQos::get_LOW_QOS, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCQos::OCQos(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_qos_t>(new oc_qos_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_qos_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCQos::get_HIGH_QOS(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), HIGH_QOS);
}

void OCQos::set_HIGH_QOS(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCQos::get_LOW_QOS(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), LOW_QOS);
}

void OCQos::set_LOW_QOS(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCCloudError::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudError", {
    OCCloudError::InstanceAccessor("CLOUD_OK", &OCCloudError::get_CLOUD_OK, nullptr),
    OCCloudError::InstanceAccessor("CLOUD_ERROR_RESPONSE", &OCCloudError::get_CLOUD_ERROR_RESPONSE, nullptr),
    OCCloudError::InstanceAccessor("CLOUD_ERROR_CONNECT", &OCCloudError::get_CLOUD_ERROR_CONNECT, nullptr),
    OCCloudError::InstanceAccessor("CLOUD_ERROR_REFRESH_ACCESS_TOKEN", &OCCloudError::get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCloudError::OCCloudError(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_cloud_error_t>(new oc_cloud_error_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_cloud_error_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCloudError::get_CLOUD_OK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CLOUD_OK);
}

void OCCloudError::set_CLOUD_OK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudError::get_CLOUD_ERROR_RESPONSE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CLOUD_ERROR_RESPONSE);
}

void OCCloudError::set_CLOUD_ERROR_RESPONSE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudError::get_CLOUD_ERROR_CONNECT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CLOUD_ERROR_CONNECT);
}

void OCCloudError::set_CLOUD_ERROR_CONNECT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudError::get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
}

void OCCloudError::set_CLOUD_ERROR_REFRESH_ACCESS_TOKEN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCCloudStatus::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudStatus", {
    OCCloudStatus::InstanceAccessor("OC_CLOUD_INITIALIZED", &OCCloudStatus::get_OC_CLOUD_INITIALIZED, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_REGISTERED", &OCCloudStatus::get_OC_CLOUD_REGISTERED, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_LOGGED_IN", &OCCloudStatus::get_OC_CLOUD_LOGGED_IN, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_TOKEN_EXPIRY", &OCCloudStatus::get_OC_CLOUD_TOKEN_EXPIRY, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_REFRESHED_TOKEN", &OCCloudStatus::get_OC_CLOUD_REFRESHED_TOKEN, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_LOGGED_OUT", &OCCloudStatus::get_OC_CLOUD_LOGGED_OUT, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_FAILURE", &OCCloudStatus::get_OC_CLOUD_FAILURE, nullptr),
    OCCloudStatus::InstanceAccessor("OC_CLOUD_DEREGISTERED", &OCCloudStatus::get_OC_CLOUD_DEREGISTERED, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCloudStatus::OCCloudStatus(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_cloud_status_t>(new oc_cloud_status_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_cloud_status_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCloudStatus::get_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_INITIALIZED);
}

void OCCloudStatus::set_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_REGISTERED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_REGISTERED);
}

void OCCloudStatus::set_OC_CLOUD_REGISTERED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_LOGGED_IN);
}

void OCCloudStatus::set_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_TOKEN_EXPIRY);
}

void OCCloudStatus::set_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_REFRESHED_TOKEN);
}

void OCCloudStatus::set_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_LOGGED_OUT);
}

void OCCloudStatus::set_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_FAILURE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_FAILURE);
}

void OCCloudStatus::set_OC_CLOUD_FAILURE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatus::get_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CLOUD_DEREGISTERED);
}

void OCCloudStatus::set_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCCps::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCps", {
    OCCps::InstanceAccessor("OC_CPS_UNINITIALIZED", &OCCps::get_OC_CPS_UNINITIALIZED, nullptr),
    OCCps::InstanceAccessor("OC_CPS_READYTOREGISTER", &OCCps::get_OC_CPS_READYTOREGISTER, nullptr),
    OCCps::InstanceAccessor("OC_CPS_REGISTERING", &OCCps::get_OC_CPS_REGISTERING, nullptr),
    OCCps::InstanceAccessor("OC_CPS_REGISTERED", &OCCps::get_OC_CPS_REGISTERED, nullptr),
    OCCps::InstanceAccessor("OC_CPS_FAILED", &OCCps::get_OC_CPS_FAILED, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCps::OCCps(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_cps_t>(new oc_cps_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_cps_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCps::get_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CPS_UNINITIALIZED);
}

void OCCps::set_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCps::get_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CPS_READYTOREGISTER);
}

void OCCps::set_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCps::get_OC_CPS_REGISTERING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CPS_REGISTERING);
}

void OCCps::set_OC_CPS_REGISTERING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCps::get_OC_CPS_REGISTERED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CPS_REGISTERED);
}

void OCCps::set_OC_CPS_REGISTERED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCps::get_OC_CPS_FAILED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CPS_FAILED);
}

void OCCps::set_OC_CPS_FAILED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

#ifdef OC_TCP
Napi::Function tcpCsmState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "tcpCsmState", {
    tcpCsmState::InstanceAccessor("CSM_NONE", &tcpCsmState::get_CSM_NONE, nullptr),
    tcpCsmState::InstanceAccessor("CSM_SENT", &tcpCsmState::get_CSM_SENT, nullptr),
    tcpCsmState::InstanceAccessor("CSM_DONE", &tcpCsmState::get_CSM_DONE, nullptr),
    tcpCsmState::InstanceAccessor("CSM_ERROR", &tcpCsmState::get_CSM_ERROR, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
tcpCsmState::tcpCsmState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<tcp_csm_state_t>(new tcp_csm_state_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<tcp_csm_state_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value tcpCsmState::get_CSM_NONE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CSM_NONE);
}

void tcpCsmState::set_CSM_NONE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value tcpCsmState::get_CSM_SENT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CSM_SENT);
}

void tcpCsmState::set_CSM_SENT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value tcpCsmState::get_CSM_DONE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CSM_DONE);
}

void tcpCsmState::set_CSM_DONE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value tcpCsmState::get_CSM_ERROR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), CSM_ERROR);
}

void tcpCsmState::set_CSM_ERROR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

Napi::Function OCSecCredtype::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecCredtype", {
    OCSecCredtype::InstanceAccessor("OC_CREDTYPE_NULL", &OCSecCredtype::get_OC_CREDTYPE_NULL, nullptr),
    OCSecCredtype::InstanceAccessor("OC_CREDTYPE_PSK", &OCSecCredtype::get_OC_CREDTYPE_PSK, nullptr),
    OCSecCredtype::InstanceAccessor("OC_CREDTYPE_CERT", &OCSecCredtype::get_OC_CREDTYPE_CERT, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecCredtype::OCSecCredtype(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_credtype_t>(new oc_sec_credtype_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_credtype_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSecCredtype::get_OC_CREDTYPE_NULL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDTYPE_NULL);
}

void OCSecCredtype::set_OC_CREDTYPE_NULL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredtype::get_OC_CREDTYPE_PSK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDTYPE_PSK);
}

void OCSecCredtype::set_OC_CREDTYPE_PSK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredtype::get_OC_CREDTYPE_CERT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDTYPE_CERT);
}

void OCSecCredtype::set_OC_CREDTYPE_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCSecCredusage::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecCredusage", {
    OCSecCredusage::InstanceAccessor("OC_CREDUSAGE_NULL", &OCSecCredusage::get_OC_CREDUSAGE_NULL, nullptr),
    OCSecCredusage::InstanceAccessor("OC_CREDUSAGE_TRUSTCA", &OCSecCredusage::get_OC_CREDUSAGE_TRUSTCA, nullptr),
    OCSecCredusage::InstanceAccessor("OC_CREDUSAGE_IDENTITY_CERT", &OCSecCredusage::get_OC_CREDUSAGE_IDENTITY_CERT, nullptr),
    OCSecCredusage::InstanceAccessor("OC_CREDUSAGE_ROLE_CERT", &OCSecCredusage::get_OC_CREDUSAGE_ROLE_CERT, nullptr),
    OCSecCredusage::InstanceAccessor("OC_CREDUSAGE_MFG_TRUSTCA", &OCSecCredusage::get_OC_CREDUSAGE_MFG_TRUSTCA, nullptr),
    OCSecCredusage::InstanceAccessor("OC_CREDUSAGE_MFG_CERT", &OCSecCredusage::get_OC_CREDUSAGE_MFG_CERT, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecCredusage::OCSecCredusage(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_credusage_t>(new oc_sec_credusage_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_credusage_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSecCredusage::get_OC_CREDUSAGE_NULL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDUSAGE_NULL);
}

void OCSecCredusage::set_OC_CREDUSAGE_NULL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredusage::get_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDUSAGE_TRUSTCA);
}

void OCSecCredusage::set_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredusage::get_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDUSAGE_IDENTITY_CERT);
}

void OCSecCredusage::set_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredusage::get_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDUSAGE_ROLE_CERT);
}

void OCSecCredusage::set_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredusage::get_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDUSAGE_MFG_TRUSTCA);
}

void OCSecCredusage::set_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecCredusage::get_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_CREDUSAGE_MFG_CERT);
}

void OCSecCredusage::set_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCSecEncoding::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecEncoding", {
    OCSecEncoding::InstanceAccessor("OC_ENCODING_UNSUPPORTED", &OCSecEncoding::get_OC_ENCODING_UNSUPPORTED, nullptr),
    OCSecEncoding::InstanceAccessor("OC_ENCODING_BASE64", &OCSecEncoding::get_OC_ENCODING_BASE64, nullptr),
    OCSecEncoding::InstanceAccessor("OC_ENCODING_RAW", &OCSecEncoding::get_OC_ENCODING_RAW, nullptr),
    OCSecEncoding::InstanceAccessor("OC_ENCODING_PEM", &OCSecEncoding::get_OC_ENCODING_PEM, nullptr),
    OCSecEncoding::InstanceAccessor("OC_ENCODING_HANDLE", &OCSecEncoding::get_OC_ENCODING_HANDLE, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecEncoding::OCSecEncoding(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sec_encoding_t>(new oc_sec_encoding_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sec_encoding_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSecEncoding::get_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENCODING_UNSUPPORTED);
}

void OCSecEncoding::set_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecEncoding::get_OC_ENCODING_BASE64(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENCODING_BASE64);
}

void OCSecEncoding::set_OC_ENCODING_BASE64(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecEncoding::get_OC_ENCODING_RAW(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENCODING_RAW);
}

void OCSecEncoding::set_OC_ENCODING_RAW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecEncoding::get_OC_ENCODING_PEM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENCODING_PEM);
}

void OCSecEncoding::set_OC_ENCODING_PEM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSecEncoding::get_OC_ENCODING_HANDLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENCODING_HANDLE);
}

void OCSecEncoding::set_OC_ENCODING_HANDLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCfVersion::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCfVersion", {
    OCfVersion::InstanceAccessor("OCF_VER_1_0_0", &OCfVersion::get_OCF_VER_1_0_0, nullptr),
    OCfVersion::InstanceAccessor("OIC_VER_1_1_0", &OCfVersion::get_OIC_VER_1_1_0, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCfVersion::OCfVersion(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<ocf_version_t>(new ocf_version_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<ocf_version_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCfVersion::get_OCF_VER_1_0_0(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_VER_1_0_0);
}

void OCfVersion::set_OCF_VER_1_0_0(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCfVersion::get_OIC_VER_1_1_0(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OIC_VER_1_1_0);
}

void OCfVersion::set_OIC_VER_1_1_0(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function transportFlags::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "transportFlags", {
    transportFlags::InstanceAccessor("DISCOVERY", &transportFlags::get_DISCOVERY, nullptr),
    transportFlags::InstanceAccessor("SECURED", &transportFlags::get_SECURED, nullptr),
    transportFlags::InstanceAccessor("IPV4", &transportFlags::get_IPV4, nullptr),
    transportFlags::InstanceAccessor("IPV6", &transportFlags::get_IPV6, nullptr),
    transportFlags::InstanceAccessor("TCP", &transportFlags::get_TCP, nullptr),
    transportFlags::InstanceAccessor("GATT", &transportFlags::get_GATT, nullptr),
    transportFlags::InstanceAccessor("MULTICAST", &transportFlags::get_MULTICAST, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
transportFlags::transportFlags(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<transport_flags>(new transport_flags());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<transport_flags>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value transportFlags::get_DISCOVERY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), DISCOVERY);
}

void transportFlags::set_DISCOVERY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value transportFlags::get_SECURED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), SECURED);
}

void transportFlags::set_SECURED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value transportFlags::get_IPV4(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), IPV4);
}

void transportFlags::set_IPV4(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value transportFlags::get_IPV6(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), IPV6);
}

void transportFlags::set_IPV6(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value transportFlags::get_TCP(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), TCP);
}

void transportFlags::set_TCP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value transportFlags::get_GATT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), GATT);
}

void transportFlags::set_GATT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value transportFlags::get_MULTICAST(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), MULTICAST);
}

void transportFlags::set_MULTICAST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCEnum::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEnum", {
    OCEnum::InstanceAccessor("OC_ENUM_ABORTED", &OCEnum::get_OC_ENUM_ABORTED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ACTIVE", &OCEnum::get_OC_ENUM_ACTIVE, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_AIRDRY", &OCEnum::get_OC_ENUM_AIRDRY, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ARMEDAWAY", &OCEnum::get_OC_ENUM_ARMEDAWAY, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ARMEDINSTANT", &OCEnum::get_OC_ENUM_ARMEDINSTANT, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ARMEDMAXIMUM", &OCEnum::get_OC_ENUM_ARMEDMAXIMUM, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ARMEDNIGHTSTAY", &OCEnum::get_OC_ENUM_ARMEDNIGHTSTAY, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ARMEDSTAY", &OCEnum::get_OC_ENUM_ARMEDSTAY, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_AROMA", &OCEnum::get_OC_ENUM_AROMA, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_AI", &OCEnum::get_OC_ENUM_AI, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_AUTO", &OCEnum::get_OC_ENUM_AUTO, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_BOILING", &OCEnum::get_OC_ENUM_BOILING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_BREWING", &OCEnum::get_OC_ENUM_BREWING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_CANCELLED", &OCEnum::get_OC_ENUM_CANCELLED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_CIRCULATING", &OCEnum::get_OC_ENUM_CIRCULATING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_CLEANING", &OCEnum::get_OC_ENUM_CLEANING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_CLOTHES", &OCEnum::get_OC_ENUM_CLOTHES, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_COMPLETED", &OCEnum::get_OC_ENUM_COMPLETED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_COOL", &OCEnum::get_OC_ENUM_COOL, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_DELICATE", &OCEnum::get_OC_ENUM_DELICATE, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_DISABLED", &OCEnum::get_OC_ENUM_DISABLED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_DOWN", &OCEnum::get_OC_ENUM_DOWN, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_DUAL", &OCEnum::get_OC_ENUM_DUAL, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_DRY", &OCEnum::get_OC_ENUM_DRY, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ENABLED", &OCEnum::get_OC_ENUM_ENABLED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_EXTENDED", &OCEnum::get_OC_ENUM_EXTENDED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_FAN", &OCEnum::get_OC_ENUM_FAN, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_FAST", &OCEnum::get_OC_ENUM_FAST, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_FILTERMATERIAL", &OCEnum::get_OC_ENUM_FILTERMATERIAL, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_FOCUSED", &OCEnum::get_OC_ENUM_FOCUSED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_GRINDING", &OCEnum::get_OC_ENUM_GRINDING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_HEATING", &OCEnum::get_OC_ENUM_HEATING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_HEAVY", &OCEnum::get_OC_ENUM_HEAVY, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_IDLE", &OCEnum::get_OC_ENUM_IDLE, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_INK", &OCEnum::get_OC_ENUM_INK, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_INKBLACK", &OCEnum::get_OC_ENUM_INKBLACK, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_INKCYAN", &OCEnum::get_OC_ENUM_INKCYAN, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_INKMAGENTA", &OCEnum::get_OC_ENUM_INKMAGENTA, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_INKTRICOLOUR", &OCEnum::get_OC_ENUM_INKTRICOLOUR, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_INKYELLOW", &OCEnum::get_OC_ENUM_INKYELLOW, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_KEEPWARM", &OCEnum::get_OC_ENUM_KEEPWARM, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_NORMAL", &OCEnum::get_OC_ENUM_NORMAL, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_NOTSUPPORTED", &OCEnum::get_OC_ENUM_NOTSUPPORTED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PAUSE", &OCEnum::get_OC_ENUM_PAUSE, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PENDING", &OCEnum::get_OC_ENUM_PENDING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PENDINGHELD", &OCEnum::get_OC_ENUM_PENDINGHELD, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PERMAPRESS", &OCEnum::get_OC_ENUM_PERMAPRESS, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PREWASH", &OCEnum::get_OC_ENUM_PREWASH, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PROCESSING", &OCEnum::get_OC_ENUM_PROCESSING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_PURE", &OCEnum::get_OC_ENUM_PURE, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_QUICK", &OCEnum::get_OC_ENUM_QUICK, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_QUIET", &OCEnum::get_OC_ENUM_QUIET, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_RINSE", &OCEnum::get_OC_ENUM_RINSE, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_SECTORED", &OCEnum::get_OC_ENUM_SECTORED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_SILENT", &OCEnum::get_OC_ENUM_SILENT, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_SLEEP", &OCEnum::get_OC_ENUM_SLEEP, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_SMART", &OCEnum::get_OC_ENUM_SMART, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_SPOT", &OCEnum::get_OC_ENUM_SPOT, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_STEAM", &OCEnum::get_OC_ENUM_STEAM, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_STOPPED", &OCEnum::get_OC_ENUM_STOPPED, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_SPIN", &OCEnum::get_OC_ENUM_SPIN, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_TESTING", &OCEnum::get_OC_ENUM_TESTING, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_TONER", &OCEnum::get_OC_ENUM_TONER, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_TONERBLACK", &OCEnum::get_OC_ENUM_TONERBLACK, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_TONERCYAN", &OCEnum::get_OC_ENUM_TONERCYAN, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_TONERMAGENTA", &OCEnum::get_OC_ENUM_TONERMAGENTA, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_TONERYELLOW", &OCEnum::get_OC_ENUM_TONERYELLOW, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_WARM", &OCEnum::get_OC_ENUM_WARM, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_WASH", &OCEnum::get_OC_ENUM_WASH, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_WET", &OCEnum::get_OC_ENUM_WET, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_WIND", &OCEnum::get_OC_ENUM_WIND, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_WRINKLEPREVENT", &OCEnum::get_OC_ENUM_WRINKLEPREVENT, nullptr),
    OCEnum::InstanceAccessor("OC_ENUM_ZIGZAG", &OCEnum::get_OC_ENUM_ZIGZAG, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEnum::OCEnum(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_enum_t>(new oc_enum_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_enum_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCEnum::get_OC_ENUM_ABORTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ABORTED);
}

void OCEnum::set_OC_ENUM_ABORTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ACTIVE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ACTIVE);
}

void OCEnum::set_OC_ENUM_ACTIVE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_AIRDRY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_AIRDRY);
}

void OCEnum::set_OC_ENUM_AIRDRY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ARMEDAWAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ARMEDAWAY);
}

void OCEnum::set_OC_ENUM_ARMEDAWAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ARMEDINSTANT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ARMEDINSTANT);
}

void OCEnum::set_OC_ENUM_ARMEDINSTANT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ARMEDMAXIMUM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ARMEDMAXIMUM);
}

void OCEnum::set_OC_ENUM_ARMEDMAXIMUM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ARMEDNIGHTSTAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ARMEDNIGHTSTAY);
}

void OCEnum::set_OC_ENUM_ARMEDNIGHTSTAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ARMEDSTAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ARMEDSTAY);
}

void OCEnum::set_OC_ENUM_ARMEDSTAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_AROMA(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_AROMA);
}

void OCEnum::set_OC_ENUM_AROMA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_AI(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_AI);
}

void OCEnum::set_OC_ENUM_AI(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_AUTO(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_AUTO);
}

void OCEnum::set_OC_ENUM_AUTO(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_BOILING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_BOILING);
}

void OCEnum::set_OC_ENUM_BOILING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_BREWING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_BREWING);
}

void OCEnum::set_OC_ENUM_BREWING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_CANCELLED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_CANCELLED);
}

void OCEnum::set_OC_ENUM_CANCELLED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_CIRCULATING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_CIRCULATING);
}

void OCEnum::set_OC_ENUM_CIRCULATING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_CLEANING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_CLEANING);
}

void OCEnum::set_OC_ENUM_CLEANING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_CLOTHES(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_CLOTHES);
}

void OCEnum::set_OC_ENUM_CLOTHES(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_COMPLETED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_COMPLETED);
}

void OCEnum::set_OC_ENUM_COMPLETED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_COOL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_COOL);
}

void OCEnum::set_OC_ENUM_COOL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_DELICATE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_DELICATE);
}

void OCEnum::set_OC_ENUM_DELICATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_DISABLED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_DISABLED);
}

void OCEnum::set_OC_ENUM_DISABLED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_DOWN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_DOWN);
}

void OCEnum::set_OC_ENUM_DOWN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_DUAL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_DUAL);
}

void OCEnum::set_OC_ENUM_DUAL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_DRY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_DRY);
}

void OCEnum::set_OC_ENUM_DRY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ENABLED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ENABLED);
}

void OCEnum::set_OC_ENUM_ENABLED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_EXTENDED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_EXTENDED);
}

void OCEnum::set_OC_ENUM_EXTENDED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_FAN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_FAN);
}

void OCEnum::set_OC_ENUM_FAN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_FAST(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_FAST);
}

void OCEnum::set_OC_ENUM_FAST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_FILTERMATERIAL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_FILTERMATERIAL);
}

void OCEnum::set_OC_ENUM_FILTERMATERIAL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_FOCUSED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_FOCUSED);
}

void OCEnum::set_OC_ENUM_FOCUSED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_GRINDING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_GRINDING);
}

void OCEnum::set_OC_ENUM_GRINDING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_HEATING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_HEATING);
}

void OCEnum::set_OC_ENUM_HEATING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_HEAVY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_HEAVY);
}

void OCEnum::set_OC_ENUM_HEAVY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_IDLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_IDLE);
}

void OCEnum::set_OC_ENUM_IDLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_INK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_INK);
}

void OCEnum::set_OC_ENUM_INK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_INKBLACK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_INKBLACK);
}

void OCEnum::set_OC_ENUM_INKBLACK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_INKCYAN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_INKCYAN);
}

void OCEnum::set_OC_ENUM_INKCYAN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_INKMAGENTA(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_INKMAGENTA);
}

void OCEnum::set_OC_ENUM_INKMAGENTA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_INKTRICOLOUR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_INKTRICOLOUR);
}

void OCEnum::set_OC_ENUM_INKTRICOLOUR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_INKYELLOW(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_INKYELLOW);
}

void OCEnum::set_OC_ENUM_INKYELLOW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_KEEPWARM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_KEEPWARM);
}

void OCEnum::set_OC_ENUM_KEEPWARM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_NORMAL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_NORMAL);
}

void OCEnum::set_OC_ENUM_NORMAL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_NOTSUPPORTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_NOTSUPPORTED);
}

void OCEnum::set_OC_ENUM_NOTSUPPORTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PAUSE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PAUSE);
}

void OCEnum::set_OC_ENUM_PAUSE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PENDING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PENDING);
}

void OCEnum::set_OC_ENUM_PENDING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PENDINGHELD(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PENDINGHELD);
}

void OCEnum::set_OC_ENUM_PENDINGHELD(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PERMAPRESS(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PERMAPRESS);
}

void OCEnum::set_OC_ENUM_PERMAPRESS(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PREWASH(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PREWASH);
}

void OCEnum::set_OC_ENUM_PREWASH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PROCESSING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PROCESSING);
}

void OCEnum::set_OC_ENUM_PROCESSING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_PURE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_PURE);
}

void OCEnum::set_OC_ENUM_PURE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_QUICK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_QUICK);
}

void OCEnum::set_OC_ENUM_QUICK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_QUIET(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_QUIET);
}

void OCEnum::set_OC_ENUM_QUIET(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_RINSE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_RINSE);
}

void OCEnum::set_OC_ENUM_RINSE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_SECTORED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_SECTORED);
}

void OCEnum::set_OC_ENUM_SECTORED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_SILENT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_SILENT);
}

void OCEnum::set_OC_ENUM_SILENT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_SLEEP(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_SLEEP);
}

void OCEnum::set_OC_ENUM_SLEEP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_SMART(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_SMART);
}

void OCEnum::set_OC_ENUM_SMART(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_SPOT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_SPOT);
}

void OCEnum::set_OC_ENUM_SPOT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_STEAM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_STEAM);
}

void OCEnum::set_OC_ENUM_STEAM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_STOPPED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_STOPPED);
}

void OCEnum::set_OC_ENUM_STOPPED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_SPIN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_SPIN);
}

void OCEnum::set_OC_ENUM_SPIN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_TESTING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_TESTING);
}

void OCEnum::set_OC_ENUM_TESTING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_TONER(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_TONER);
}

void OCEnum::set_OC_ENUM_TONER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_TONERBLACK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_TONERBLACK);
}

void OCEnum::set_OC_ENUM_TONERBLACK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_TONERCYAN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_TONERCYAN);
}

void OCEnum::set_OC_ENUM_TONERCYAN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_TONERMAGENTA(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_TONERMAGENTA);
}

void OCEnum::set_OC_ENUM_TONERMAGENTA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_TONERYELLOW(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_TONERYELLOW);
}

void OCEnum::set_OC_ENUM_TONERYELLOW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_WARM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_WARM);
}

void OCEnum::set_OC_ENUM_WARM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_WASH(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_WASH);
}

void OCEnum::set_OC_ENUM_WASH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_WET(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_WET);
}

void OCEnum::set_OC_ENUM_WET(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_WIND(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_WIND);
}

void OCEnum::set_OC_ENUM_WIND(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_WRINKLEPREVENT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_WRINKLEPREVENT);
}

void OCEnum::set_OC_ENUM_WRINKLEPREVENT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEnum::get_OC_ENUM_ZIGZAG(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_ENUM_ZIGZAG);
}

void OCEnum::set_OC_ENUM_ZIGZAG(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCPosDescription::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCPosDescription", {
    OCPosDescription::InstanceAccessor("OC_POS_UNKNOWN", &OCPosDescription::get_OC_POS_UNKNOWN, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_TOP", &OCPosDescription::get_OC_POS_TOP, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_BOTTOM", &OCPosDescription::get_OC_POS_BOTTOM, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_LEFT", &OCPosDescription::get_OC_POS_LEFT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_RIGHT", &OCPosDescription::get_OC_POS_RIGHT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_CENTRE", &OCPosDescription::get_OC_POS_CENTRE, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_TOPLEFT", &OCPosDescription::get_OC_POS_TOPLEFT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_BOTTOMLEFT", &OCPosDescription::get_OC_POS_BOTTOMLEFT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_CENTRELEFT", &OCPosDescription::get_OC_POS_CENTRELEFT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_CENTRERIGHT", &OCPosDescription::get_OC_POS_CENTRERIGHT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_BOTTOMRIGHT", &OCPosDescription::get_OC_POS_BOTTOMRIGHT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_TOPRIGHT", &OCPosDescription::get_OC_POS_TOPRIGHT, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_TOPCENTRE", &OCPosDescription::get_OC_POS_TOPCENTRE, nullptr),
    OCPosDescription::InstanceAccessor("OC_POS_BOTTOMCENTRE", &OCPosDescription::get_OC_POS_BOTTOMCENTRE, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCPosDescription::OCPosDescription(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_pos_description_t>(new oc_pos_description_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_pos_description_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCPosDescription::get_OC_POS_UNKNOWN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_UNKNOWN);
}

void OCPosDescription::set_OC_POS_UNKNOWN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_TOP(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_TOP);
}

void OCPosDescription::set_OC_POS_TOP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_BOTTOM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_BOTTOM);
}

void OCPosDescription::set_OC_POS_BOTTOM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_LEFT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_LEFT);
}

void OCPosDescription::set_OC_POS_LEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_RIGHT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_RIGHT);
}

void OCPosDescription::set_OC_POS_RIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_CENTRE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_CENTRE);
}

void OCPosDescription::set_OC_POS_CENTRE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_TOPLEFT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_TOPLEFT);
}

void OCPosDescription::set_OC_POS_TOPLEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_BOTTOMLEFT);
}

void OCPosDescription::set_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_CENTRELEFT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_CENTRELEFT);
}

void OCPosDescription::set_OC_POS_CENTRELEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_CENTRERIGHT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_CENTRERIGHT);
}

void OCPosDescription::set_OC_POS_CENTRERIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_BOTTOMRIGHT);
}

void OCPosDescription::set_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_TOPRIGHT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_TOPRIGHT);
}

void OCPosDescription::set_OC_POS_TOPRIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_TOPCENTRE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_TOPCENTRE);
}

void OCPosDescription::set_OC_POS_TOPCENTRE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPosDescription::get_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POS_BOTTOMCENTRE);
}

void OCPosDescription::set_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCPool::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCPool", {
    OCPool::InstanceAccessor("BYTE_POOL", &OCPool::get_BYTE_POOL, nullptr),
    OCPool::InstanceAccessor("INT_POOL", &OCPool::get_INT_POOL, nullptr),
    OCPool::InstanceAccessor("DOUBLE_POOL", &OCPool::get_DOUBLE_POOL, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCPool::OCPool(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<pool>(new pool());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<pool>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCPool::get_BYTE_POOL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), BYTE_POOL);
}

void OCPool::set_BYTE_POOL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPool::get_INT_POOL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), INT_POOL);
}

void OCPool::set_INT_POOL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPool::get_DOUBLE_POOL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), DOUBLE_POOL);
}

void OCPool::set_DOUBLE_POOL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCInterfaceEvent::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCInterfaceEvent", {
    OCInterfaceEvent::InstanceAccessor("NETWORK_INTERFACE_DOWN", &OCInterfaceEvent::get_NETWORK_INTERFACE_DOWN, nullptr),
    OCInterfaceEvent::InstanceAccessor("NETWORK_INTERFACE_UP", &OCInterfaceEvent::get_NETWORK_INTERFACE_UP, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCInterfaceEvent::OCInterfaceEvent(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_interface_event_t>(new oc_interface_event_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_interface_event_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCInterfaceEvent::get_NETWORK_INTERFACE_DOWN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), NETWORK_INTERFACE_DOWN);
}

void OCInterfaceEvent::set_NETWORK_INTERFACE_DOWN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceEvent::get_NETWORK_INTERFACE_UP(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), NETWORK_INTERFACE_UP);
}

void OCInterfaceEvent::set_NETWORK_INTERFACE_UP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCSpTypes::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSpTypes", {
    OCSpTypes::InstanceAccessor("OC_SP_BASELINE", &OCSpTypes::get_OC_SP_BASELINE, nullptr),
    OCSpTypes::InstanceAccessor("OC_SP_BLACK", &OCSpTypes::get_OC_SP_BLACK, nullptr),
    OCSpTypes::InstanceAccessor("OC_SP_BLUE", &OCSpTypes::get_OC_SP_BLUE, nullptr),
    OCSpTypes::InstanceAccessor("OC_SP_PURPLE", &OCSpTypes::get_OC_SP_PURPLE, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSpTypes::OCSpTypes(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_sp_types_t>(new oc_sp_types_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_sp_types_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSpTypes::get_OC_SP_BASELINE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SP_BASELINE);
}

void OCSpTypes::set_OC_SP_BASELINE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSpTypes::get_OC_SP_BLACK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SP_BLACK);
}

void OCSpTypes::set_OC_SP_BLACK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSpTypes::get_OC_SP_BLUE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SP_BLUE);
}

void OCSpTypes::set_OC_SP_BLUE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSpTypes::get_OC_SP_PURPLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SP_PURPLE);
}

void OCSpTypes::set_OC_SP_PURPLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCRepValueType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRepValueType", {
    OCRepValueType::InstanceAccessor("OC_REP_NIL", &OCRepValueType::get_OC_REP_NIL, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_INT", &OCRepValueType::get_OC_REP_INT, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_DOUBLE", &OCRepValueType::get_OC_REP_DOUBLE, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_BOOL", &OCRepValueType::get_OC_REP_BOOL, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_BYTE_STRING", &OCRepValueType::get_OC_REP_BYTE_STRING, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_STRING", &OCRepValueType::get_OC_REP_STRING, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_OBJECT", &OCRepValueType::get_OC_REP_OBJECT, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_ARRAY", &OCRepValueType::get_OC_REP_ARRAY, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_INT_ARRAY", &OCRepValueType::get_OC_REP_INT_ARRAY, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_DOUBLE_ARRAY", &OCRepValueType::get_OC_REP_DOUBLE_ARRAY, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_BOOL_ARRAY", &OCRepValueType::get_OC_REP_BOOL_ARRAY, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_BYTE_STRING_ARRAY", &OCRepValueType::get_OC_REP_BYTE_STRING_ARRAY, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_STRING_ARRAY", &OCRepValueType::get_OC_REP_STRING_ARRAY, nullptr),
    OCRepValueType::InstanceAccessor("OC_REP_OBJECT_ARRAY", &OCRepValueType::get_OC_REP_OBJECT_ARRAY, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRepValueType::OCRepValueType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_rep_value_type_t>(new oc_rep_value_type_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_rep_value_type_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCRepValueType::get_OC_REP_NIL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_NIL);
}

void OCRepValueType::set_OC_REP_NIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_INT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_INT);
}

void OCRepValueType::set_OC_REP_INT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_DOUBLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_DOUBLE);
}

void OCRepValueType::set_OC_REP_DOUBLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_BOOL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_BOOL);
}

void OCRepValueType::set_OC_REP_BOOL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_BYTE_STRING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_BYTE_STRING);
}

void OCRepValueType::set_OC_REP_BYTE_STRING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_STRING(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_STRING);
}

void OCRepValueType::set_OC_REP_STRING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_OBJECT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_OBJECT);
}

void OCRepValueType::set_OC_REP_OBJECT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_ARRAY);
}

void OCRepValueType::set_OC_REP_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_INT_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_INT_ARRAY);
}

void OCRepValueType::set_OC_REP_INT_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_DOUBLE_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_DOUBLE_ARRAY);
}

void OCRepValueType::set_OC_REP_DOUBLE_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_BOOL_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_BOOL_ARRAY);
}

void OCRepValueType::set_OC_REP_BOOL_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_BYTE_STRING_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_BYTE_STRING_ARRAY);
}

void OCRepValueType::set_OC_REP_BYTE_STRING_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_STRING_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_STRING_ARRAY);
}

void OCRepValueType::set_OC_REP_STRING_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCRepValueType::get_OC_REP_OBJECT_ARRAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_REP_OBJECT_ARRAY);
}

void OCRepValueType::set_OC_REP_OBJECT_ARRAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCContentFormat::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCContentFormat", {
    OCContentFormat::InstanceAccessor("TEXT_PLAIN", &OCContentFormat::get_TEXT_PLAIN, nullptr),
    OCContentFormat::InstanceAccessor("TEXT_XML", &OCContentFormat::get_TEXT_XML, nullptr),
    OCContentFormat::InstanceAccessor("TEXT_CSV", &OCContentFormat::get_TEXT_CSV, nullptr),
    OCContentFormat::InstanceAccessor("TEXT_HTML", &OCContentFormat::get_TEXT_HTML, nullptr),
    OCContentFormat::InstanceAccessor("IMAGE_GIF", &OCContentFormat::get_IMAGE_GIF, nullptr),
    OCContentFormat::InstanceAccessor("IMAGE_JPEG", &OCContentFormat::get_IMAGE_JPEG, nullptr),
    OCContentFormat::InstanceAccessor("IMAGE_PNG", &OCContentFormat::get_IMAGE_PNG, nullptr),
    OCContentFormat::InstanceAccessor("IMAGE_TIFF", &OCContentFormat::get_IMAGE_TIFF, nullptr),
    OCContentFormat::InstanceAccessor("AUDIO_RAW", &OCContentFormat::get_AUDIO_RAW, nullptr),
    OCContentFormat::InstanceAccessor("VIDEO_RAW", &OCContentFormat::get_VIDEO_RAW, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_LINK_FORMAT", &OCContentFormat::get_APPLICATION_LINK_FORMAT, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_XML", &OCContentFormat::get_APPLICATION_XML, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_OCTET_STREAM", &OCContentFormat::get_APPLICATION_OCTET_STREAM, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_RDF_XML", &OCContentFormat::get_APPLICATION_RDF_XML, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_SOAP_XML", &OCContentFormat::get_APPLICATION_SOAP_XML, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_ATOM_XML", &OCContentFormat::get_APPLICATION_ATOM_XML, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_XMPP_XML", &OCContentFormat::get_APPLICATION_XMPP_XML, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_EXI", &OCContentFormat::get_APPLICATION_EXI, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_FASTINFOSET", &OCContentFormat::get_APPLICATION_FASTINFOSET, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_SOAP_FASTINFOSET", &OCContentFormat::get_APPLICATION_SOAP_FASTINFOSET, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_JSON", &OCContentFormat::get_APPLICATION_JSON, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_X_OBIX_BINARY", &OCContentFormat::get_APPLICATION_X_OBIX_BINARY, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_CBOR", &OCContentFormat::get_APPLICATION_CBOR, nullptr),
    OCContentFormat::InstanceAccessor("APPLICATION_VND_OCF_CBOR", &OCContentFormat::get_APPLICATION_VND_OCF_CBOR, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCContentFormat::OCContentFormat(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_content_format_t>(new oc_content_format_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_content_format_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCContentFormat::get_TEXT_PLAIN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), TEXT_PLAIN);
}

void OCContentFormat::set_TEXT_PLAIN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_TEXT_XML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), TEXT_XML);
}

void OCContentFormat::set_TEXT_XML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_TEXT_CSV(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), TEXT_CSV);
}

void OCContentFormat::set_TEXT_CSV(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_TEXT_HTML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), TEXT_HTML);
}

void OCContentFormat::set_TEXT_HTML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_IMAGE_GIF(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), IMAGE_GIF);
}

void OCContentFormat::set_IMAGE_GIF(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_IMAGE_JPEG(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), IMAGE_JPEG);
}

void OCContentFormat::set_IMAGE_JPEG(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_IMAGE_PNG(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), IMAGE_PNG);
}

void OCContentFormat::set_IMAGE_PNG(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_IMAGE_TIFF(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), IMAGE_TIFF);
}

void OCContentFormat::set_IMAGE_TIFF(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_AUDIO_RAW(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), AUDIO_RAW);
}

void OCContentFormat::set_AUDIO_RAW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_VIDEO_RAW(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), VIDEO_RAW);
}

void OCContentFormat::set_VIDEO_RAW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_LINK_FORMAT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_LINK_FORMAT);
}

void OCContentFormat::set_APPLICATION_LINK_FORMAT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_XML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_XML);
}

void OCContentFormat::set_APPLICATION_XML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_OCTET_STREAM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_OCTET_STREAM);
}

void OCContentFormat::set_APPLICATION_OCTET_STREAM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_RDF_XML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_RDF_XML);
}

void OCContentFormat::set_APPLICATION_RDF_XML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_SOAP_XML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_SOAP_XML);
}

void OCContentFormat::set_APPLICATION_SOAP_XML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_ATOM_XML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_ATOM_XML);
}

void OCContentFormat::set_APPLICATION_ATOM_XML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_XMPP_XML(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_XMPP_XML);
}

void OCContentFormat::set_APPLICATION_XMPP_XML(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_EXI(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_EXI);
}

void OCContentFormat::set_APPLICATION_EXI(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_FASTINFOSET(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_FASTINFOSET);
}

void OCContentFormat::set_APPLICATION_FASTINFOSET(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_SOAP_FASTINFOSET(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_SOAP_FASTINFOSET);
}

void OCContentFormat::set_APPLICATION_SOAP_FASTINFOSET(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_JSON(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_JSON);
}

void OCContentFormat::set_APPLICATION_JSON(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_X_OBIX_BINARY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_X_OBIX_BINARY);
}

void OCContentFormat::set_APPLICATION_X_OBIX_BINARY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_CBOR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_CBOR);
}

void OCContentFormat::set_APPLICATION_CBOR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCContentFormat::get_APPLICATION_VND_OCF_CBOR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), APPLICATION_VND_OCF_CBOR);
}

void OCContentFormat::set_APPLICATION_VND_OCF_CBOR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCCoreResource::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCoreResource", {
    OCCoreResource::InstanceAccessor("OCF_P", &OCCoreResource::get_OCF_P, nullptr),
    OCCoreResource::InstanceAccessor("OCF_CON", &OCCoreResource::get_OCF_CON, nullptr),
    OCCoreResource::InstanceAccessor("OCF_INTROSPECTION_WK", &OCCoreResource::get_OCF_INTROSPECTION_WK, nullptr),
    OCCoreResource::InstanceAccessor("OCF_INTROSPECTION_DATA", &OCCoreResource::get_OCF_INTROSPECTION_DATA, nullptr),
    OCCoreResource::InstanceAccessor("OCF_RES", &OCCoreResource::get_OCF_RES, nullptr),
    OCCoreResource::InstanceAccessor("OCF_MNT", &OCCoreResource::get_OCF_MNT, nullptr),
    OCCoreResource::InstanceAccessor("OCF_COAPCLOUDCONF", &OCCoreResource::get_OCF_COAPCLOUDCONF, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SW_UPDATE", &OCCoreResource::get_OCF_SW_UPDATE, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_DOXM", &OCCoreResource::get_OCF_SEC_DOXM, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_PSTAT", &OCCoreResource::get_OCF_SEC_PSTAT, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_ACL", &OCCoreResource::get_OCF_SEC_ACL, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_AEL", &OCCoreResource::get_OCF_SEC_AEL, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_CRED", &OCCoreResource::get_OCF_SEC_CRED, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_SDI", &OCCoreResource::get_OCF_SEC_SDI, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_SP", &OCCoreResource::get_OCF_SEC_SP, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_CSR", &OCCoreResource::get_OCF_SEC_CSR, nullptr),
    OCCoreResource::InstanceAccessor("OCF_SEC_ROLES", &OCCoreResource::get_OCF_SEC_ROLES, nullptr),
    OCCoreResource::InstanceAccessor("OCF_D", &OCCoreResource::get_OCF_D, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCoreResource::OCCoreResource(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_core_resource_t>(new oc_core_resource_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_core_resource_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCCoreResource::get_OCF_P(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_P);
}

void OCCoreResource::set_OCF_P(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCoreResource::get_OCF_CON(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_CON);
}

void OCCoreResource::set_OCF_CON(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCoreResource::get_OCF_INTROSPECTION_WK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_INTROSPECTION_WK);
}

void OCCoreResource::set_OCF_INTROSPECTION_WK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCoreResource::get_OCF_INTROSPECTION_DATA(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_INTROSPECTION_DATA);
}

void OCCoreResource::set_OCF_INTROSPECTION_DATA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCoreResource::get_OCF_RES(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_RES);
}

void OCCoreResource::set_OCF_RES(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

#ifdef OC_MNT
Napi::Value OCCoreResource::get_OCF_MNT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_MNT);
}

void OCCoreResource::set_OCF_MNT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_CLOUD
Napi::Value OCCoreResource::get_OCF_COAPCLOUDCONF(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_COAPCLOUDCONF);
}

void OCCoreResource::set_OCF_COAPCLOUDCONF(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SOFTWARE_UPDATE
Napi::Value OCCoreResource::get_OCF_SW_UPDATE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SW_UPDATE);
}

void OCCoreResource::set_OCF_SW_UPDATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_DOXM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_DOXM);
}

void OCCoreResource::set_OCF_SEC_DOXM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_PSTAT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_PSTAT);
}

void OCCoreResource::set_OCF_SEC_PSTAT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_ACL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_ACL);
}

void OCCoreResource::set_OCF_SEC_ACL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_AEL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_AEL);
}

void OCCoreResource::set_OCF_SEC_AEL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_CRED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_CRED);
}

void OCCoreResource::set_OCF_SEC_CRED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_SDI(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_SDI);
}

void OCCoreResource::set_OCF_SEC_SDI(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_SECURITY
Napi::Value OCCoreResource::get_OCF_SEC_SP(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_SP);
}

void OCCoreResource::set_OCF_SEC_SP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_PKI
Napi::Value OCCoreResource::get_OCF_SEC_CSR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_CSR);
}

void OCCoreResource::set_OCF_SEC_CSR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#ifdef OC_PKI
Napi::Value OCCoreResource::get_OCF_SEC_ROLES(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_SEC_ROLES);
}

void OCCoreResource::set_OCF_SEC_ROLES(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

Napi::Value OCCoreResource::get_OCF_D(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OCF_D);
}

void OCCoreResource::set_OCF_D(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCEventCallbackRetval::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEventCallbackRetval", {
    OCEventCallbackRetval::InstanceAccessor("OC_EVENT_DONE", &OCEventCallbackRetval::get_OC_EVENT_DONE, nullptr),
    OCEventCallbackRetval::InstanceAccessor("OC_EVENT_CONTINUE", &OCEventCallbackRetval::get_OC_EVENT_CONTINUE, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEventCallbackRetval::OCEventCallbackRetval(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_event_callback_retval_t>(new oc_event_callback_retval_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_event_callback_retval_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCEventCallbackRetval::get_OC_EVENT_DONE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_EVENT_DONE);
}

void OCEventCallbackRetval::set_OC_EVENT_DONE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEventCallbackRetval::get_OC_EVENT_CONTINUE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_EVENT_CONTINUE);
}

void OCEventCallbackRetval::set_OC_EVENT_CONTINUE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCInterfaceMask::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCInterfaceMask", {
    OCInterfaceMask::InstanceAccessor("OC_IF_BASELINE", &OCInterfaceMask::get_OC_IF_BASELINE, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_LL", &OCInterfaceMask::get_OC_IF_LL, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_B", &OCInterfaceMask::get_OC_IF_B, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_R", &OCInterfaceMask::get_OC_IF_R, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_RW", &OCInterfaceMask::get_OC_IF_RW, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_A", &OCInterfaceMask::get_OC_IF_A, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_S", &OCInterfaceMask::get_OC_IF_S, nullptr),
    OCInterfaceMask::InstanceAccessor("OC_IF_CREATE", &OCInterfaceMask::get_OC_IF_CREATE, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCInterfaceMask::OCInterfaceMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_interface_mask_t>(new oc_interface_mask_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_interface_mask_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCInterfaceMask::get_OC_IF_BASELINE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_BASELINE);
}

void OCInterfaceMask::set_OC_IF_BASELINE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_LL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_LL);
}

void OCInterfaceMask::set_OC_IF_LL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_B(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_B);
}

void OCInterfaceMask::set_OC_IF_B(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_R(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_R);
}

void OCInterfaceMask::set_OC_IF_R(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_RW(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_RW);
}

void OCInterfaceMask::set_OC_IF_RW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_A(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_A);
}

void OCInterfaceMask::set_OC_IF_A(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_S(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_S);
}

void OCInterfaceMask::set_OC_IF_S(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCInterfaceMask::get_OC_IF_CREATE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IF_CREATE);
}

void OCInterfaceMask::set_OC_IF_CREATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCMethod::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCMethod", {
    OCMethod::InstanceAccessor("OC_GET", &OCMethod::get_OC_GET, nullptr),
    OCMethod::InstanceAccessor("OC_POST", &OCMethod::get_OC_POST, nullptr),
    OCMethod::InstanceAccessor("OC_PUT", &OCMethod::get_OC_PUT, nullptr),
    OCMethod::InstanceAccessor("OC_DELETE", &OCMethod::get_OC_DELETE, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCMethod::OCMethod(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_method_t>(new oc_method_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_method_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCMethod::get_OC_GET(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_GET);
}

void OCMethod::set_OC_GET(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCMethod::get_OC_POST(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_POST);
}

void OCMethod::set_OC_POST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCMethod::get_OC_PUT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PUT);
}

void OCMethod::set_OC_PUT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCMethod::get_OC_DELETE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_DELETE);
}

void OCMethod::set_OC_DELETE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCResourceProperties::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResourceProperties", {
    OCResourceProperties::InstanceAccessor("OC_DISCOVERABLE", &OCResourceProperties::get_OC_DISCOVERABLE, nullptr),
    OCResourceProperties::InstanceAccessor("OC_OBSERVABLE", &OCResourceProperties::get_OC_OBSERVABLE, nullptr),
    OCResourceProperties::InstanceAccessor("OC_SECURE", &OCResourceProperties::get_OC_SECURE, nullptr),
    OCResourceProperties::InstanceAccessor("OC_PERIODIC", &OCResourceProperties::get_OC_PERIODIC, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCResourceProperties::OCResourceProperties(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_resource_properties_t>(new oc_resource_properties_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_resource_properties_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCResourceProperties::get_OC_DISCOVERABLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_DISCOVERABLE);
}

void OCResourceProperties::set_OC_DISCOVERABLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourceProperties::get_OC_OBSERVABLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_OBSERVABLE);
}

void OCResourceProperties::set_OC_OBSERVABLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourceProperties::get_OC_SECURE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SECURE);
}

void OCResourceProperties::set_OC_SECURE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourceProperties::get_OC_PERIODIC(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PERIODIC);
}

void OCResourceProperties::set_OC_PERIODIC(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCStatus::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCStatus", {
    OCStatus::InstanceAccessor("OC_STATUS_OK", &OCStatus::get_OC_STATUS_OK, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_CREATED", &OCStatus::get_OC_STATUS_CREATED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_CHANGED", &OCStatus::get_OC_STATUS_CHANGED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_DELETED", &OCStatus::get_OC_STATUS_DELETED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_NOT_MODIFIED", &OCStatus::get_OC_STATUS_NOT_MODIFIED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_BAD_REQUEST", &OCStatus::get_OC_STATUS_BAD_REQUEST, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_UNAUTHORIZED", &OCStatus::get_OC_STATUS_UNAUTHORIZED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_BAD_OPTION", &OCStatus::get_OC_STATUS_BAD_OPTION, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_FORBIDDEN", &OCStatus::get_OC_STATUS_FORBIDDEN, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_NOT_FOUND", &OCStatus::get_OC_STATUS_NOT_FOUND, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_METHOD_NOT_ALLOWED", &OCStatus::get_OC_STATUS_METHOD_NOT_ALLOWED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_NOT_ACCEPTABLE", &OCStatus::get_OC_STATUS_NOT_ACCEPTABLE, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_REQUEST_ENTITY_TOO_LARGE", &OCStatus::get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_UNSUPPORTED_MEDIA_TYPE", &OCStatus::get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_INTERNAL_SERVER_ERROR", &OCStatus::get_OC_STATUS_INTERNAL_SERVER_ERROR, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_NOT_IMPLEMENTED", &OCStatus::get_OC_STATUS_NOT_IMPLEMENTED, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_BAD_GATEWAY", &OCStatus::get_OC_STATUS_BAD_GATEWAY, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_SERVICE_UNAVAILABLE", &OCStatus::get_OC_STATUS_SERVICE_UNAVAILABLE, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_GATEWAY_TIMEOUT", &OCStatus::get_OC_STATUS_GATEWAY_TIMEOUT, nullptr),
    OCStatus::InstanceAccessor("OC_STATUS_PROXYING_NOT_SUPPORTED", &OCStatus::get_OC_STATUS_PROXYING_NOT_SUPPORTED, nullptr),
    OCStatus::InstanceAccessor("__NUM_OC_STATUS_CODES__", &OCStatus::get___NUM_OC_STATUS_CODES__, nullptr),
    OCStatus::InstanceAccessor("OC_IGNORE", &OCStatus::get_OC_IGNORE, nullptr),
    OCStatus::InstanceAccessor("OC_PING_TIMEOUT", &OCStatus::get_OC_PING_TIMEOUT, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCStatus::OCStatus(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_status_t>(new oc_status_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_status_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCStatus::get_OC_STATUS_OK(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_OK);
}

void OCStatus::set_OC_STATUS_OK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_CREATED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_CREATED);
}

void OCStatus::set_OC_STATUS_CREATED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_CHANGED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_CHANGED);
}

void OCStatus::set_OC_STATUS_CHANGED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_DELETED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_DELETED);
}

void OCStatus::set_OC_STATUS_DELETED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_NOT_MODIFIED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_NOT_MODIFIED);
}

void OCStatus::set_OC_STATUS_NOT_MODIFIED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_BAD_REQUEST(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_BAD_REQUEST);
}

void OCStatus::set_OC_STATUS_BAD_REQUEST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_UNAUTHORIZED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_UNAUTHORIZED);
}

void OCStatus::set_OC_STATUS_UNAUTHORIZED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_BAD_OPTION(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_BAD_OPTION);
}

void OCStatus::set_OC_STATUS_BAD_OPTION(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_FORBIDDEN(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_FORBIDDEN);
}

void OCStatus::set_OC_STATUS_FORBIDDEN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_NOT_FOUND(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_NOT_FOUND);
}

void OCStatus::set_OC_STATUS_NOT_FOUND(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_METHOD_NOT_ALLOWED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_METHOD_NOT_ALLOWED);
}

void OCStatus::set_OC_STATUS_METHOD_NOT_ALLOWED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_NOT_ACCEPTABLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_NOT_ACCEPTABLE);
}

void OCStatus::set_OC_STATUS_NOT_ACCEPTABLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_REQUEST_ENTITY_TOO_LARGE);
}

void OCStatus::set_OC_STATUS_REQUEST_ENTITY_TOO_LARGE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_UNSUPPORTED_MEDIA_TYPE);
}

void OCStatus::set_OC_STATUS_UNSUPPORTED_MEDIA_TYPE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_INTERNAL_SERVER_ERROR(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_INTERNAL_SERVER_ERROR);
}

void OCStatus::set_OC_STATUS_INTERNAL_SERVER_ERROR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_NOT_IMPLEMENTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_NOT_IMPLEMENTED);
}

void OCStatus::set_OC_STATUS_NOT_IMPLEMENTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_BAD_GATEWAY(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_BAD_GATEWAY);
}

void OCStatus::set_OC_STATUS_BAD_GATEWAY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_SERVICE_UNAVAILABLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_SERVICE_UNAVAILABLE);
}

void OCStatus::set_OC_STATUS_SERVICE_UNAVAILABLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_GATEWAY_TIMEOUT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_GATEWAY_TIMEOUT);
}

void OCStatus::set_OC_STATUS_GATEWAY_TIMEOUT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_STATUS_PROXYING_NOT_SUPPORTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_STATUS_PROXYING_NOT_SUPPORTED);
}

void OCStatus::set_OC_STATUS_PROXYING_NOT_SUPPORTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get___NUM_OC_STATUS_CODES__(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), __NUM_OC_STATUS_CODES__);
}

void OCStatus::set___NUM_OC_STATUS_CODES__(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_IGNORE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_IGNORE);
}

void OCStatus::set_OC_IGNORE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCStatus::get_OC_PING_TIMEOUT(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_PING_TIMEOUT);
}

void OCStatus::set_OC_PING_TIMEOUT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCSessionState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSessionState", {
    OCSessionState::InstanceAccessor("OC_SESSION_CONNECTED", &OCSessionState::get_OC_SESSION_CONNECTED, nullptr),
    OCSessionState::InstanceAccessor("OC_SESSION_DISCONNECTED", &OCSessionState::get_OC_SESSION_DISCONNECTED, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSessionState::OCSessionState(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_session_state_t>(new oc_session_state_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_session_state_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSessionState::get_OC_SESSION_CONNECTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SESSION_CONNECTED);
}

void OCSessionState::set_OC_SESSION_CONNECTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSessionState::get_OC_SESSION_DISCONNECTED(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SESSION_DISCONNECTED);
}

void OCSessionState::set_OC_SESSION_DISCONNECTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Function OCSwupdateResult::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSwupdateResult", {
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_IDLE", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_IDLE, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_SUCCESS", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_SUCCESS, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_LESS_RAM", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_LESS_FLASH", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_CONN_FAIL", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_SVV_FAIL", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_INVALID_URL", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL, nullptr),
    OCSwupdateResult::InstanceAccessor("OC_SWUPDATE_RESULT_UPGRADE_FAIL", &OCSwupdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL, nullptr),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSwupdateResult::OCSwupdateResult(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_swupdate_result_t>(new oc_swupdate_result_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_swupdate_result_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_IDLE);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_SUCCESS);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_LESS_RAM);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_LESS_FLASH);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_CONN_FAIL);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_SVV_FAIL);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_INVALID_URL);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSwupdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo& info)
{
return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_UPGRADE_FAIL);
}

void OCSwupdateResult::set_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

