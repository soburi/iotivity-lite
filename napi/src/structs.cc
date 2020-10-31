#include "structs.h"
#include "helper.h"
Napi::FunctionReference coapObserver::constructor;

Napi::Function coapObserver::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapObserver", {
    coapObserver::InstanceAccessor("block2_size", &coapObserver::get_block2_size, &coapObserver::set_block2_size),
    coapObserver::InstanceAccessor("endpoint", &coapObserver::get_endpoint, &coapObserver::set_endpoint),
    coapObserver::InstanceAccessor("iface_mask", &coapObserver::get_iface_mask, &coapObserver::set_iface_mask),
    coapObserver::InstanceAccessor("last_mid", &coapObserver::get_last_mid, &coapObserver::set_last_mid),
    coapObserver::InstanceAccessor("obs_counter", &coapObserver::get_obs_counter, &coapObserver::set_obs_counter),
    coapObserver::InstanceAccessor("retrans_counter", &coapObserver::get_retrans_counter, &coapObserver::set_retrans_counter),
    coapObserver::InstanceAccessor("retrans_timer", &coapObserver::get_retrans_timer, &coapObserver::set_retrans_timer),
    coapObserver::InstanceAccessor("token_len", &coapObserver::get_token_len, &coapObserver::set_token_len),
    coapObserver::InstanceAccessor("url", &coapObserver::get_url, &coapObserver::set_url),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapObserver::coapObserver(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_observer>(new coap_observer());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_observer>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapObserver::get_block2_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block2_size);
}

void coapObserver::set_block2_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block2_size = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapObserver::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void coapObserver::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value coapObserver::get_iface_mask(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->iface_mask);
}

void coapObserver::set_iface_mask(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->iface_mask = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapObserver::get_last_mid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->last_mid);
}

void coapObserver::set_last_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->last_mid = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapObserver::get_obs_counter(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->obs_counter);
}

void coapObserver::set_obs_counter(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->obs_counter = value.As<Napi::Number>().Int32Value();
}

Napi::Value coapObserver::get_retrans_counter(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->retrans_counter);
}

void coapObserver::set_retrans_counter(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->retrans_counter = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapObserver::get_retrans_timer(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_etimer> sp(&m_pvalue->retrans_timer);
  auto accessor = Napi::External<std::shared_ptr<oc_etimer>>::New(info.Env(), &sp);
  return OCEtimer::constructor.New({accessor});
}

void coapObserver::set_retrans_timer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->retrans_timer = *(*(value.As<Napi::External<std::shared_ptr<oc_etimer>>>().Data()));
}

Napi::Value coapObserver::get_token_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->token_len);
}

void coapObserver::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->token_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapObserver::get_url(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->url);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void coapObserver::set_url(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->url = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference coapPacket::constructor;

Napi::Function coapPacket::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapPacket", {
    coapPacket::InstanceAccessor("accept", &coapPacket::get_accept, &coapPacket::set_accept),
    coapPacket::InstanceAccessor("alt_addr_len", &coapPacket::get_alt_addr_len, &coapPacket::set_alt_addr_len),
    coapPacket::InstanceAccessor("bad_csm_opt", &coapPacket::get_bad_csm_opt, &coapPacket::set_bad_csm_opt),
    coapPacket::InstanceAccessor("block1_more", &coapPacket::get_block1_more, &coapPacket::set_block1_more),
    coapPacket::InstanceAccessor("block1_num", &coapPacket::get_block1_num, &coapPacket::set_block1_num),
    coapPacket::InstanceAccessor("block1_offset", &coapPacket::get_block1_offset, &coapPacket::set_block1_offset),
    coapPacket::InstanceAccessor("block1_size", &coapPacket::get_block1_size, &coapPacket::set_block1_size),
    coapPacket::InstanceAccessor("block2_more", &coapPacket::get_block2_more, &coapPacket::set_block2_more),
    coapPacket::InstanceAccessor("block2_num", &coapPacket::get_block2_num, &coapPacket::set_block2_num),
    coapPacket::InstanceAccessor("block2_offset", &coapPacket::get_block2_offset, &coapPacket::set_block2_offset),
    coapPacket::InstanceAccessor("block2_size", &coapPacket::get_block2_size, &coapPacket::set_block2_size),
    coapPacket::InstanceAccessor("blockwise_transfer", &coapPacket::get_blockwise_transfer, &coapPacket::set_blockwise_transfer),
    coapPacket::InstanceAccessor("code", &coapPacket::get_code, &coapPacket::set_code),
    coapPacket::InstanceAccessor("content_format", &coapPacket::get_content_format, &coapPacket::set_content_format),
    coapPacket::InstanceAccessor("custody", &coapPacket::get_custody, &coapPacket::set_custody),
    coapPacket::InstanceAccessor("etag_len", &coapPacket::get_etag_len, &coapPacket::set_etag_len),
    coapPacket::InstanceAccessor("hold_off", &coapPacket::get_hold_off, &coapPacket::set_hold_off),
    coapPacket::InstanceAccessor("if_match_len", &coapPacket::get_if_match_len, &coapPacket::set_if_match_len),
    coapPacket::InstanceAccessor("if_none_match", &coapPacket::get_if_none_match, &coapPacket::set_if_none_match),
    coapPacket::InstanceAccessor("location_path_len", &coapPacket::get_location_path_len, &coapPacket::set_location_path_len),
    coapPacket::InstanceAccessor("location_query_len", &coapPacket::get_location_query_len, &coapPacket::set_location_query_len),
    coapPacket::InstanceAccessor("max_age", &coapPacket::get_max_age, &coapPacket::set_max_age),
    coapPacket::InstanceAccessor("max_msg_size", &coapPacket::get_max_msg_size, &coapPacket::set_max_msg_size),
    coapPacket::InstanceAccessor("mid", &coapPacket::get_mid, &coapPacket::set_mid),
    coapPacket::InstanceAccessor("observe", &coapPacket::get_observe, &coapPacket::set_observe),
    coapPacket::InstanceAccessor("payload_len", &coapPacket::get_payload_len, &coapPacket::set_payload_len),
    coapPacket::InstanceAccessor("proxy_scheme_len", &coapPacket::get_proxy_scheme_len, &coapPacket::set_proxy_scheme_len),
    coapPacket::InstanceAccessor("proxy_uri_len", &coapPacket::get_proxy_uri_len, &coapPacket::set_proxy_uri_len),
    coapPacket::InstanceAccessor("size1", &coapPacket::get_size1, &coapPacket::set_size1),
    coapPacket::InstanceAccessor("size2", &coapPacket::get_size2, &coapPacket::set_size2),
    coapPacket::InstanceAccessor("token_len", &coapPacket::get_token_len, &coapPacket::set_token_len),
    coapPacket::InstanceAccessor("transport_type", &coapPacket::get_transport_type, &coapPacket::set_transport_type),
    coapPacket::InstanceAccessor("type", &coapPacket::get_type, &coapPacket::set_type),
    coapPacket::InstanceAccessor("uri_host_len", &coapPacket::get_uri_host_len, &coapPacket::set_uri_host_len),
    coapPacket::InstanceAccessor("uri_path_len", &coapPacket::get_uri_path_len, &coapPacket::set_uri_path_len),
    coapPacket::InstanceAccessor("uri_port", &coapPacket::get_uri_port, &coapPacket::set_uri_port),
    coapPacket::InstanceAccessor("uri_query_len", &coapPacket::get_uri_query_len, &coapPacket::set_uri_query_len),
    coapPacket::InstanceAccessor("version", &coapPacket::get_version, &coapPacket::set_version),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapPacket::coapPacket(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_packet_t>(new coap_packet_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_packet_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapPacket::get_accept(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->accept);
}

void coapPacket::set_accept(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->accept = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_alt_addr_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->alt_addr_len);
}

void coapPacket::set_alt_addr_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->alt_addr_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_bad_csm_opt(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->bad_csm_opt);
}

void coapPacket::set_bad_csm_opt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->bad_csm_opt = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_block1_more(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block1_more);
}

void coapPacket::set_block1_more(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block1_more = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_block1_num(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block1_num);
}

void coapPacket::set_block1_num(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block1_num = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_block1_offset(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block1_offset);
}

void coapPacket::set_block1_offset(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block1_offset = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_block1_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block1_size);
}

void coapPacket::set_block1_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block1_size = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_block2_more(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block2_more);
}

void coapPacket::set_block2_more(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block2_more = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_block2_num(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block2_num);
}

void coapPacket::set_block2_num(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block2_num = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_block2_offset(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block2_offset);
}

void coapPacket::set_block2_offset(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block2_offset = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_block2_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block2_size);
}

void coapPacket::set_block2_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block2_size = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_blockwise_transfer(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->blockwise_transfer);
}

void coapPacket::set_blockwise_transfer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->blockwise_transfer = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_code(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->code);
}

void coapPacket::set_code(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->code = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_content_format(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->content_format);
}

void coapPacket::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->content_format = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_custody(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->custody);
}

void coapPacket::set_custody(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->custody = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_etag_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->etag_len);
}

void coapPacket::set_etag_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->etag_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_hold_off(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->hold_off);
}

void coapPacket::set_hold_off(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->hold_off = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_if_match_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->if_match_len);
}

void coapPacket::set_if_match_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->if_match_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_if_none_match(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->if_none_match);
}

void coapPacket::set_if_none_match(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->if_none_match = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_location_path_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->location_path_len);
}

void coapPacket::set_location_path_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->location_path_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_location_query_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->location_query_len);
}

void coapPacket::set_location_query_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->location_query_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_max_age(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->max_age);
}

void coapPacket::set_max_age(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->max_age = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_max_msg_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->max_msg_size);
}

void coapPacket::set_max_msg_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->max_msg_size = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_mid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->mid);
}

void coapPacket::set_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mid = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_observe(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe);
}

void coapPacket::set_observe(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe = value.As<Napi::Number>().Int32Value();
}

Napi::Value coapPacket::get_payload_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->payload_len);
}

void coapPacket::set_payload_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->payload_len = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_proxy_scheme_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->proxy_scheme_len);
}

void coapPacket::set_proxy_scheme_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->proxy_scheme_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_proxy_uri_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->proxy_uri_len);
}

void coapPacket::set_proxy_uri_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->proxy_uri_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_size1(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->size1);
}

void coapPacket::set_size1(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->size1 = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_size2(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->size2);
}

void coapPacket::set_size2(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->size2 = static_cast<uint32_t>(value.As<Napi::Number>());
}

Napi::Value coapPacket::get_token_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->token_len);
}

void coapPacket::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->token_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_transport_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->transport_type);
}

void coapPacket::set_transport_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->transport_type = static_cast<coap_transport_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->type);
}

void coapPacket::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->type = static_cast<coap_message_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_uri_host_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->uri_host_len);
}

void coapPacket::set_uri_host_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri_host_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_uri_path_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->uri_path_len);
}

void coapPacket::set_uri_path_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri_path_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_uri_port(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->uri_port);
}

void coapPacket::set_uri_port(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri_port = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_uri_query_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->uri_query_len);
}

void coapPacket::set_uri_query_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri_query_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapPacket::get_version(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->version);
}

void coapPacket::set_version(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->version = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::FunctionReference coapSeparate::constructor;

Napi::Function coapSeparate::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapSeparate", {
    coapSeparate::InstanceAccessor("block2_size", &coapSeparate::get_block2_size, &coapSeparate::set_block2_size),
    coapSeparate::InstanceAccessor("endpoint", &coapSeparate::get_endpoint, &coapSeparate::set_endpoint),
    coapSeparate::InstanceAccessor("method", &coapSeparate::get_method, &coapSeparate::set_method),
    coapSeparate::InstanceAccessor("observe", &coapSeparate::get_observe, &coapSeparate::set_observe),
    coapSeparate::InstanceAccessor("token_len", &coapSeparate::get_token_len, &coapSeparate::set_token_len),
    coapSeparate::InstanceAccessor("type", &coapSeparate::get_type, &coapSeparate::set_type),
    coapSeparate::InstanceAccessor("uri", &coapSeparate::get_uri, &coapSeparate::set_uri),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapSeparate::coapSeparate(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_separate>(new coap_separate());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_separate>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapSeparate::get_block2_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->block2_size);
}

void coapSeparate::set_block2_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->block2_size = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapSeparate::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void coapSeparate::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value coapSeparate::get_method(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->method);
}

void coapSeparate::set_method(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->method = static_cast<oc_method_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapSeparate::get_observe(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe);
}

void coapSeparate::set_observe(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe = value.As<Napi::Number>().Int32Value();
}

Napi::Value coapSeparate::get_token_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->token_len);
}

void coapSeparate::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->token_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapSeparate::get_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->type);
}

void coapSeparate::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->type = static_cast<coap_message_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapSeparate::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void coapSeparate::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference coapTransaction::constructor;

Napi::Function coapTransaction::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapTransaction", {
    coapTransaction::InstanceAccessor("message", &coapTransaction::get_message, &coapTransaction::set_message),
    coapTransaction::InstanceAccessor("mid", &coapTransaction::get_mid, &coapTransaction::set_mid),
    coapTransaction::InstanceAccessor("retrans_counter", &coapTransaction::get_retrans_counter, &coapTransaction::set_retrans_counter),
    coapTransaction::InstanceAccessor("retrans_timer", &coapTransaction::get_retrans_timer, &coapTransaction::set_retrans_timer),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapTransaction::coapTransaction(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_transaction>(new coap_transaction());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_transaction>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapTransaction::get_message(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_message_t*> sp(&m_pvalue->message);
  auto accessor = Napi::External<std::shared_ptr<oc_message_t*>>::New(info.Env(), &sp);
  return OCMessage::constructor.New({accessor});
}

void coapTransaction::set_message(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->message = *(*(value.As<Napi::External<std::shared_ptr<oc_message_t*>>>().Data()));
}

Napi::Value coapTransaction::get_mid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->mid);
}

void coapTransaction::set_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mid = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapTransaction::get_retrans_counter(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->retrans_counter);
}

void coapTransaction::set_retrans_counter(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->retrans_counter = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value coapTransaction::get_retrans_timer(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_etimer> sp(&m_pvalue->retrans_timer);
  auto accessor = Napi::External<std::shared_ptr<oc_etimer>>::New(info.Env(), &sp);
  return OCEtimer::constructor.New({accessor});
}

void coapTransaction::set_retrans_timer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->retrans_timer = *(*(value.As<Napi::External<std::shared_ptr<oc_etimer>>>().Data()));
}

Napi::FunctionReference OCAceResource::constructor;

Napi::Function OCAceResource::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceResource", {
    OCAceResource::InstanceAccessor("href", &OCAceResource::get_href, &OCAceResource::set_href),
    OCAceResource::InstanceAccessor("interfaces", &OCAceResource::get_interfaces, &OCAceResource::set_interfaces),
    OCAceResource::InstanceAccessor("types", &OCAceResource::get_types, &OCAceResource::set_types),
    OCAceResource::InstanceAccessor("wildcard", &OCAceResource::get_wildcard, &OCAceResource::set_wildcard),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAceResource::OCAceResource(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCAceResource::get_href(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->href);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCAceResource::set_href(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->href = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCAceResource::get_interfaces(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->interfaces);
}

void OCAceResource::set_interfaces(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->interfaces = static_cast<oc_interface_mask_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCAceResource::get_types(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->types);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCAceResource::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCAceResource::get_wildcard(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->wildcard);
}

void OCAceResource::set_wildcard(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->wildcard = static_cast<oc_ace_wildcard_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::FunctionReference OCBlockwiseRequestState::constructor;

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
  return OCBlockwiseState::constructor.New({accessor});
}

void OCBlockwiseRequestState::set_base(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->base = *(*(value.As<Napi::External<std::shared_ptr<oc_blockwise_state_s>>>().Data()));
}

Napi::FunctionReference OCBlockwiseResponseState::constructor;

Napi::Function OCBlockwiseResponseState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseResponseState", {
    OCBlockwiseResponseState::InstanceAccessor("base", &OCBlockwiseResponseState::get_base, &OCBlockwiseResponseState::set_base),
    OCBlockwiseResponseState::InstanceAccessor("etag", &OCBlockwiseResponseState::get_etag, &OCBlockwiseResponseState::set_etag),
#if defined(OC_CLIENT)
    OCBlockwiseResponseState::InstanceAccessor("observe_seq", &OCBlockwiseResponseState::get_observe_seq, &OCBlockwiseResponseState::set_observe_seq),
#endif

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
  return OCBlockwiseState::constructor.New({accessor});
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

#if defined(OC_CLIENT)
Napi::Value OCBlockwiseResponseState::get_observe_seq(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_seq);
}

void OCBlockwiseResponseState::set_observe_seq(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_seq = value.As<Napi::Number>().Int32Value();
}
#endif

Napi::FunctionReference OCBlockwiseState::constructor;

Napi::Function OCBlockwiseState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseState", {
    OCBlockwiseState::InstanceAccessor("buffer", &OCBlockwiseState::get_buffer, &OCBlockwiseState::set_buffer),
#if defined(OC_CLEINT)
    OCBlockwiseState::InstanceAccessor("client_cb", &OCBlockwiseState::get_client_cb, &OCBlockwiseState::set_client_cb),
#endif
    OCBlockwiseState::InstanceAccessor("endpoint", &OCBlockwiseState::get_endpoint, &OCBlockwiseState::set_endpoint),
    OCBlockwiseState::InstanceAccessor("href", &OCBlockwiseState::get_href, &OCBlockwiseState::set_href),
    OCBlockwiseState::InstanceAccessor("method", &OCBlockwiseState::get_method, &OCBlockwiseState::set_method),
#if defined(OC_CLIENT)
    OCBlockwiseState::InstanceAccessor("mid", &OCBlockwiseState::get_mid, &OCBlockwiseState::set_mid),
#endif
    OCBlockwiseState::InstanceAccessor("next_block_offset", &OCBlockwiseState::get_next_block_offset, &OCBlockwiseState::set_next_block_offset),
    OCBlockwiseState::InstanceAccessor("payload_size", &OCBlockwiseState::get_payload_size, &OCBlockwiseState::set_payload_size),
    OCBlockwiseState::InstanceAccessor("ref_count", &OCBlockwiseState::get_ref_count, &OCBlockwiseState::set_ref_count),
    OCBlockwiseState::InstanceAccessor("role", &OCBlockwiseState::get_role, &OCBlockwiseState::set_role),
#if defined(OC_CLIENT)
    OCBlockwiseState::InstanceAccessor("token", &OCBlockwiseState::get_token, &OCBlockwiseState::set_token),
#endif
#if defined(OC_CLIENT)
    OCBlockwiseState::InstanceAccessor("token_len", &OCBlockwiseState::get_token_len, &OCBlockwiseState::set_token_len),
#endif
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

#if defined(OC_CLEINT)
Napi::Value OCBlockwiseState::get_client_cb(const Napi::CallbackInfo& info)
{
#error void* OCBlockwiseState::client_cb gen_getter_impl
}

void OCBlockwiseState::set_client_cb(const Napi::CallbackInfo& info, const Napi::Value& value)
{
#error void* OCBlockwiseState::client_cb gen_setter_impl
}
#endif

Napi::Value OCBlockwiseState::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCBlockwiseState::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value OCBlockwiseState::get_href(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->href);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
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

#if defined(OC_CLIENT)
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

#if defined(OC_CLIENT)
Napi::Value OCBlockwiseState::get_token(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);
}

void OCBlockwiseState::set_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) { m_pvalue->token[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}
#endif

#if defined(OC_CLIENT)
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
  return OCMmem::constructor.New({accessor});
}

void OCBlockwiseState::set_uri_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri_query = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCClientCallback::constructor;

Napi::Function OCClientCallback::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCClientCallback", {
    OCClientCallback::InstanceAccessor("discovery", &OCClientCallback::get_discovery, &OCClientCallback::set_discovery),
    OCClientCallback::InstanceAccessor("endpoint", &OCClientCallback::get_endpoint, &OCClientCallback::set_endpoint),
    OCClientCallback::InstanceAccessor("handler", &OCClientCallback::get_handler, &OCClientCallback::set_handler),
    OCClientCallback::InstanceAccessor("method", &OCClientCallback::get_method, &OCClientCallback::set_method),
    OCClientCallback::InstanceAccessor("mid", &OCClientCallback::get_mid, &OCClientCallback::set_mid),
    OCClientCallback::InstanceAccessor("multicast", &OCClientCallback::get_multicast, &OCClientCallback::set_multicast),
    OCClientCallback::InstanceAccessor("observe_seq", &OCClientCallback::get_observe_seq, &OCClientCallback::set_observe_seq),
    OCClientCallback::InstanceAccessor("qos", &OCClientCallback::get_qos, &OCClientCallback::set_qos),
    OCClientCallback::InstanceAccessor("query", &OCClientCallback::get_query, &OCClientCallback::set_query),
    OCClientCallback::InstanceAccessor("ref_count", &OCClientCallback::get_ref_count, &OCClientCallback::set_ref_count),
    OCClientCallback::InstanceAccessor("separate", &OCClientCallback::get_separate, &OCClientCallback::set_separate),
    OCClientCallback::InstanceAccessor("stop_multicast_receive", &OCClientCallback::get_stop_multicast_receive, &OCClientCallback::set_stop_multicast_receive),
    OCClientCallback::InstanceAccessor("timestamp", &OCClientCallback::get_timestamp, &OCClientCallback::set_timestamp),
    OCClientCallback::InstanceAccessor("token", &OCClientCallback::get_token, &OCClientCallback::set_token),
    OCClientCallback::InstanceAccessor("token_len", &OCClientCallback::get_token_len, &OCClientCallback::set_token_len),
    OCClientCallback::InstanceAccessor("uri", &OCClientCallback::get_uri, &OCClientCallback::set_uri),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCClientCallback::OCClientCallback(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCClientCallback::get_discovery(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->discovery);
}

void OCClientCallback::set_discovery(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->discovery = value.As<Napi::Boolean>().Value();
}

Napi::Value OCClientCallback::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCClientCallback::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t>>>().Data()));
}

Napi::Value OCClientCallback::get_handler(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_client_handler_t> sp(&m_pvalue->handler);
  auto accessor = Napi::External<std::shared_ptr<oc_client_handler_t>>::New(info.Env(), &sp);
  return OCClientHandler::constructor.New({accessor});
}

void OCClientCallback::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->handler = *(*(value.As<Napi::External<std::shared_ptr<oc_client_handler_t>>>().Data()));
}

Napi::Value OCClientCallback::get_method(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->method);
}

void OCClientCallback::set_method(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->method = static_cast<oc_method_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_mid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->mid);
}

void OCClientCallback::set_mid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mid = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_multicast(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->multicast);
}

void OCClientCallback::set_multicast(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->multicast = value.As<Napi::Boolean>().Value();
}

Napi::Value OCClientCallback::get_observe_seq(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_seq);
}

void OCClientCallback::set_observe_seq(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_seq = value.As<Napi::Number>().Int32Value();
}

Napi::Value OCClientCallback::get_qos(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->qos);
}

void OCClientCallback::set_qos(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->qos = static_cast<oc_qos_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_query(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->query);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCClientCallback::set_query(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->query = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCClientCallback::get_ref_count(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->ref_count);
}

void OCClientCallback::set_ref_count(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ref_count = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_separate(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->separate);
}

void OCClientCallback::set_separate(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->separate = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_stop_multicast_receive(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->stop_multicast_receive);
}

void OCClientCallback::set_stop_multicast_receive(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->stop_multicast_receive = value.As<Napi::Boolean>().Value();
}

Napi::Value OCClientCallback::get_timestamp(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->timestamp);
}

void OCClientCallback::set_timestamp(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->timestamp = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_token(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);
}

void OCClientCallback::set_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) { m_pvalue->token[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }
}

Napi::Value OCClientCallback::get_token_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->token_len);
}

void OCClientCallback::set_token_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->token_len = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCClientCallback::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCClientCallback::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCClientHandler::constructor;

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

Napi::FunctionReference OCClientResponse::constructor;

Napi::Function OCClientResponse::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCClientResponse", {
    OCClientResponse::InstanceAccessor("_payload", &OCClientResponse::get__payload, &OCClientResponse::set__payload),
    OCClientResponse::InstanceAccessor("_payload_len", &OCClientResponse::get__payload_len, &OCClientResponse::set__payload_len),
    OCClientResponse::InstanceAccessor("code", &OCClientResponse::get_code, &OCClientResponse::set_code),
    OCClientResponse::InstanceAccessor("content_format", &OCClientResponse::get_content_format, &OCClientResponse::set_content_format),
    OCClientResponse::InstanceAccessor("endpoint", &OCClientResponse::get_endpoint, &OCClientResponse::set_endpoint),
    OCClientResponse::InstanceAccessor("observe_option", &OCClientResponse::get_observe_option, &OCClientResponse::set_observe_option),
    OCClientResponse::InstanceAccessor("payload", &OCClientResponse::get_payload, &OCClientResponse::set_payload),

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
Napi::Value OCClientResponse::get__payload(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(m_pvalue->_payload), m_pvalue->_payload_len);
}

void OCClientResponse::set__payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->_payload =    value.As<Napi::Buffer<uint8_t>>().Data();
m_pvalue->_payload_len = value.As<Napi::Buffer<uint8_t>>().Length();
}

Napi::Value OCClientResponse::get__payload_len(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->_payload_len);
}

void OCClientResponse::set__payload_len(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->_payload_len = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());
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

Napi::Value OCClientResponse::get_endpoint(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t*> sp(&m_pvalue->endpoint);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t*>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCClientResponse::set_endpoint(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->endpoint = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t*>>>().Data()));
}

Napi::Value OCClientResponse::get_observe_option(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->observe_option);
}

void OCClientResponse::set_observe_option(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->observe_option = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCClientResponse::get_payload(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_rep_t*> sp(&m_pvalue->payload);
  auto accessor = Napi::External<std::shared_ptr<oc_rep_t*>>::New(info.Env(), &sp);
  return OCRepresentation::constructor.New({accessor});
}

void OCClientResponse::set_payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->payload = *(*(value.As<Napi::External<std::shared_ptr<oc_rep_t*>>>().Data()));
}

Napi::FunctionReference OCCloudContext::constructor;

Napi::Function OCCloudContext::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudContext", {
    OCCloudContext::InstanceAccessor("callback", &OCCloudContext::get_callback, &OCCloudContext::set_callback),
    OCCloudContext::InstanceAccessor("cloud_conf", &OCCloudContext::get_cloud_conf, &OCCloudContext::set_cloud_conf),
    OCCloudContext::InstanceAccessor("cloud_ep", &OCCloudContext::get_cloud_ep, &OCCloudContext::set_cloud_ep),
    OCCloudContext::InstanceAccessor("cloud_ep_state", &OCCloudContext::get_cloud_ep_state, &OCCloudContext::set_cloud_ep_state),
    OCCloudContext::InstanceAccessor("cloud_manager", &OCCloudContext::get_cloud_manager, &OCCloudContext::set_cloud_manager),
    OCCloudContext::InstanceAccessor("device", &OCCloudContext::get_device, &OCCloudContext::set_device),
    OCCloudContext::InstanceAccessor("expires_in", &OCCloudContext::get_expires_in, &OCCloudContext::set_expires_in),
    OCCloudContext::InstanceAccessor("last_error", &OCCloudContext::get_last_error, &OCCloudContext::set_last_error),
    OCCloudContext::InstanceAccessor("rd_delete_all", &OCCloudContext::get_rd_delete_all, &OCCloudContext::set_rd_delete_all),
    OCCloudContext::InstanceAccessor("rd_delete_resources", &OCCloudContext::get_rd_delete_resources, &OCCloudContext::set_rd_delete_resources),
    OCCloudContext::InstanceAccessor("rd_publish_resources", &OCCloudContext::get_rd_publish_resources, &OCCloudContext::set_rd_publish_resources),
    OCCloudContext::InstanceAccessor("rd_published_resources", &OCCloudContext::get_rd_published_resources, &OCCloudContext::set_rd_published_resources),
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

Napi::Value OCCloudContext::get_cloud_conf(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_resource_t*> sp(&m_pvalue->cloud_conf);
  auto accessor = Napi::External<std::shared_ptr<oc_resource_t*>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCCloudContext::set_cloud_conf(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->cloud_conf = *(*(value.As<Napi::External<std::shared_ptr<oc_resource_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_cloud_ep(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t*> sp(&m_pvalue->cloud_ep);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t*>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCCloudContext::set_cloud_ep(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->cloud_ep = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_cloud_ep_state(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->cloud_ep_state);
}

void OCCloudContext::set_cloud_ep_state(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->cloud_ep_state = static_cast<oc_session_state_t>(value.As<Napi::Number>().Uint32Value());
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

Napi::Value OCCloudContext::get_rd_delete_resources(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_link_t*> sp(&m_pvalue->rd_delete_resources);
  auto accessor = Napi::External<std::shared_ptr<oc_link_t*>>::New(info.Env(), &sp);
  return OCLink::constructor.New({accessor});
}

void OCCloudContext::set_rd_delete_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rd_delete_resources = *(*(value.As<Napi::External<std::shared_ptr<oc_link_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_rd_publish_resources(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_link_t*> sp(&m_pvalue->rd_publish_resources);
  auto accessor = Napi::External<std::shared_ptr<oc_link_t*>>::New(info.Env(), &sp);
  return OCLink::constructor.New({accessor});
}

void OCCloudContext::set_rd_publish_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rd_publish_resources = *(*(value.As<Napi::External<std::shared_ptr<oc_link_t*>>>().Data()));
}

Napi::Value OCCloudContext::get_rd_published_resources(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_link_t*> sp(&m_pvalue->rd_published_resources);
  auto accessor = Napi::External<std::shared_ptr<oc_link_t*>>::New(info.Env(), &sp);
  return OCLink::constructor.New({accessor});
}

void OCCloudContext::set_rd_published_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rd_published_resources = *(*(value.As<Napi::External<std::shared_ptr<oc_link_t*>>>().Data()));
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
  return OCCloudStore::constructor.New({accessor});
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

Napi::FunctionReference OCCloudStore::constructor;

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
  return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_access_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->access_token = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_auth_provider(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->auth_provider);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_auth_provider(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->auth_provider = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_ci_server(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->ci_server);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
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
  return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_refresh_token(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->refresh_token = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCloudStore::get_sid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->sid);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
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
  return OCMmem::constructor.New({accessor});
}

void OCCloudStore::set_uid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uid = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCCollection::constructor;

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
  return OCRequestHandler::constructor.New({accessor});
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
  return OCRequestHandler::constructor.New({accessor});
}

void OCCollection::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_get_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCPropertiesCb::constructor.New({accessor});
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
  return OCMmem::constructor.New({accessor});
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
  return OCRequestHandler::constructor.New({accessor});
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
  return OCRequestHandler::constructor.New({accessor});
}

void OCCollection::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->put_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCCollection::get_set_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCPropertiesCb::constructor.New({accessor});
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
return array;
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
  return OCMmem::constructor.New({accessor});
}

void OCCollection::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCCollection::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCCollection::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCCredData::constructor;

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
  return OCMmem::constructor.New({accessor});
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

Napi::FunctionReference OCDeviceInfo::constructor;

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
  return OCUuid::constructor.New({accessor});
}

void OCDeviceInfo::set_di(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->di = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::Value OCDeviceInfo::get_dmv(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->dmv);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCDeviceInfo::set_dmv(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->dmv = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_icv(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->icv);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCDeviceInfo::set_icv(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->icv = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCDeviceInfo::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCDeviceInfo::get_piid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->piid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({accessor});
}

void OCDeviceInfo::set_piid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->piid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCEndpoint::constructor;

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
  return DevAddr::constructor.New({accessor});
}

void OCEndpoint::set_addr(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->addr = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>>().Data()));
}

Napi::Value OCEndpoint::get_addr_local(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t::dev_addr> sp(&m_pvalue->addr_local);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t::dev_addr>>::New(info.Env(), &sp);
  return DevAddr::constructor.New({accessor});
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
  return OCUuid::constructor.New({accessor});
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

Napi::FunctionReference OCEtimer::constructor;

Napi::Function OCEtimer::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEtimer", {
    OCEtimer::InstanceAccessor("p", &OCEtimer::get_p, &OCEtimer::set_p),
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
Napi::Value OCEtimer::get_p(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_process*> sp(&m_pvalue->p);
  auto accessor = Napi::External<std::shared_ptr<oc_process*>>::New(info.Env(), &sp);
  return OCProcess::constructor.New({accessor});
}

void OCEtimer::set_p(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->p = *(*(value.As<Napi::External<std::shared_ptr<oc_process*>>>().Data()));
}

Napi::Value OCEtimer::get_timer(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_timer> sp(&m_pvalue->timer);
  auto accessor = Napi::External<std::shared_ptr<oc_timer>>::New(info.Env(), &sp);
  return OCTimer::constructor.New({accessor});
}

void OCEtimer::set_timer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->timer = *(*(value.As<Napi::External<std::shared_ptr<oc_timer>>>().Data()));
}

Napi::FunctionReference OCEventCallback::constructor;

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
  return OCEtimer::constructor.New({accessor});
}

void OCEventCallback::set_timer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->timer = *(*(value.As<Napi::External<std::shared_ptr<oc_etimer>>>().Data()));
}

Napi::FunctionReference OCHandler::constructor;

Napi::Function OCHandler::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCHandler", {
    OCHandler::InstanceAccessor("init", &OCHandler::get_init, &OCHandler::set_init),
#if defined(OC_SERVER)
    OCHandler::InstanceAccessor("register_resources", &OCHandler::get_register_resources, &OCHandler::set_register_resources),
#endif
#if defined(OC_CLIENT)
    OCHandler::InstanceAccessor("requests_entry", &OCHandler::get_requests_entry, &OCHandler::set_requests_entry),
#endif
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
  return init.Value();
}

void OCHandler::set_init(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  init.Reset(value.As<Napi::Function>());

}

#if defined(OC_SERVER)
Napi::Value OCHandler::get_register_resources(const Napi::CallbackInfo& info)
{
  return oc_handler_register_resources_ref.Value();
}

void OCHandler::set_register_resources(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  register_resources.Reset(value.As<Napi::Function>());

}
#endif

#if defined(OC_CLIENT)
Napi::Value OCHandler::get_requests_entry(const Napi::CallbackInfo& info)
{
  return requests_entry.Value();

}

void OCHandler::set_requests_entry(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  requests_entry.Reset(value.As<Napi::Function>());

}
#endif

Napi::Value OCHandler::get_signal_event_loop(const Napi::CallbackInfo& info)
{
  return signal_event_loop.Value();

}

void OCHandler::set_signal_event_loop(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  signal_event_loop.Reset(value.As<Napi::Function>());

}

Napi::FunctionReference OCIPv4Addr::constructor;

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

Napi::FunctionReference OCIPv6Addr::constructor;

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

Napi::FunctionReference OCLEAddr::constructor;

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

Napi::FunctionReference OCLinkParams::constructor;

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
  return OCMmem::constructor.New({accessor});
}

void OCLinkParams::set_key(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->key = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCLinkParams::get_value(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->value);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCLinkParams::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->value = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCLink::constructor;

Napi::Function OCLink::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCLink", {
    OCLink::InstanceAccessor("ins", &OCLink::get_ins, &OCLink::set_ins),
    OCLink::InstanceAccessor("interfaces", &OCLink::get_interfaces, &OCLink::set_interfaces),
    OCLink::InstanceAccessor("rel", &OCLink::get_rel, &OCLink::set_rel),
    OCLink::InstanceAccessor("resource", &OCLink::get_resource, &OCLink::set_resource),

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
  return OCMmem::constructor.New({accessor});
}

void OCLink::set_rel(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rel = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCLink::get_resource(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_resource_t*> sp(&m_pvalue->resource);
  auto accessor = Napi::External<std::shared_ptr<oc_resource_t*>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCLink::set_resource(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->resource = *(*(value.As<Napi::External<std::shared_ptr<oc_resource_t*>>>().Data()));
}

Napi::FunctionReference OCMemb::constructor;

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

Napi::FunctionReference OCMessage::constructor;

Napi::Function OCMessage::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCMessage", {
    OCMessage::InstanceAccessor("data", &OCMessage::get_data, &OCMessage::set_data),
#if defined(OC_SECURITY)
    OCMessage::InstanceAccessor("encrypted", &OCMessage::get_encrypted, &OCMessage::set_encrypted),
#endif
    OCMessage::InstanceAccessor("endpoint", &OCMessage::get_endpoint, &OCMessage::set_endpoint),
    OCMessage::InstanceAccessor("length", &OCMessage::get_length, &OCMessage::set_length),
    OCMessage::InstanceAccessor("pool", &OCMessage::get_pool, &OCMessage::set_pool),
#if defined(OC_TCP)
    OCMessage::InstanceAccessor("read_offset", &OCMessage::get_read_offset, &OCMessage::set_read_offset),
#endif
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

#if defined(OC_SECURITY)
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
  return OCEndpoint::constructor.New({accessor});
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

Napi::Value OCMessage::get_pool(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_memb*> sp(&m_pvalue->pool);
  auto accessor = Napi::External<std::shared_ptr<oc_memb*>>::New(info.Env(), &sp);
  return OCMemb::constructor.New({accessor});
}

void OCMessage::set_pool(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->pool = *(*(value.As<Napi::External<std::shared_ptr<oc_memb*>>>().Data()));
}

#if defined(OC_TCP)
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

Napi::FunctionReference OCMmem::constructor;

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

Napi::FunctionReference OCNetworkInterfaceCb::constructor;

Napi::Function OCNetworkInterfaceCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCNetworkInterfaceCb", {
    OCNetworkInterfaceCb::InstanceAccessor("handler", &OCNetworkInterfaceCb::get_handler, &OCNetworkInterfaceCb::set_handler),

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
Napi::Value OCNetworkInterfaceCb::get_handler(const Napi::CallbackInfo& info)
{
  return handler_function;
}

void OCNetworkInterfaceCb::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  handler_function = value;
}

Napi::FunctionReference OCPlatformInfo::constructor;

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
  return OCMmem::constructor.New({accessor});
}

void OCPlatformInfo::set_mfg_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->mfg_name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCPlatformInfo::get_pi(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->pi);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({accessor});
}

void OCPlatformInfo::set_pi(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->pi = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCProcess::constructor;

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

Napi::FunctionReference OCPropertiesCb::constructor;

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

Napi::FunctionReference OCRepresentation::constructor;

Napi::Function OCRepresentation::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRepresentation", {
    OCRepresentation::InstanceAccessor("name", &OCRepresentation::get_name, &OCRepresentation::set_name),
    OCRepresentation::InstanceAccessor("type", &OCRepresentation::get_type, &OCRepresentation::set_type),
    OCRepresentation::InstanceAccessor("value", &OCRepresentation::get_value, &OCRepresentation::set_value),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCRepresentation::OCRepresentation(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCRepresentation::get_name(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->name);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCRepresentation::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCRepresentation::get_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->type);
}

void OCRepresentation::set_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->type = static_cast<oc_rep_value_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCRepresentation::get_value(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_rep_s::oc_rep_value> sp(&m_pvalue->value);
  auto accessor = Napi::External<std::shared_ptr<oc_rep_s::oc_rep_value>>::New(info.Env(), &sp);
  return OCValue::constructor.New({accessor});
}

void OCRepresentation::set_value(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->value = *(*(value.As<Napi::External<std::shared_ptr<oc_rep_s::oc_rep_value>>>().Data()));
}

Napi::FunctionReference OCRequestHandler::constructor;

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

Napi::FunctionReference OCRequest::constructor;

Napi::Function OCRequest::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRequest", {
    OCRequest::InstanceAccessor("_payload", &OCRequest::get__payload, &OCRequest::set__payload),
    OCRequest::InstanceAccessor("_payload_len", &OCRequest::get__payload_len, &OCRequest::set__payload_len),
    OCRequest::InstanceAccessor("content_format", &OCRequest::get_content_format, &OCRequest::set_content_format),
    OCRequest::InstanceAccessor("origin", &OCRequest::get_origin, &OCRequest::set_origin),
    OCRequest::InstanceAccessor("query", &OCRequest::get_query, &OCRequest::set_query),
    OCRequest::InstanceAccessor("query_len", &OCRequest::get_query_len, &OCRequest::set_query_len),
    OCRequest::InstanceAccessor("request_payload", &OCRequest::get_request_payload, &OCRequest::set_request_payload),
    OCRequest::InstanceAccessor("resource", &OCRequest::get_resource, &OCRequest::set_resource),
    OCRequest::InstanceAccessor("response", &OCRequest::get_response, &OCRequest::set_response),

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

Napi::Value OCRequest::get_origin(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_endpoint_t*> sp(&m_pvalue->origin);
  auto accessor = Napi::External<std::shared_ptr<oc_endpoint_t*>>::New(info.Env(), &sp);
  return OCEndpoint::constructor.New({accessor});
}

void OCRequest::set_origin(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->origin = *(*(value.As<Napi::External<std::shared_ptr<oc_endpoint_t*>>>().Data()));
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

Napi::Value OCRequest::get_request_payload(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_rep_t*> sp(&m_pvalue->request_payload);
  auto accessor = Napi::External<std::shared_ptr<oc_rep_t*>>::New(info.Env(), &sp);
  return OCRepresentation::constructor.New({accessor});
}

void OCRequest::set_request_payload(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->request_payload = *(*(value.As<Napi::External<std::shared_ptr<oc_rep_t*>>>().Data()));
}

Napi::Value OCRequest::get_resource(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_resource_t*> sp(&m_pvalue->resource);
  auto accessor = Napi::External<std::shared_ptr<oc_resource_t*>>::New(info.Env(), &sp);
  return OCResource::constructor.New({accessor});
}

void OCRequest::set_resource(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->resource = *(*(value.As<Napi::External<std::shared_ptr<oc_resource_t*>>>().Data()));
}

Napi::Value OCRequest::get_response(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_response_t*> sp(&m_pvalue->response);
  auto accessor = Napi::External<std::shared_ptr<oc_response_t*>>::New(info.Env(), &sp);
  return OCResponse::constructor.New({accessor});
}

void OCRequest::set_response(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->response = *(*(value.As<Napi::External<std::shared_ptr<oc_response_t*>>>().Data()));
}

Napi::FunctionReference OCResource::constructor;

Napi::Function OCResource::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResource", {
    OCResource::InstanceAccessor("default_interface", &OCResource::get_default_interface, &OCResource::set_default_interface),
    OCResource::InstanceAccessor("delete_handler", &OCResource::get_delete_handler, &OCResource::set_delete_handler),
    OCResource::InstanceAccessor("device", &OCResource::get_device, &OCResource::set_device),
    OCResource::InstanceAccessor("get_handler", &OCResource::get_get_handler, &OCResource::set_get_handler),
    OCResource::InstanceAccessor("get_properties", &OCResource::get_get_properties, &OCResource::set_get_properties),
    OCResource::InstanceAccessor("interfaces", &OCResource::get_interfaces, &OCResource::set_interfaces),
    OCResource::InstanceAccessor("name", &OCResource::get_name, &OCResource::set_name),
#if defined(OC_COLLECTIONS)
    OCResource::InstanceAccessor("num_links", &OCResource::get_num_links, &OCResource::set_num_links),
#endif
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
  return OCRequestHandler::constructor.New({accessor});
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
  return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_get_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->get_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_get_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->get_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCPropertiesCb::constructor.New({accessor});
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
  return OCMmem::constructor.New({accessor});
}

void OCResource::set_name(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->name = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

#if defined(OC_COLLECTIONS)
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
  return OCRequestHandler::constructor.New({accessor});
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
  return OCRequestHandler::constructor.New({accessor});
}

void OCResource::set_put_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->put_handler = *(*(value.As<Napi::External<std::shared_ptr<oc_request_handler_s>>>().Data()));
}

Napi::Value OCResource::get_set_properties(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_properties_cb_t> sp(&m_pvalue->set_properties);
  auto accessor = Napi::External<std::shared_ptr<oc_properties_cb_t>>::New(info.Env(), &sp);
  return OCPropertiesCb::constructor.New({accessor});
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
return array;
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
  return OCMmem::constructor.New({accessor});
}

void OCResource::set_types(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->types = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCResource::get_uri(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->uri);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCResource::set_uri(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uri = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCResponseBuffer::constructor;

Napi::Function OCResponseBuffer::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResponseBuffer", {
    OCResponseBuffer::InstanceAccessor("buffer", &OCResponseBuffer::get_buffer, &OCResponseBuffer::set_buffer),
    OCResponseBuffer::InstanceAccessor("buffer_size", &OCResponseBuffer::get_buffer_size, &OCResponseBuffer::set_buffer_size),
    OCResponseBuffer::InstanceAccessor("code", &OCResponseBuffer::get_code, &OCResponseBuffer::set_code),
    OCResponseBuffer::InstanceAccessor("content_format", &OCResponseBuffer::get_content_format, &OCResponseBuffer::set_content_format),
    OCResponseBuffer::InstanceAccessor("response_length", &OCResponseBuffer::get_response_length, &OCResponseBuffer::set_response_length),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCResponseBuffer::OCResponseBuffer(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_response_buffer_s>(new oc_response_buffer_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_response_buffer_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCResponseBuffer::get_buffer(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, m_pvalue->buffer_size);
}

void OCResponseBuffer::set_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->buffer =     value.As<Napi::Buffer<uint8_t>>().Data();
m_pvalue->buffer_size = value.As<Napi::Buffer<uint8_t>>().Length();
}

Napi::Value OCResponseBuffer::get_buffer_size(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->buffer_size);
}

void OCResponseBuffer::set_buffer_size(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->buffer_size = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResponseBuffer::get_code(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->code);
}

void OCResponseBuffer::set_code(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->code = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCResponseBuffer::get_content_format(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->content_format);
}

void OCResponseBuffer::set_content_format(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->content_format = static_cast<oc_content_format_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCResponseBuffer::get_response_length(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->response_length);
}

void OCResponseBuffer::set_response_length(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->response_length = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::FunctionReference OCResponse::constructor;

Napi::Function OCResponse::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResponse", {
    OCResponse::InstanceAccessor("response_buffer", &OCResponse::get_response_buffer, &OCResponse::set_response_buffer),
    OCResponse::InstanceAccessor("separate_response", &OCResponse::get_separate_response, &OCResponse::set_separate_response),

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
Napi::Value OCResponse::get_response_buffer(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_response_buffer_t*> sp(&m_pvalue->response_buffer);
  auto accessor = Napi::External<std::shared_ptr<oc_response_buffer_t*>>::New(info.Env(), &sp);
  return OCResponseBuffer::constructor.New({accessor});
}

void OCResponse::set_response_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->response_buffer = *(*(value.As<Napi::External<std::shared_ptr<oc_response_buffer_t*>>>().Data()));
}

Napi::Value OCResponse::get_separate_response(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_separate_response_t*> sp(&m_pvalue->separate_response);
  auto accessor = Napi::External<std::shared_ptr<oc_separate_response_t*>>::New(info.Env(), &sp);
  return OCSeparateResponse::constructor.New({accessor});
}

void OCResponse::set_separate_response(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->separate_response = *(*(value.As<Napi::External<std::shared_ptr<oc_separate_response_t*>>>().Data()));
}

Napi::FunctionReference OCRole::constructor;

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
  return OCMmem::constructor.New({accessor});
}

void OCRole::set_authority(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->authority = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::Value OCRole::get_role(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->role);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCRole::set_role(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->role = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCResourceType::constructor;

Napi::Function OCResourceType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResourceType", {
    OCResourceType::InstanceAccessor("rt", &OCResourceType::get_rt, &OCResourceType::set_rt),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCResourceType::OCResourceType(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCResourceType::get_rt(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->rt);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCResourceType::set_rt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rt = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCSecurityAce::constructor;

Napi::Function OCSecurityAce::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecurityAce", {
    OCSecurityAce::InstanceAccessor("aceid", &OCSecurityAce::get_aceid, &OCSecurityAce::set_aceid),
    OCSecurityAce::InstanceAccessor("permission", &OCSecurityAce::get_permission, &OCSecurityAce::set_permission),
    OCSecurityAce::InstanceAccessor("subject", &OCSecurityAce::get_subject, &OCSecurityAce::set_subject),
    OCSecurityAce::InstanceAccessor("subject_type", &OCSecurityAce::get_subject_type, &OCSecurityAce::set_subject_type),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecurityAce::OCSecurityAce(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCSecurityAce::get_aceid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->aceid);
}

void OCSecurityAce::set_aceid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->aceid = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCSecurityAce::get_permission(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->permission);
}

void OCSecurityAce::set_permission(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->permission = static_cast<oc_ace_permissions_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::Value OCSecurityAce::get_subject(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_ace_subject_t> sp(&m_pvalue->subject);
  auto accessor = Napi::External<std::shared_ptr<oc_ace_subject_t>>::New(info.Env(), &sp);
  return OCAceSubject::constructor.New({accessor});
}

void OCSecurityAce::set_subject(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->subject = *(*(value.As<Napi::External<std::shared_ptr<oc_ace_subject_t>>>().Data()));
}

Napi::Value OCSecurityAce::get_subject_type(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->subject_type);
}

void OCSecurityAce::set_subject_type(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->subject_type = static_cast<oc_ace_subject_type_t>(value.As<Napi::Number>().Uint32Value());
}

Napi::FunctionReference OCSecurityAcl::constructor;

Napi::Function OCSecurityAcl::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSecurityAcl", {
    OCSecurityAcl::InstanceAccessor("rowneruuid", &OCSecurityAcl::get_rowneruuid, &OCSecurityAcl::set_rowneruuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSecurityAcl::OCSecurityAcl(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCSecurityAcl::get_rowneruuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->rowneruuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({accessor});
}

void OCSecurityAcl::set_rowneruuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rowneruuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCCreds::constructor;

Napi::Function OCCreds::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCreds", {
    OCCreds::InstanceAccessor("rowneruuid", &OCCreds::get_rowneruuid, &OCCreds::set_rowneruuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCreds::OCCreds(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCCreds::get_rowneruuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->rowneruuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({accessor});
}

void OCCreds::set_rowneruuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->rowneruuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCCred::constructor;

Napi::Function OCCred::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCred", {
#if defined(OC_PKI)
    OCCred::InstanceAccessor("chain", &OCCred::get_chain, &OCCred::set_chain),
#endif
#if defined(OC_PKI)
    OCCred::InstanceAccessor("child", &OCCred::get_child, &OCCred::set_child),
#endif
    OCCred::InstanceAccessor("credid", &OCCred::get_credid, &OCCred::set_credid),
    OCCred::InstanceAccessor("credtype", &OCCred::get_credtype, &OCCred::set_credtype),
#if defined(OC_PKI)
    OCCred::InstanceAccessor("credusage", &OCCred::get_credusage, &OCCred::set_credusage),
#endif
    OCCred::InstanceAccessor("owner_cred", &OCCred::get_owner_cred, &OCCred::set_owner_cred),
    OCCred::InstanceAccessor("privatedata", &OCCred::get_privatedata, &OCCred::set_privatedata),
#if defined(OC_PKI)
    OCCred::InstanceAccessor("publicdata", &OCCred::get_publicdata, &OCCred::set_publicdata),
#endif
    OCCred::InstanceAccessor("subjectuuid", &OCCred::get_subjectuuid, &OCCred::set_subjectuuid),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCred::OCCred(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
#if defined(OC_PKI)
Napi::Value OCCred::get_chain(const Napi::CallbackInfo& info)
{
//
  std::shared_ptr<oc_sec_cred_t*> sp(&m_pvalue->chain);
  auto accessor = Napi::External<std::shared_ptr<oc_sec_cred_t*>>::New(info.Env(), &sp);
  return OCCred::constructor.New({accessor});

}

void OCCred::set_chain(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->chain = *(*(value.As<Napi::External<std::shared_ptr<oc_sec_cred_t*>>>().Data()));
}
#endif

#if defined(OC_PKI)
Napi::Value OCCred::get_child(const Napi::CallbackInfo& info)
{
//
  std::shared_ptr<oc_sec_cred_t*> sp(&m_pvalue->child);
  auto accessor = Napi::External<std::shared_ptr<oc_sec_cred_t*>>::New(info.Env(), &sp);
  return OCCred::constructor.New({accessor});

}

void OCCred::set_child(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->child = *(*(value.As<Napi::External<std::shared_ptr<oc_sec_cred_t*>>>().Data()));
}
#endif

Napi::Value OCCred::get_credid(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->credid);
}

void OCCred::set_credid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->credid = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCCred::get_credtype(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->credtype);
}

void OCCred::set_credtype(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->credtype = static_cast<oc_sec_credtype_t>(value.As<Napi::Number>().Uint32Value());
}

#if defined(OC_PKI)
Napi::Value OCCred::get_credusage(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->credusage);
}

void OCCred::set_credusage(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->credusage = static_cast<oc_sec_credusage_t>(value.As<Napi::Number>().Uint32Value());
}
#endif

Napi::Value OCCred::get_owner_cred(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->owner_cred);
}

void OCCred::set_owner_cred(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->owner_cred = value.As<Napi::Boolean>().Value();
}

Napi::Value OCCred::get_privatedata(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_cred_data_t> sp(&m_pvalue->privatedata);
  auto accessor = Napi::External<std::shared_ptr<oc_cred_data_t>>::New(info.Env(), &sp);
  return OCCredData::constructor.New({accessor});
}

void OCCred::set_privatedata(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->privatedata = *(*(value.As<Napi::External<std::shared_ptr<oc_cred_data_t>>>().Data()));
}

#if defined(OC_PKI)
Napi::Value OCCred::get_publicdata(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_cred_data_t> sp(&m_pvalue->publicdata);
  auto accessor = Napi::External<std::shared_ptr<oc_cred_data_t>>::New(info.Env(), &sp);
  return OCCredData::constructor.New({accessor});
}

void OCCred::set_publicdata(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->publicdata = *(*(value.As<Napi::External<std::shared_ptr<oc_cred_data_t>>>().Data()));
}
#endif

Napi::Value OCCred::get_subjectuuid(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_uuid_t> sp(&m_pvalue->subjectuuid);
  auto accessor = Napi::External<std::shared_ptr<oc_uuid_t>>::New(info.Env(), &sp);
  return OCUuid::constructor.New({accessor});
}

void OCCred::set_subjectuuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->subjectuuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference OCSeparateResponse::constructor;

Napi::Function OCSeparateResponse::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSeparateResponse", {
    OCSeparateResponse::InstanceAccessor("active", &OCSeparateResponse::get_active, &OCSeparateResponse::set_active),
    OCSeparateResponse::InstanceAccessor("buffer", &OCSeparateResponse::get_buffer, &OCSeparateResponse::set_buffer),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSeparateResponse::OCSeparateResponse(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_separate_response_s>(new oc_separate_response_s());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_separate_response_s>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCSeparateResponse::get_active(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->active);
}

void OCSeparateResponse::set_active(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->active = static_cast<int>(value.As<Napi::Number>());
}

Napi::Value OCSeparateResponse::get_buffer(const Napi::CallbackInfo& info)
{
return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, OC_MAX_APP_DATA_SIZE);
}

void OCSeparateResponse::set_buffer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
m_pvalue->buffer =     value.As<Napi::Buffer<uint8_t>>().Data();
}

Napi::FunctionReference OCSessionEventCb::constructor;

Napi::Function OCSessionEventCb::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSessionEventCb", {
    OCSessionEventCb::InstanceAccessor("handler", &OCSessionEventCb::get_handler, &OCSessionEventCb::set_handler),

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
Napi::Value OCSessionEventCb::get_handler(const Napi::CallbackInfo& info)
{
  return handler_function;
}

void OCSessionEventCb::set_handler(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  handler_function = value;
}

Napi::FunctionReference OCSoftwareUpdateHandler::constructor;

Napi::Function OCSoftwareUpdateHandler::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSoftwareUpdateHandler", {
    OCSoftwareUpdateHandler::InstanceAccessor("check_new_version", &OCSoftwareUpdateHandler::get_check_new_version, &OCSoftwareUpdateHandler::set_check_new_version),
    OCSoftwareUpdateHandler::InstanceAccessor("download_update", &OCSoftwareUpdateHandler::get_download_update, &OCSoftwareUpdateHandler::set_download_update),
    OCSoftwareUpdateHandler::InstanceAccessor("perform_upgrade", &OCSoftwareUpdateHandler::get_perform_upgrade, &OCSoftwareUpdateHandler::set_perform_upgrade),
    OCSoftwareUpdateHandler::InstanceAccessor("validate_purl", &OCSoftwareUpdateHandler::get_validate_purl, &OCSoftwareUpdateHandler::set_validate_purl),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSoftwareUpdateHandler::OCSoftwareUpdateHandler(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCSoftwareUpdateHandler::get_check_new_version(const Napi::CallbackInfo& info)
{
return check_new_version_function ;
}

void OCSoftwareUpdateHandler::set_check_new_version(const Napi::CallbackInfo& info, const Napi::Value& value)
{
check_new_version_function = value;
}

Napi::Value OCSoftwareUpdateHandler::get_download_update(const Napi::CallbackInfo& info)
{
return download_update_function;
}

void OCSoftwareUpdateHandler::set_download_update(const Napi::CallbackInfo& info, const Napi::Value& value)
{
download_update_function = value;
}

Napi::Value OCSoftwareUpdateHandler::get_perform_upgrade(const Napi::CallbackInfo& info)
{
return perform_upgrade_function;
}

void OCSoftwareUpdateHandler::set_perform_upgrade(const Napi::CallbackInfo& info, const Napi::Value& value)
{
perform_upgrade_function = value;
}

Napi::Value OCSoftwareUpdateHandler::get_validate_purl(const Napi::CallbackInfo& info)
{
return validate_purl_function;
}

void OCSoftwareUpdateHandler::set_validate_purl(const Napi::CallbackInfo& info, const Napi::Value& value)
{
validate_purl_function = value;
}

Napi::FunctionReference OCTimer::constructor;

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

Napi::FunctionReference OCUuid::constructor;

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

Napi::FunctionReference OCAceSubject::constructor;

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
  return OCUuid::constructor.New({accessor});
}

void OCAceSubject::set_uuid(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->uuid = *(*(value.As<Napi::External<std::shared_ptr<oc_uuid_t>>>().Data()));
}

Napi::FunctionReference DevAddr::constructor;

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
  return OCLEAddr::constructor.New({accessor});
}

void DevAddr::set_bt(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->bt = *(*(value.As<Napi::External<std::shared_ptr<oc_le_addr_t>>>().Data()));
}

Napi::Value DevAddr::get_ipv4(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_ipv4_addr_t> sp(&m_pvalue->ipv4);
  auto accessor = Napi::External<std::shared_ptr<oc_ipv4_addr_t>>::New(info.Env(), &sp);
  return OCIPv4Addr::constructor.New({accessor});
}

void DevAddr::set_ipv4(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ipv4 = *(*(value.As<Napi::External<std::shared_ptr<oc_ipv4_addr_t>>>().Data()));
}

Napi::Value DevAddr::get_ipv6(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_ipv6_addr_t> sp(&m_pvalue->ipv6);
  auto accessor = Napi::External<std::shared_ptr<oc_ipv6_addr_t>>::New(info.Env(), &sp);
  return OCIPv6Addr::constructor.New({accessor});
}

void DevAddr::set_ipv6(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->ipv6 = *(*(value.As<Napi::External<std::shared_ptr<oc_ipv6_addr_t>>>().Data()));
}

Napi::FunctionReference OCValue::constructor;

Napi::Function OCValue::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCValue", {
    OCValue::InstanceAccessor("array", &OCValue::get_array, &OCValue::set_array),
    OCValue::InstanceAccessor("boolean", &OCValue::get_boolean, &OCValue::set_boolean),
    OCValue::InstanceAccessor("double_p", &OCValue::get_double_p, &OCValue::set_double_p),
    OCValue::InstanceAccessor("integer", &OCValue::get_integer, &OCValue::set_integer),
    OCValue::InstanceAccessor("object", &OCValue::get_object, &OCValue::set_object),
    OCValue::InstanceAccessor("object_array", &OCValue::get_object_array, &OCValue::set_object_array),
    OCValue::InstanceAccessor("string", &OCValue::get_string, &OCValue::set_string),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCValue::OCValue(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_rep_s::oc_rep_value>(new oc_rep_s::oc_rep_value());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_rep_s::oc_rep_value>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value OCValue::get_array(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_array_t> sp(&m_pvalue->array);
  auto accessor = Napi::External<std::shared_ptr<oc_array_t>>::New(info.Env(), &sp);
  return OCArray::constructor.New({accessor});
}

void OCValue::set_array(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->array = *(*(value.As<Napi::External<std::shared_ptr<oc_array_t>>>().Data()));
}

Napi::Value OCValue::get_boolean(const Napi::CallbackInfo& info)
{
  return Napi::Boolean::New(info.Env(), m_pvalue->boolean);
}

void OCValue::set_boolean(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->boolean = value.As<Napi::Boolean>().Value();
}

Napi::Value OCValue::get_double_p(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->double_p);
}

void OCValue::set_double_p(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->double_p = value.As<Napi::Number>().DoubleValue();
}

Napi::Value OCValue::get_integer(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), m_pvalue->integer);
}

void OCValue::set_integer(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->integer = value.As<Napi::Number>().Int64Value();
}

Napi::Value OCValue::get_object(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_rep_s*> sp(&m_pvalue->object);
  auto accessor = Napi::External<std::shared_ptr<oc_rep_s*>>::New(info.Env(), &sp);
  return OCRepresentation::constructor.New({accessor});
}

void OCValue::set_object(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->object = *(*(value.As<Napi::External<std::shared_ptr<oc_rep_s*>>>().Data()));
}

Napi::Value OCValue::get_object_array(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_rep_s*> sp(&m_pvalue->object_array);
  auto accessor = Napi::External<std::shared_ptr<oc_rep_s*>>::New(info.Env(), &sp);
  return OCRepresentation::constructor.New({accessor});
}

void OCValue::set_object_array(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->object_array = *(*(value.As<Napi::External<std::shared_ptr<oc_rep_s*>>>().Data()));
}

Napi::Value OCValue::get_string(const Napi::CallbackInfo& info)
{
  std::shared_ptr<oc_mmem> sp(&m_pvalue->string);
  auto accessor = Napi::External<std::shared_ptr<oc_mmem>>::New(info.Env(), &sp);
  return OCMmem::constructor.New({accessor});
}

void OCValue::set_string(const Napi::CallbackInfo& info, const Napi::Value& value)
{
  m_pvalue->string = *(*(value.As<Napi::External<std::shared_ptr<oc_mmem>>>().Data()));
}

Napi::FunctionReference OCArray::constructor;

Napi::Function OCArray::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCArray", {

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCArray::OCArray(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<oc_array_t>(new oc_array_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<oc_array_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}

Napi::FunctionReference OCCborEncoder::constructor;

Napi::Function OCCborEncoder::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCborEncoder", {

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCborEncoder::OCCborEncoder(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<CborEncoder>(new CborEncoder());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<CborEncoder>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}


Napi::FunctionReference coapTransportType::constructor;

Napi::Function coapTransportType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapTransportType", {
    coapTransportType::StaticAccessor("COAP_TRANSPORT_UDP", coapTransportType::get_COAP_TRANSPORT_UDP, coapTransportType::set_COAP_TRANSPORT_UDP),
    coapTransportType::StaticAccessor("COAP_TRANSPORT_TCP", coapTransportType::get_COAP_TRANSPORT_TCP, coapTransportType::set_COAP_TRANSPORT_TCP),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapTransportType::coapTransportType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_transport_type_t>(new coap_transport_type_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_transport_type_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapTransportType::get_COAP_TRANSPORT_UDP(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_TRANSPORT_UDP);
}

void coapTransportType::set_COAP_TRANSPORT_UDP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapTransportType::get_COAP_TRANSPORT_TCP(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_TRANSPORT_TCP);
}

void coapTransportType::set_COAP_TRANSPORT_TCP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference coapSignalCode::constructor;

Napi::Function coapSignalCode::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapSignalCode", {
    coapSignalCode::StaticAccessor("CSM_7_01", coapSignalCode::get_CSM_7_01, coapSignalCode::set_CSM_7_01),
    coapSignalCode::StaticAccessor("PING_7_02", coapSignalCode::get_PING_7_02, coapSignalCode::set_PING_7_02),
    coapSignalCode::StaticAccessor("PONG_7_03", coapSignalCode::get_PONG_7_03, coapSignalCode::set_PONG_7_03),
    coapSignalCode::StaticAccessor("RELEASE_7_04", coapSignalCode::get_RELEASE_7_04, coapSignalCode::set_RELEASE_7_04),
    coapSignalCode::StaticAccessor("ABORT_7_05", coapSignalCode::get_ABORT_7_05, coapSignalCode::set_ABORT_7_05),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapSignalCode::coapSignalCode(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_signal_code_t>(new coap_signal_code_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_signal_code_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapSignalCode::get_CSM_7_01(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CSM_7_01);
}

void coapSignalCode::set_CSM_7_01(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalCode::get_PING_7_02(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), PING_7_02);
}

void coapSignalCode::set_PING_7_02(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalCode::get_PONG_7_03(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), PONG_7_03);
}

void coapSignalCode::set_PONG_7_03(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalCode::get_RELEASE_7_04(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), RELEASE_7_04);
}

void coapSignalCode::set_RELEASE_7_04(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalCode::get_ABORT_7_05(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), ABORT_7_05);
}

void coapSignalCode::set_ABORT_7_05(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference coapSignalOption::constructor;

Napi::Function coapSignalOption::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapSignalOption", {
    coapSignalOption::StaticAccessor("COAP_SIGNAL_OPTION_MAX_MSG_SIZE", coapSignalOption::get_COAP_SIGNAL_OPTION_MAX_MSG_SIZE, coapSignalOption::set_COAP_SIGNAL_OPTION_MAX_MSG_SIZE),
    coapSignalOption::StaticAccessor("COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER", coapSignalOption::get_COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER, coapSignalOption::set_COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER),
    coapSignalOption::StaticAccessor("COAP_SIGNAL_OPTION_CUSTODY", coapSignalOption::get_COAP_SIGNAL_OPTION_CUSTODY, coapSignalOption::set_COAP_SIGNAL_OPTION_CUSTODY),
    coapSignalOption::StaticAccessor("COAP_SIGNAL_OPTION_ALT_ADDR", coapSignalOption::get_COAP_SIGNAL_OPTION_ALT_ADDR, coapSignalOption::set_COAP_SIGNAL_OPTION_ALT_ADDR),
    coapSignalOption::StaticAccessor("COAP_SIGNAL_OPTION_HOLD_OFF", coapSignalOption::get_COAP_SIGNAL_OPTION_HOLD_OFF, coapSignalOption::set_COAP_SIGNAL_OPTION_HOLD_OFF),
    coapSignalOption::StaticAccessor("COAP_SIGNAL_OPTION_BAD_CSM", coapSignalOption::get_COAP_SIGNAL_OPTION_BAD_CSM, coapSignalOption::set_COAP_SIGNAL_OPTION_BAD_CSM),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapSignalOption::coapSignalOption(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_signal_option_t>(new coap_signal_option_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_signal_option_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapSignalOption::get_COAP_SIGNAL_OPTION_MAX_MSG_SIZE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_SIGNAL_OPTION_MAX_MSG_SIZE);
}

void coapSignalOption::set_COAP_SIGNAL_OPTION_MAX_MSG_SIZE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalOption::get_COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER);
}

void coapSignalOption::set_COAP_SIGNAL_OPTION_BLOCKWISE_TRANSFER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalOption::get_COAP_SIGNAL_OPTION_CUSTODY(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_SIGNAL_OPTION_CUSTODY);
}

void coapSignalOption::set_COAP_SIGNAL_OPTION_CUSTODY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalOption::get_COAP_SIGNAL_OPTION_ALT_ADDR(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_SIGNAL_OPTION_ALT_ADDR);
}

void coapSignalOption::set_COAP_SIGNAL_OPTION_ALT_ADDR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalOption::get_COAP_SIGNAL_OPTION_HOLD_OFF(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_SIGNAL_OPTION_HOLD_OFF);
}

void coapSignalOption::set_COAP_SIGNAL_OPTION_HOLD_OFF(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapSignalOption::get_COAP_SIGNAL_OPTION_BAD_CSM(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_SIGNAL_OPTION_BAD_CSM);
}

void coapSignalOption::set_COAP_SIGNAL_OPTION_BAD_CSM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference coapMessageType::constructor;

Napi::Function coapMessageType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapMessageType", {
    coapMessageType::StaticAccessor("COAP_TYPE_CON", coapMessageType::get_COAP_TYPE_CON, coapMessageType::set_COAP_TYPE_CON),
    coapMessageType::StaticAccessor("COAP_TYPE_NON", coapMessageType::get_COAP_TYPE_NON, coapMessageType::set_COAP_TYPE_NON),
    coapMessageType::StaticAccessor("COAP_TYPE_ACK", coapMessageType::get_COAP_TYPE_ACK, coapMessageType::set_COAP_TYPE_ACK),
    coapMessageType::StaticAccessor("COAP_TYPE_RST", coapMessageType::get_COAP_TYPE_RST, coapMessageType::set_COAP_TYPE_RST),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapMessageType::coapMessageType(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_message_type_t>(new coap_message_type_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_message_type_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapMessageType::get_COAP_TYPE_CON(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_TYPE_CON);
}

void coapMessageType::set_COAP_TYPE_CON(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapMessageType::get_COAP_TYPE_NON(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_TYPE_NON);
}

void coapMessageType::set_COAP_TYPE_NON(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapMessageType::get_COAP_TYPE_ACK(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_TYPE_ACK);
}

void coapMessageType::set_COAP_TYPE_ACK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapMessageType::get_COAP_TYPE_RST(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_TYPE_RST);
}

void coapMessageType::set_COAP_TYPE_RST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference coapMethod::constructor;

Napi::Function coapMethod::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapMethod", {
    coapMethod::StaticAccessor("COAP_GET", coapMethod::get_COAP_GET, coapMethod::set_COAP_GET),
    coapMethod::StaticAccessor("COAP_POST", coapMethod::get_COAP_POST, coapMethod::set_COAP_POST),
    coapMethod::StaticAccessor("COAP_PUT", coapMethod::get_COAP_PUT, coapMethod::set_COAP_PUT),
    coapMethod::StaticAccessor("COAP_DELETE", coapMethod::get_COAP_DELETE, coapMethod::set_COAP_DELETE),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapMethod::coapMethod(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_method_t>(new coap_method_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_method_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapMethod::get_COAP_GET(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_GET);
}

void coapMethod::set_COAP_GET(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapMethod::get_COAP_POST(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_POST);
}

void coapMethod::set_COAP_POST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapMethod::get_COAP_PUT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_PUT);
}

void coapMethod::set_COAP_PUT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapMethod::get_COAP_DELETE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_DELETE);
}

void coapMethod::set_COAP_DELETE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference coapOption::constructor;

Napi::Function coapOption::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapOption", {
    coapOption::StaticAccessor("COAP_OPTION_IF_MATCH", coapOption::get_COAP_OPTION_IF_MATCH, coapOption::set_COAP_OPTION_IF_MATCH),
    coapOption::StaticAccessor("COAP_OPTION_URI_HOST", coapOption::get_COAP_OPTION_URI_HOST, coapOption::set_COAP_OPTION_URI_HOST),
    coapOption::StaticAccessor("COAP_OPTION_ETAG", coapOption::get_COAP_OPTION_ETAG, coapOption::set_COAP_OPTION_ETAG),
    coapOption::StaticAccessor("COAP_OPTION_IF_NONE_MATCH", coapOption::get_COAP_OPTION_IF_NONE_MATCH, coapOption::set_COAP_OPTION_IF_NONE_MATCH),
    coapOption::StaticAccessor("COAP_OPTION_OBSERVE", coapOption::get_COAP_OPTION_OBSERVE, coapOption::set_COAP_OPTION_OBSERVE),
    coapOption::StaticAccessor("COAP_OPTION_URI_PORT", coapOption::get_COAP_OPTION_URI_PORT, coapOption::set_COAP_OPTION_URI_PORT),
    coapOption::StaticAccessor("COAP_OPTION_LOCATION_PATH", coapOption::get_COAP_OPTION_LOCATION_PATH, coapOption::set_COAP_OPTION_LOCATION_PATH),
    coapOption::StaticAccessor("COAP_OPTION_URI_PATH", coapOption::get_COAP_OPTION_URI_PATH, coapOption::set_COAP_OPTION_URI_PATH),
    coapOption::StaticAccessor("COAP_OPTION_CONTENT_FORMAT", coapOption::get_COAP_OPTION_CONTENT_FORMAT, coapOption::set_COAP_OPTION_CONTENT_FORMAT),
    coapOption::StaticAccessor("COAP_OPTION_MAX_AGE", coapOption::get_COAP_OPTION_MAX_AGE, coapOption::set_COAP_OPTION_MAX_AGE),
    coapOption::StaticAccessor("COAP_OPTION_URI_QUERY", coapOption::get_COAP_OPTION_URI_QUERY, coapOption::set_COAP_OPTION_URI_QUERY),
    coapOption::StaticAccessor("COAP_OPTION_ACCEPT", coapOption::get_COAP_OPTION_ACCEPT, coapOption::set_COAP_OPTION_ACCEPT),
    coapOption::StaticAccessor("COAP_OPTION_LOCATION_QUERY", coapOption::get_COAP_OPTION_LOCATION_QUERY, coapOption::set_COAP_OPTION_LOCATION_QUERY),
    coapOption::StaticAccessor("COAP_OPTION_BLOCK2", coapOption::get_COAP_OPTION_BLOCK2, coapOption::set_COAP_OPTION_BLOCK2),
    coapOption::StaticAccessor("COAP_OPTION_BLOCK1", coapOption::get_COAP_OPTION_BLOCK1, coapOption::set_COAP_OPTION_BLOCK1),
    coapOption::StaticAccessor("COAP_OPTION_SIZE2", coapOption::get_COAP_OPTION_SIZE2, coapOption::set_COAP_OPTION_SIZE2),
    coapOption::StaticAccessor("COAP_OPTION_PROXY_URI", coapOption::get_COAP_OPTION_PROXY_URI, coapOption::set_COAP_OPTION_PROXY_URI),
    coapOption::StaticAccessor("COAP_OPTION_PROXY_SCHEME", coapOption::get_COAP_OPTION_PROXY_SCHEME, coapOption::set_COAP_OPTION_PROXY_SCHEME),
    coapOption::StaticAccessor("COAP_OPTION_SIZE1", coapOption::get_COAP_OPTION_SIZE1, coapOption::set_COAP_OPTION_SIZE1),
    coapOption::StaticAccessor("OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER", coapOption::get_OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER, coapOption::set_OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER),
    coapOption::StaticAccessor("OCF_OPTION_CONTENT_FORMAT_VER", coapOption::get_OCF_OPTION_CONTENT_FORMAT_VER, coapOption::set_OCF_OPTION_CONTENT_FORMAT_VER),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapOption::coapOption(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_option_t>(new coap_option_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_option_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapOption::get_COAP_OPTION_IF_MATCH(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_IF_MATCH);
}

void coapOption::set_COAP_OPTION_IF_MATCH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_URI_HOST(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_URI_HOST);
}

void coapOption::set_COAP_OPTION_URI_HOST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_ETAG(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_ETAG);
}

void coapOption::set_COAP_OPTION_ETAG(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_IF_NONE_MATCH(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_IF_NONE_MATCH);
}

void coapOption::set_COAP_OPTION_IF_NONE_MATCH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_OBSERVE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_OBSERVE);
}

void coapOption::set_COAP_OPTION_OBSERVE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_URI_PORT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_URI_PORT);
}

void coapOption::set_COAP_OPTION_URI_PORT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_LOCATION_PATH(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_LOCATION_PATH);
}

void coapOption::set_COAP_OPTION_LOCATION_PATH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_URI_PATH(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_URI_PATH);
}

void coapOption::set_COAP_OPTION_URI_PATH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_CONTENT_FORMAT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_CONTENT_FORMAT);
}

void coapOption::set_COAP_OPTION_CONTENT_FORMAT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_MAX_AGE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_MAX_AGE);
}

void coapOption::set_COAP_OPTION_MAX_AGE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_URI_QUERY(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_URI_QUERY);
}

void coapOption::set_COAP_OPTION_URI_QUERY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_ACCEPT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_ACCEPT);
}

void coapOption::set_COAP_OPTION_ACCEPT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_LOCATION_QUERY(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_LOCATION_QUERY);
}

void coapOption::set_COAP_OPTION_LOCATION_QUERY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_BLOCK2(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_BLOCK2);
}

void coapOption::set_COAP_OPTION_BLOCK2(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_BLOCK1(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_BLOCK1);
}

void coapOption::set_COAP_OPTION_BLOCK1(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_SIZE2(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_SIZE2);
}

void coapOption::set_COAP_OPTION_SIZE2(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_PROXY_URI(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_PROXY_URI);
}

void coapOption::set_COAP_OPTION_PROXY_URI(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_PROXY_SCHEME(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_PROXY_SCHEME);
}

void coapOption::set_COAP_OPTION_PROXY_SCHEME(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_COAP_OPTION_SIZE1(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_OPTION_SIZE1);
}

void coapOption::set_COAP_OPTION_SIZE1(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER);
}

void coapOption::set_OCF_OPTION_ACCEPT_CONTENT_FORMAT_VER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapOption::get_OCF_OPTION_CONTENT_FORMAT_VER(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_OPTION_CONTENT_FORMAT_VER);
}

void coapOption::set_OCF_OPTION_CONTENT_FORMAT_VER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference coapStatus::constructor;

Napi::Function coapStatus::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "coapStatus", {
    coapStatus::StaticAccessor("COAP_NO_ERROR", coapStatus::get_COAP_NO_ERROR, coapStatus::set_COAP_NO_ERROR),
    coapStatus::StaticAccessor("CREATED_2_01", coapStatus::get_CREATED_2_01, coapStatus::set_CREATED_2_01),
    coapStatus::StaticAccessor("DELETED_2_02", coapStatus::get_DELETED_2_02, coapStatus::set_DELETED_2_02),
    coapStatus::StaticAccessor("VALID_2_03", coapStatus::get_VALID_2_03, coapStatus::set_VALID_2_03),
    coapStatus::StaticAccessor("CHANGED_2_04", coapStatus::get_CHANGED_2_04, coapStatus::set_CHANGED_2_04),
    coapStatus::StaticAccessor("CONTENT_2_05", coapStatus::get_CONTENT_2_05, coapStatus::set_CONTENT_2_05),
    coapStatus::StaticAccessor("CONTINUE_2_31", coapStatus::get_CONTINUE_2_31, coapStatus::set_CONTINUE_2_31),
    coapStatus::StaticAccessor("BAD_REQUEST_4_00", coapStatus::get_BAD_REQUEST_4_00, coapStatus::set_BAD_REQUEST_4_00),
    coapStatus::StaticAccessor("UNAUTHORIZED_4_01", coapStatus::get_UNAUTHORIZED_4_01, coapStatus::set_UNAUTHORIZED_4_01),
    coapStatus::StaticAccessor("BAD_OPTION_4_02", coapStatus::get_BAD_OPTION_4_02, coapStatus::set_BAD_OPTION_4_02),
    coapStatus::StaticAccessor("FORBIDDEN_4_03", coapStatus::get_FORBIDDEN_4_03, coapStatus::set_FORBIDDEN_4_03),
    coapStatus::StaticAccessor("NOT_FOUND_4_04", coapStatus::get_NOT_FOUND_4_04, coapStatus::set_NOT_FOUND_4_04),
    coapStatus::StaticAccessor("METHOD_NOT_ALLOWED_4_05", coapStatus::get_METHOD_NOT_ALLOWED_4_05, coapStatus::set_METHOD_NOT_ALLOWED_4_05),
    coapStatus::StaticAccessor("NOT_ACCEPTABLE_4_06", coapStatus::get_NOT_ACCEPTABLE_4_06, coapStatus::set_NOT_ACCEPTABLE_4_06),
    coapStatus::StaticAccessor("PRECONDITION_FAILED_4_12", coapStatus::get_PRECONDITION_FAILED_4_12, coapStatus::set_PRECONDITION_FAILED_4_12),
    coapStatus::StaticAccessor("REQUEST_ENTITY_TOO_LARGE_4_13", coapStatus::get_REQUEST_ENTITY_TOO_LARGE_4_13, coapStatus::set_REQUEST_ENTITY_TOO_LARGE_4_13),
    coapStatus::StaticAccessor("UNSUPPORTED_MEDIA_TYPE_4_15", coapStatus::get_UNSUPPORTED_MEDIA_TYPE_4_15, coapStatus::set_UNSUPPORTED_MEDIA_TYPE_4_15),
    coapStatus::StaticAccessor("INTERNAL_SERVER_ERROR_5_00", coapStatus::get_INTERNAL_SERVER_ERROR_5_00, coapStatus::set_INTERNAL_SERVER_ERROR_5_00),
    coapStatus::StaticAccessor("NOT_IMPLEMENTED_5_01", coapStatus::get_NOT_IMPLEMENTED_5_01, coapStatus::set_NOT_IMPLEMENTED_5_01),
    coapStatus::StaticAccessor("BAD_GATEWAY_5_02", coapStatus::get_BAD_GATEWAY_5_02, coapStatus::set_BAD_GATEWAY_5_02),
    coapStatus::StaticAccessor("SERVICE_UNAVAILABLE_5_03", coapStatus::get_SERVICE_UNAVAILABLE_5_03, coapStatus::set_SERVICE_UNAVAILABLE_5_03),
    coapStatus::StaticAccessor("GATEWAY_TIMEOUT_5_04", coapStatus::get_GATEWAY_TIMEOUT_5_04, coapStatus::set_GATEWAY_TIMEOUT_5_04),
    coapStatus::StaticAccessor("PROXYING_NOT_SUPPORTED_5_05", coapStatus::get_PROXYING_NOT_SUPPORTED_5_05, coapStatus::set_PROXYING_NOT_SUPPORTED_5_05),
    coapStatus::StaticAccessor("MEMORY_ALLOCATION_ERROR", coapStatus::get_MEMORY_ALLOCATION_ERROR, coapStatus::set_MEMORY_ALLOCATION_ERROR),
    coapStatus::StaticAccessor("PACKET_SERIALIZATION_ERROR", coapStatus::get_PACKET_SERIALIZATION_ERROR, coapStatus::set_PACKET_SERIALIZATION_ERROR),
    coapStatus::StaticAccessor("CLEAR_TRANSACTION", coapStatus::get_CLEAR_TRANSACTION, coapStatus::set_CLEAR_TRANSACTION),
    coapStatus::StaticAccessor("EMPTY_ACK_RESPONSE", coapStatus::get_EMPTY_ACK_RESPONSE, coapStatus::set_EMPTY_ACK_RESPONSE),
    coapStatus::StaticAccessor("CLOSE_ALL_TLS_SESSIONS", coapStatus::get_CLOSE_ALL_TLS_SESSIONS, coapStatus::set_CLOSE_ALL_TLS_SESSIONS),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
coapStatus::coapStatus(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<coap_status_t>(new coap_status_t());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<coap_status_t>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
Napi::Value coapStatus::get_COAP_NO_ERROR(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), COAP_NO_ERROR);
}

void coapStatus::set_COAP_NO_ERROR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_CREATED_2_01(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CREATED_2_01);
}

void coapStatus::set_CREATED_2_01(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_DELETED_2_02(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), DELETED_2_02);
}

void coapStatus::set_DELETED_2_02(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_VALID_2_03(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), VALID_2_03);
}

void coapStatus::set_VALID_2_03(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_CHANGED_2_04(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CHANGED_2_04);
}

void coapStatus::set_CHANGED_2_04(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_CONTENT_2_05(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CONTENT_2_05);
}

void coapStatus::set_CONTENT_2_05(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_CONTINUE_2_31(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CONTINUE_2_31);
}

void coapStatus::set_CONTINUE_2_31(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_BAD_REQUEST_4_00(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), BAD_REQUEST_4_00);
}

void coapStatus::set_BAD_REQUEST_4_00(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_UNAUTHORIZED_4_01(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), UNAUTHORIZED_4_01);
}

void coapStatus::set_UNAUTHORIZED_4_01(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_BAD_OPTION_4_02(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), BAD_OPTION_4_02);
}

void coapStatus::set_BAD_OPTION_4_02(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_FORBIDDEN_4_03(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), FORBIDDEN_4_03);
}

void coapStatus::set_FORBIDDEN_4_03(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_NOT_FOUND_4_04(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), NOT_FOUND_4_04);
}

void coapStatus::set_NOT_FOUND_4_04(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_METHOD_NOT_ALLOWED_4_05(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), METHOD_NOT_ALLOWED_4_05);
}

void coapStatus::set_METHOD_NOT_ALLOWED_4_05(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_NOT_ACCEPTABLE_4_06(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), NOT_ACCEPTABLE_4_06);
}

void coapStatus::set_NOT_ACCEPTABLE_4_06(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_PRECONDITION_FAILED_4_12(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), PRECONDITION_FAILED_4_12);
}

void coapStatus::set_PRECONDITION_FAILED_4_12(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_REQUEST_ENTITY_TOO_LARGE_4_13(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), REQUEST_ENTITY_TOO_LARGE_4_13);
}

void coapStatus::set_REQUEST_ENTITY_TOO_LARGE_4_13(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_UNSUPPORTED_MEDIA_TYPE_4_15(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), UNSUPPORTED_MEDIA_TYPE_4_15);
}

void coapStatus::set_UNSUPPORTED_MEDIA_TYPE_4_15(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_INTERNAL_SERVER_ERROR_5_00(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), INTERNAL_SERVER_ERROR_5_00);
}

void coapStatus::set_INTERNAL_SERVER_ERROR_5_00(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_NOT_IMPLEMENTED_5_01(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), NOT_IMPLEMENTED_5_01);
}

void coapStatus::set_NOT_IMPLEMENTED_5_01(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_BAD_GATEWAY_5_02(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), BAD_GATEWAY_5_02);
}

void coapStatus::set_BAD_GATEWAY_5_02(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_SERVICE_UNAVAILABLE_5_03(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), SERVICE_UNAVAILABLE_5_03);
}

void coapStatus::set_SERVICE_UNAVAILABLE_5_03(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_GATEWAY_TIMEOUT_5_04(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), GATEWAY_TIMEOUT_5_04);
}

void coapStatus::set_GATEWAY_TIMEOUT_5_04(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_PROXYING_NOT_SUPPORTED_5_05(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), PROXYING_NOT_SUPPORTED_5_05);
}

void coapStatus::set_PROXYING_NOT_SUPPORTED_5_05(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_MEMORY_ALLOCATION_ERROR(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), MEMORY_ALLOCATION_ERROR);
}

void coapStatus::set_MEMORY_ALLOCATION_ERROR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_PACKET_SERIALIZATION_ERROR(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), PACKET_SERIALIZATION_ERROR);
}

void coapStatus::set_PACKET_SERIALIZATION_ERROR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_CLEAR_TRANSACTION(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CLEAR_TRANSACTION);
}

void coapStatus::set_CLEAR_TRANSACTION(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_EMPTY_ACK_RESPONSE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), EMPTY_ACK_RESPONSE);
}

void coapStatus::set_EMPTY_ACK_RESPONSE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value coapStatus::get_CLOSE_ALL_TLS_SESSIONS(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), CLOSE_ALL_TLS_SESSIONS);
}

void coapStatus::set_CLOSE_ALL_TLS_SESSIONS(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCAceConnectionType::constructor;

Napi::Function OCAceConnectionType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceConnectionType", {
    OCAceConnectionType::StaticAccessor("OC_CONN_AUTH_CRYPT", OCAceConnectionType::get_OC_CONN_AUTH_CRYPT, OCAceConnectionType::set_OC_CONN_AUTH_CRYPT),
    OCAceConnectionType::StaticAccessor("OC_CONN_ANON_CLEAR", OCAceConnectionType::get_OC_CONN_ANON_CLEAR, OCAceConnectionType::set_OC_CONN_ANON_CLEAR),

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

Napi::FunctionReference OCAcePermissionsMask::constructor;

Napi::Function OCAcePermissionsMask::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAcePermissionsMask", {
    OCAcePermissionsMask::StaticAccessor("OC_PERM_NONE", OCAcePermissionsMask::get_OC_PERM_NONE, OCAcePermissionsMask::set_OC_PERM_NONE),
    OCAcePermissionsMask::StaticAccessor("OC_PERM_CREATE", OCAcePermissionsMask::get_OC_PERM_CREATE, OCAcePermissionsMask::set_OC_PERM_CREATE),
    OCAcePermissionsMask::StaticAccessor("OC_PERM_RETRIEVE", OCAcePermissionsMask::get_OC_PERM_RETRIEVE, OCAcePermissionsMask::set_OC_PERM_RETRIEVE),
    OCAcePermissionsMask::StaticAccessor("OC_PERM_UPDATE", OCAcePermissionsMask::get_OC_PERM_UPDATE, OCAcePermissionsMask::set_OC_PERM_UPDATE),
    OCAcePermissionsMask::StaticAccessor("OC_PERM_DELETE", OCAcePermissionsMask::get_OC_PERM_DELETE, OCAcePermissionsMask::set_OC_PERM_DELETE),
    OCAcePermissionsMask::StaticAccessor("OC_PERM_NOTIFY", OCAcePermissionsMask::get_OC_PERM_NOTIFY, OCAcePermissionsMask::set_OC_PERM_NOTIFY),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCAcePermissionsMask::OCAcePermissionsMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCAcePermissionsMask::get_OC_PERM_NONE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERM_NONE);
}

void OCAcePermissionsMask::set_OC_PERM_NONE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissionsMask::get_OC_PERM_CREATE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERM_CREATE);
}

void OCAcePermissionsMask::set_OC_PERM_CREATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissionsMask::get_OC_PERM_RETRIEVE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERM_RETRIEVE);
}

void OCAcePermissionsMask::set_OC_PERM_RETRIEVE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissionsMask::get_OC_PERM_UPDATE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERM_UPDATE);
}

void OCAcePermissionsMask::set_OC_PERM_UPDATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissionsMask::get_OC_PERM_DELETE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERM_DELETE);
}

void OCAcePermissionsMask::set_OC_PERM_DELETE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCAcePermissionsMask::get_OC_PERM_NOTIFY(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERM_NOTIFY);
}

void OCAcePermissionsMask::set_OC_PERM_NOTIFY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCAceSubjectType::constructor;

Napi::Function OCAceSubjectType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceSubjectType", {
    OCAceSubjectType::StaticAccessor("OC_SUBJECT_UUID", OCAceSubjectType::get_OC_SUBJECT_UUID, OCAceSubjectType::set_OC_SUBJECT_UUID),
    OCAceSubjectType::StaticAccessor("OC_SUBJECT_ROLE", OCAceSubjectType::get_OC_SUBJECT_ROLE, OCAceSubjectType::set_OC_SUBJECT_ROLE),
    OCAceSubjectType::StaticAccessor("OC_SUBJECT_CONN", OCAceSubjectType::get_OC_SUBJECT_CONN, OCAceSubjectType::set_OC_SUBJECT_CONN),

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

Napi::FunctionReference OCAceWildcard::constructor;

Napi::Function OCAceWildcard::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCAceWildcard", {
    OCAceWildcard::StaticAccessor("OC_ACE_NO_WC", OCAceWildcard::get_OC_ACE_NO_WC, OCAceWildcard::set_OC_ACE_NO_WC),
    OCAceWildcard::StaticAccessor("OC_ACE_WC_ALL", OCAceWildcard::get_OC_ACE_WC_ALL, OCAceWildcard::set_OC_ACE_WC_ALL),
    OCAceWildcard::StaticAccessor("OC_ACE_WC_ALL_SECURED", OCAceWildcard::get_OC_ACE_WC_ALL_SECURED, OCAceWildcard::set_OC_ACE_WC_ALL_SECURED),
    OCAceWildcard::StaticAccessor("OC_ACE_WC_ALL_PUBLIC", OCAceWildcard::get_OC_ACE_WC_ALL_PUBLIC, OCAceWildcard::set_OC_ACE_WC_ALL_PUBLIC),

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

Napi::FunctionReference OCBlockwiseRole::constructor;

Napi::Function OCBlockwiseRole::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCBlockwiseRole", {
    OCBlockwiseRole::StaticAccessor("OC_BLOCKWISE_CLIENT", OCBlockwiseRole::get_OC_BLOCKWISE_CLIENT, OCBlockwiseRole::set_OC_BLOCKWISE_CLIENT),
    OCBlockwiseRole::StaticAccessor("OC_BLOCKWISE_SERVER", OCBlockwiseRole::get_OC_BLOCKWISE_SERVER, OCBlockwiseRole::set_OC_BLOCKWISE_SERVER),

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

Napi::FunctionReference OCDiscoveryFlags::constructor;

Napi::Function OCDiscoveryFlags::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCDiscoveryFlags", {
    OCDiscoveryFlags::StaticAccessor("OC_STOP_DISCOVERY", OCDiscoveryFlags::get_OC_STOP_DISCOVERY, OCDiscoveryFlags::set_OC_STOP_DISCOVERY),
    OCDiscoveryFlags::StaticAccessor("OC_CONTINUE_DISCOVERY", OCDiscoveryFlags::get_OC_CONTINUE_DISCOVERY, OCDiscoveryFlags::set_OC_CONTINUE_DISCOVERY),

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

Napi::FunctionReference OCQos::constructor;

Napi::Function OCQos::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCQos", {
    OCQos::StaticAccessor("HIGH_QOS", OCQos::get_HIGH_QOS, OCQos::set_HIGH_QOS),
    OCQos::StaticAccessor("LOW_QOS", OCQos::get_LOW_QOS, OCQos::set_LOW_QOS),

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

Napi::FunctionReference OCCloudError::constructor;

Napi::Function OCCloudError::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudError", {
    OCCloudError::StaticAccessor("CLOUD_OK", OCCloudError::get_CLOUD_OK, OCCloudError::set_CLOUD_OK),
    OCCloudError::StaticAccessor("CLOUD_ERROR_RESPONSE", OCCloudError::get_CLOUD_ERROR_RESPONSE, OCCloudError::set_CLOUD_ERROR_RESPONSE),
    OCCloudError::StaticAccessor("CLOUD_ERROR_CONNECT", OCCloudError::get_CLOUD_ERROR_CONNECT, OCCloudError::set_CLOUD_ERROR_CONNECT),
    OCCloudError::StaticAccessor("CLOUD_ERROR_REFRESH_ACCESS_TOKEN", OCCloudError::get_CLOUD_ERROR_REFRESH_ACCESS_TOKEN, OCCloudError::set_CLOUD_ERROR_REFRESH_ACCESS_TOKEN),

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

Napi::FunctionReference OCCloudStatusMask::constructor;

Napi::Function OCCloudStatusMask::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudStatusMask", {
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_INITIALIZED", OCCloudStatusMask::get_OC_CLOUD_INITIALIZED, OCCloudStatusMask::set_OC_CLOUD_INITIALIZED),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_REGISTERED", OCCloudStatusMask::get_OC_CLOUD_REGISTERED, OCCloudStatusMask::set_OC_CLOUD_REGISTERED),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_LOGGED_IN", OCCloudStatusMask::get_OC_CLOUD_LOGGED_IN, OCCloudStatusMask::set_OC_CLOUD_LOGGED_IN),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_TOKEN_EXPIRY", OCCloudStatusMask::get_OC_CLOUD_TOKEN_EXPIRY, OCCloudStatusMask::set_OC_CLOUD_TOKEN_EXPIRY),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_REFRESHED_TOKEN", OCCloudStatusMask::get_OC_CLOUD_REFRESHED_TOKEN, OCCloudStatusMask::set_OC_CLOUD_REFRESHED_TOKEN),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_LOGGED_OUT", OCCloudStatusMask::get_OC_CLOUD_LOGGED_OUT, OCCloudStatusMask::set_OC_CLOUD_LOGGED_OUT),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_FAILURE", OCCloudStatusMask::get_OC_CLOUD_FAILURE, OCCloudStatusMask::set_OC_CLOUD_FAILURE),
    OCCloudStatusMask::StaticAccessor("OC_CLOUD_DEREGISTERED", OCCloudStatusMask::get_OC_CLOUD_DEREGISTERED, OCCloudStatusMask::set_OC_CLOUD_DEREGISTERED),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCloudStatusMask::OCCloudStatusMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCCloudStatusMask::get_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_INITIALIZED);
}

void OCCloudStatusMask::set_OC_CLOUD_INITIALIZED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_REGISTERED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_REGISTERED);
}

void OCCloudStatusMask::set_OC_CLOUD_REGISTERED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_LOGGED_IN);
}

void OCCloudStatusMask::set_OC_CLOUD_LOGGED_IN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_TOKEN_EXPIRY);
}

void OCCloudStatusMask::set_OC_CLOUD_TOKEN_EXPIRY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_REFRESHED_TOKEN);
}

void OCCloudStatusMask::set_OC_CLOUD_REFRESHED_TOKEN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_LOGGED_OUT);
}

void OCCloudStatusMask::set_OC_CLOUD_LOGGED_OUT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_FAILURE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_FAILURE);
}

void OCCloudStatusMask::set_OC_CLOUD_FAILURE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudStatusMask::get_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CLOUD_DEREGISTERED);
}

void OCCloudStatusMask::set_OC_CLOUD_DEREGISTERED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCCloudPrivisoningStatus::constructor;

Napi::Function OCCloudPrivisoningStatus::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCloudPrivisoningStatus", {
    OCCloudPrivisoningStatus::StaticAccessor("OC_CPS_UNINITIALIZED", OCCloudPrivisoningStatus::get_OC_CPS_UNINITIALIZED, OCCloudPrivisoningStatus::set_OC_CPS_UNINITIALIZED),
    OCCloudPrivisoningStatus::StaticAccessor("OC_CPS_READYTOREGISTER", OCCloudPrivisoningStatus::get_OC_CPS_READYTOREGISTER, OCCloudPrivisoningStatus::set_OC_CPS_READYTOREGISTER),
    OCCloudPrivisoningStatus::StaticAccessor("OC_CPS_REGISTERING", OCCloudPrivisoningStatus::get_OC_CPS_REGISTERING, OCCloudPrivisoningStatus::set_OC_CPS_REGISTERING),
    OCCloudPrivisoningStatus::StaticAccessor("OC_CPS_REGISTERED", OCCloudPrivisoningStatus::get_OC_CPS_REGISTERED, OCCloudPrivisoningStatus::set_OC_CPS_REGISTERED),
    OCCloudPrivisoningStatus::StaticAccessor("OC_CPS_FAILED", OCCloudPrivisoningStatus::get_OC_CPS_FAILED, OCCloudPrivisoningStatus::set_OC_CPS_FAILED),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCloudPrivisoningStatus::OCCloudPrivisoningStatus(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CPS_UNINITIALIZED);
}

void OCCloudPrivisoningStatus::set_OC_CPS_UNINITIALIZED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CPS_READYTOREGISTER);
}

void OCCloudPrivisoningStatus::set_OC_CPS_READYTOREGISTER(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_REGISTERING(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CPS_REGISTERING);
}

void OCCloudPrivisoningStatus::set_OC_CPS_REGISTERING(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_REGISTERED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CPS_REGISTERED);
}

void OCCloudPrivisoningStatus::set_OC_CPS_REGISTERED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCloudPrivisoningStatus::get_OC_CPS_FAILED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CPS_FAILED);
}

void OCCloudPrivisoningStatus::set_OC_CPS_FAILED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

#if defined(OC_TCP)
Napi::FunctionReference tcpCsmState::constructor;

Napi::Function tcpCsmState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "tcpCsmState", {
    tcpCsmState::StaticAccessor("CSM_NONE", tcpCsmState::get_CSM_NONE, tcpCsmState::set_CSM_NONE),
    tcpCsmState::StaticAccessor("CSM_SENT", tcpCsmState::get_CSM_SENT, tcpCsmState::set_CSM_SENT),
    tcpCsmState::StaticAccessor("CSM_DONE", tcpCsmState::get_CSM_DONE, tcpCsmState::set_CSM_DONE),
    tcpCsmState::StaticAccessor("CSM_ERROR", tcpCsmState::get_CSM_ERROR, tcpCsmState::set_CSM_ERROR),

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

Napi::FunctionReference OCCredType::constructor;

Napi::Function OCCredType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCredType", {
    OCCredType::StaticAccessor("OC_CREDTYPE_NULL", OCCredType::get_OC_CREDTYPE_NULL, OCCredType::set_OC_CREDTYPE_NULL),
    OCCredType::StaticAccessor("OC_CREDTYPE_PSK", OCCredType::get_OC_CREDTYPE_PSK, OCCredType::set_OC_CREDTYPE_PSK),
    OCCredType::StaticAccessor("OC_CREDTYPE_CERT", OCCredType::get_OC_CREDTYPE_CERT, OCCredType::set_OC_CREDTYPE_CERT),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCredType::OCCredType(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCCredType::get_OC_CREDTYPE_NULL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDTYPE_NULL);
}

void OCCredType::set_OC_CREDTYPE_NULL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredType::get_OC_CREDTYPE_PSK(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDTYPE_PSK);
}

void OCCredType::set_OC_CREDTYPE_PSK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredType::get_OC_CREDTYPE_CERT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDTYPE_CERT);
}

void OCCredType::set_OC_CREDTYPE_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCCredUsage::constructor;

Napi::Function OCCredUsage::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCredUsage", {
    OCCredUsage::StaticAccessor("OC_CREDUSAGE_NULL", OCCredUsage::get_OC_CREDUSAGE_NULL, OCCredUsage::set_OC_CREDUSAGE_NULL),
    OCCredUsage::StaticAccessor("OC_CREDUSAGE_TRUSTCA", OCCredUsage::get_OC_CREDUSAGE_TRUSTCA, OCCredUsage::set_OC_CREDUSAGE_TRUSTCA),
    OCCredUsage::StaticAccessor("OC_CREDUSAGE_IDENTITY_CERT", OCCredUsage::get_OC_CREDUSAGE_IDENTITY_CERT, OCCredUsage::set_OC_CREDUSAGE_IDENTITY_CERT),
    OCCredUsage::StaticAccessor("OC_CREDUSAGE_ROLE_CERT", OCCredUsage::get_OC_CREDUSAGE_ROLE_CERT, OCCredUsage::set_OC_CREDUSAGE_ROLE_CERT),
    OCCredUsage::StaticAccessor("OC_CREDUSAGE_MFG_TRUSTCA", OCCredUsage::get_OC_CREDUSAGE_MFG_TRUSTCA, OCCredUsage::set_OC_CREDUSAGE_MFG_TRUSTCA),
    OCCredUsage::StaticAccessor("OC_CREDUSAGE_MFG_CERT", OCCredUsage::get_OC_CREDUSAGE_MFG_CERT, OCCredUsage::set_OC_CREDUSAGE_MFG_CERT),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCCredUsage::OCCredUsage(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCCredUsage::get_OC_CREDUSAGE_NULL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDUSAGE_NULL);
}

void OCCredUsage::set_OC_CREDUSAGE_NULL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDUSAGE_TRUSTCA);
}

void OCCredUsage::set_OC_CREDUSAGE_TRUSTCA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDUSAGE_IDENTITY_CERT);
}

void OCCredUsage::set_OC_CREDUSAGE_IDENTITY_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDUSAGE_ROLE_CERT);
}

void OCCredUsage::set_OC_CREDUSAGE_ROLE_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDUSAGE_MFG_TRUSTCA);
}

void OCCredUsage::set_OC_CREDUSAGE_MFG_TRUSTCA(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCCredUsage::get_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_CREDUSAGE_MFG_CERT);
}

void OCCredUsage::set_OC_CREDUSAGE_MFG_CERT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCEncoding::constructor;

Napi::Function OCEncoding::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEncoding", {
    OCEncoding::StaticAccessor("OC_ENCODING_UNSUPPORTED", OCEncoding::get_OC_ENCODING_UNSUPPORTED, OCEncoding::set_OC_ENCODING_UNSUPPORTED),
    OCEncoding::StaticAccessor("OC_ENCODING_BASE64", OCEncoding::get_OC_ENCODING_BASE64, OCEncoding::set_OC_ENCODING_BASE64),
    OCEncoding::StaticAccessor("OC_ENCODING_RAW", OCEncoding::get_OC_ENCODING_RAW, OCEncoding::set_OC_ENCODING_RAW),
    OCEncoding::StaticAccessor("OC_ENCODING_PEM", OCEncoding::get_OC_ENCODING_PEM, OCEncoding::set_OC_ENCODING_PEM),
    OCEncoding::StaticAccessor("OC_ENCODING_HANDLE", OCEncoding::get_OC_ENCODING_HANDLE, OCEncoding::set_OC_ENCODING_HANDLE),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEncoding::OCEncoding(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCEncoding::get_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_ENCODING_UNSUPPORTED);
}

void OCEncoding::set_OC_ENCODING_UNSUPPORTED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEncoding::get_OC_ENCODING_BASE64(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_ENCODING_BASE64);
}

void OCEncoding::set_OC_ENCODING_BASE64(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEncoding::get_OC_ENCODING_RAW(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_ENCODING_RAW);
}

void OCEncoding::set_OC_ENCODING_RAW(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEncoding::get_OC_ENCODING_PEM(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_ENCODING_PEM);
}

void OCEncoding::set_OC_ENCODING_PEM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEncoding::get_OC_ENCODING_HANDLE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_ENCODING_HANDLE);
}

void OCEncoding::set_OC_ENCODING_HANDLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCFVersion::constructor;

Napi::Function OCFVersion::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCFVersion", {
    OCFVersion::StaticAccessor("OCF_VER_1_0_0", OCFVersion::get_OCF_VER_1_0_0, OCFVersion::set_OCF_VER_1_0_0),
    OCFVersion::StaticAccessor("OIC_VER_1_1_0", OCFVersion::get_OIC_VER_1_1_0, OCFVersion::set_OIC_VER_1_1_0),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCFVersion::OCFVersion(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCFVersion::get_OCF_VER_1_0_0(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_VER_1_0_0);
}

void OCFVersion::set_OCF_VER_1_0_0(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCFVersion::get_OIC_VER_1_1_0(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OIC_VER_1_1_0);
}

void OCFVersion::set_OIC_VER_1_1_0(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCTransportFlags::constructor;

Napi::Function OCTransportFlags::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCTransportFlags", {
    OCTransportFlags::StaticAccessor("DISCOVERY", OCTransportFlags::get_DISCOVERY, OCTransportFlags::set_DISCOVERY),
    OCTransportFlags::StaticAccessor("SECURED", OCTransportFlags::get_SECURED, OCTransportFlags::set_SECURED),
    OCTransportFlags::StaticAccessor("IPV4", OCTransportFlags::get_IPV4, OCTransportFlags::set_IPV4),
    OCTransportFlags::StaticAccessor("IPV6", OCTransportFlags::get_IPV6, OCTransportFlags::set_IPV6),
    OCTransportFlags::StaticAccessor("TCP", OCTransportFlags::get_TCP, OCTransportFlags::set_TCP),
    OCTransportFlags::StaticAccessor("GATT", OCTransportFlags::get_GATT, OCTransportFlags::set_GATT),
    OCTransportFlags::StaticAccessor("MULTICAST", OCTransportFlags::get_MULTICAST, OCTransportFlags::set_MULTICAST),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCTransportFlags::OCTransportFlags(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCTransportFlags::get_DISCOVERY(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), DISCOVERY);
}

void OCTransportFlags::set_DISCOVERY(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCTransportFlags::get_SECURED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), SECURED);
}

void OCTransportFlags::set_SECURED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCTransportFlags::get_IPV4(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), IPV4);
}

void OCTransportFlags::set_IPV4(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCTransportFlags::get_IPV6(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), IPV6);
}

void OCTransportFlags::set_IPV6(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCTransportFlags::get_TCP(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), TCP);
}

void OCTransportFlags::set_TCP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCTransportFlags::get_GATT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), GATT);
}

void OCTransportFlags::set_GATT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCTransportFlags::get_MULTICAST(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), MULTICAST);
}

void OCTransportFlags::set_MULTICAST(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCEnum::constructor;

Napi::Function OCEnum::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEnum", {
    OCEnum::StaticAccessor("OC_ENUM_ABORTED", OCEnum::get_OC_ENUM_ABORTED, OCEnum::set_OC_ENUM_ABORTED),
    OCEnum::StaticAccessor("OC_ENUM_ACTIVE", OCEnum::get_OC_ENUM_ACTIVE, OCEnum::set_OC_ENUM_ACTIVE),
    OCEnum::StaticAccessor("OC_ENUM_AIRDRY", OCEnum::get_OC_ENUM_AIRDRY, OCEnum::set_OC_ENUM_AIRDRY),
    OCEnum::StaticAccessor("OC_ENUM_ARMEDAWAY", OCEnum::get_OC_ENUM_ARMEDAWAY, OCEnum::set_OC_ENUM_ARMEDAWAY),
    OCEnum::StaticAccessor("OC_ENUM_ARMEDINSTANT", OCEnum::get_OC_ENUM_ARMEDINSTANT, OCEnum::set_OC_ENUM_ARMEDINSTANT),
    OCEnum::StaticAccessor("OC_ENUM_ARMEDMAXIMUM", OCEnum::get_OC_ENUM_ARMEDMAXIMUM, OCEnum::set_OC_ENUM_ARMEDMAXIMUM),
    OCEnum::StaticAccessor("OC_ENUM_ARMEDNIGHTSTAY", OCEnum::get_OC_ENUM_ARMEDNIGHTSTAY, OCEnum::set_OC_ENUM_ARMEDNIGHTSTAY),
    OCEnum::StaticAccessor("OC_ENUM_ARMEDSTAY", OCEnum::get_OC_ENUM_ARMEDSTAY, OCEnum::set_OC_ENUM_ARMEDSTAY),
    OCEnum::StaticAccessor("OC_ENUM_AROMA", OCEnum::get_OC_ENUM_AROMA, OCEnum::set_OC_ENUM_AROMA),
    OCEnum::StaticAccessor("OC_ENUM_AI", OCEnum::get_OC_ENUM_AI, OCEnum::set_OC_ENUM_AI),
    OCEnum::StaticAccessor("OC_ENUM_AUTO", OCEnum::get_OC_ENUM_AUTO, OCEnum::set_OC_ENUM_AUTO),
    OCEnum::StaticAccessor("OC_ENUM_BOILING", OCEnum::get_OC_ENUM_BOILING, OCEnum::set_OC_ENUM_BOILING),
    OCEnum::StaticAccessor("OC_ENUM_BREWING", OCEnum::get_OC_ENUM_BREWING, OCEnum::set_OC_ENUM_BREWING),
    OCEnum::StaticAccessor("OC_ENUM_CANCELLED", OCEnum::get_OC_ENUM_CANCELLED, OCEnum::set_OC_ENUM_CANCELLED),
    OCEnum::StaticAccessor("OC_ENUM_CIRCULATING", OCEnum::get_OC_ENUM_CIRCULATING, OCEnum::set_OC_ENUM_CIRCULATING),
    OCEnum::StaticAccessor("OC_ENUM_CLEANING", OCEnum::get_OC_ENUM_CLEANING, OCEnum::set_OC_ENUM_CLEANING),
    OCEnum::StaticAccessor("OC_ENUM_CLOTHES", OCEnum::get_OC_ENUM_CLOTHES, OCEnum::set_OC_ENUM_CLOTHES),
    OCEnum::StaticAccessor("OC_ENUM_COMPLETED", OCEnum::get_OC_ENUM_COMPLETED, OCEnum::set_OC_ENUM_COMPLETED),
    OCEnum::StaticAccessor("OC_ENUM_COOL", OCEnum::get_OC_ENUM_COOL, OCEnum::set_OC_ENUM_COOL),
    OCEnum::StaticAccessor("OC_ENUM_DELICATE", OCEnum::get_OC_ENUM_DELICATE, OCEnum::set_OC_ENUM_DELICATE),
    OCEnum::StaticAccessor("OC_ENUM_DISABLED", OCEnum::get_OC_ENUM_DISABLED, OCEnum::set_OC_ENUM_DISABLED),
    OCEnum::StaticAccessor("OC_ENUM_DOWN", OCEnum::get_OC_ENUM_DOWN, OCEnum::set_OC_ENUM_DOWN),
    OCEnum::StaticAccessor("OC_ENUM_DUAL", OCEnum::get_OC_ENUM_DUAL, OCEnum::set_OC_ENUM_DUAL),
    OCEnum::StaticAccessor("OC_ENUM_DRY", OCEnum::get_OC_ENUM_DRY, OCEnum::set_OC_ENUM_DRY),
    OCEnum::StaticAccessor("OC_ENUM_ENABLED", OCEnum::get_OC_ENUM_ENABLED, OCEnum::set_OC_ENUM_ENABLED),
    OCEnum::StaticAccessor("OC_ENUM_EXTENDED", OCEnum::get_OC_ENUM_EXTENDED, OCEnum::set_OC_ENUM_EXTENDED),
    OCEnum::StaticAccessor("OC_ENUM_FAN", OCEnum::get_OC_ENUM_FAN, OCEnum::set_OC_ENUM_FAN),
    OCEnum::StaticAccessor("OC_ENUM_FAST", OCEnum::get_OC_ENUM_FAST, OCEnum::set_OC_ENUM_FAST),
    OCEnum::StaticAccessor("OC_ENUM_FILTERMATERIAL", OCEnum::get_OC_ENUM_FILTERMATERIAL, OCEnum::set_OC_ENUM_FILTERMATERIAL),
    OCEnum::StaticAccessor("OC_ENUM_FOCUSED", OCEnum::get_OC_ENUM_FOCUSED, OCEnum::set_OC_ENUM_FOCUSED),
    OCEnum::StaticAccessor("OC_ENUM_GRINDING", OCEnum::get_OC_ENUM_GRINDING, OCEnum::set_OC_ENUM_GRINDING),
    OCEnum::StaticAccessor("OC_ENUM_HEATING", OCEnum::get_OC_ENUM_HEATING, OCEnum::set_OC_ENUM_HEATING),
    OCEnum::StaticAccessor("OC_ENUM_HEAVY", OCEnum::get_OC_ENUM_HEAVY, OCEnum::set_OC_ENUM_HEAVY),
    OCEnum::StaticAccessor("OC_ENUM_IDLE", OCEnum::get_OC_ENUM_IDLE, OCEnum::set_OC_ENUM_IDLE),
    OCEnum::StaticAccessor("OC_ENUM_INK", OCEnum::get_OC_ENUM_INK, OCEnum::set_OC_ENUM_INK),
    OCEnum::StaticAccessor("OC_ENUM_INKBLACK", OCEnum::get_OC_ENUM_INKBLACK, OCEnum::set_OC_ENUM_INKBLACK),
    OCEnum::StaticAccessor("OC_ENUM_INKCYAN", OCEnum::get_OC_ENUM_INKCYAN, OCEnum::set_OC_ENUM_INKCYAN),
    OCEnum::StaticAccessor("OC_ENUM_INKMAGENTA", OCEnum::get_OC_ENUM_INKMAGENTA, OCEnum::set_OC_ENUM_INKMAGENTA),
    OCEnum::StaticAccessor("OC_ENUM_INKTRICOLOUR", OCEnum::get_OC_ENUM_INKTRICOLOUR, OCEnum::set_OC_ENUM_INKTRICOLOUR),
    OCEnum::StaticAccessor("OC_ENUM_INKYELLOW", OCEnum::get_OC_ENUM_INKYELLOW, OCEnum::set_OC_ENUM_INKYELLOW),
    OCEnum::StaticAccessor("OC_ENUM_KEEPWARM", OCEnum::get_OC_ENUM_KEEPWARM, OCEnum::set_OC_ENUM_KEEPWARM),
    OCEnum::StaticAccessor("OC_ENUM_NORMAL", OCEnum::get_OC_ENUM_NORMAL, OCEnum::set_OC_ENUM_NORMAL),
    OCEnum::StaticAccessor("OC_ENUM_NOTSUPPORTED", OCEnum::get_OC_ENUM_NOTSUPPORTED, OCEnum::set_OC_ENUM_NOTSUPPORTED),
    OCEnum::StaticAccessor("OC_ENUM_PAUSE", OCEnum::get_OC_ENUM_PAUSE, OCEnum::set_OC_ENUM_PAUSE),
    OCEnum::StaticAccessor("OC_ENUM_PENDING", OCEnum::get_OC_ENUM_PENDING, OCEnum::set_OC_ENUM_PENDING),
    OCEnum::StaticAccessor("OC_ENUM_PENDINGHELD", OCEnum::get_OC_ENUM_PENDINGHELD, OCEnum::set_OC_ENUM_PENDINGHELD),
    OCEnum::StaticAccessor("OC_ENUM_PERMAPRESS", OCEnum::get_OC_ENUM_PERMAPRESS, OCEnum::set_OC_ENUM_PERMAPRESS),
    OCEnum::StaticAccessor("OC_ENUM_PREWASH", OCEnum::get_OC_ENUM_PREWASH, OCEnum::set_OC_ENUM_PREWASH),
    OCEnum::StaticAccessor("OC_ENUM_PROCESSING", OCEnum::get_OC_ENUM_PROCESSING, OCEnum::set_OC_ENUM_PROCESSING),
    OCEnum::StaticAccessor("OC_ENUM_PURE", OCEnum::get_OC_ENUM_PURE, OCEnum::set_OC_ENUM_PURE),
    OCEnum::StaticAccessor("OC_ENUM_QUICK", OCEnum::get_OC_ENUM_QUICK, OCEnum::set_OC_ENUM_QUICK),
    OCEnum::StaticAccessor("OC_ENUM_QUIET", OCEnum::get_OC_ENUM_QUIET, OCEnum::set_OC_ENUM_QUIET),
    OCEnum::StaticAccessor("OC_ENUM_RINSE", OCEnum::get_OC_ENUM_RINSE, OCEnum::set_OC_ENUM_RINSE),
    OCEnum::StaticAccessor("OC_ENUM_SECTORED", OCEnum::get_OC_ENUM_SECTORED, OCEnum::set_OC_ENUM_SECTORED),
    OCEnum::StaticAccessor("OC_ENUM_SILENT", OCEnum::get_OC_ENUM_SILENT, OCEnum::set_OC_ENUM_SILENT),
    OCEnum::StaticAccessor("OC_ENUM_SLEEP", OCEnum::get_OC_ENUM_SLEEP, OCEnum::set_OC_ENUM_SLEEP),
    OCEnum::StaticAccessor("OC_ENUM_SMART", OCEnum::get_OC_ENUM_SMART, OCEnum::set_OC_ENUM_SMART),
    OCEnum::StaticAccessor("OC_ENUM_SPOT", OCEnum::get_OC_ENUM_SPOT, OCEnum::set_OC_ENUM_SPOT),
    OCEnum::StaticAccessor("OC_ENUM_STEAM", OCEnum::get_OC_ENUM_STEAM, OCEnum::set_OC_ENUM_STEAM),
    OCEnum::StaticAccessor("OC_ENUM_STOPPED", OCEnum::get_OC_ENUM_STOPPED, OCEnum::set_OC_ENUM_STOPPED),
    OCEnum::StaticAccessor("OC_ENUM_SPIN", OCEnum::get_OC_ENUM_SPIN, OCEnum::set_OC_ENUM_SPIN),
    OCEnum::StaticAccessor("OC_ENUM_TESTING", OCEnum::get_OC_ENUM_TESTING, OCEnum::set_OC_ENUM_TESTING),
    OCEnum::StaticAccessor("OC_ENUM_TONER", OCEnum::get_OC_ENUM_TONER, OCEnum::set_OC_ENUM_TONER),
    OCEnum::StaticAccessor("OC_ENUM_TONERBLACK", OCEnum::get_OC_ENUM_TONERBLACK, OCEnum::set_OC_ENUM_TONERBLACK),
    OCEnum::StaticAccessor("OC_ENUM_TONERCYAN", OCEnum::get_OC_ENUM_TONERCYAN, OCEnum::set_OC_ENUM_TONERCYAN),
    OCEnum::StaticAccessor("OC_ENUM_TONERMAGENTA", OCEnum::get_OC_ENUM_TONERMAGENTA, OCEnum::set_OC_ENUM_TONERMAGENTA),
    OCEnum::StaticAccessor("OC_ENUM_TONERYELLOW", OCEnum::get_OC_ENUM_TONERYELLOW, OCEnum::set_OC_ENUM_TONERYELLOW),
    OCEnum::StaticAccessor("OC_ENUM_WARM", OCEnum::get_OC_ENUM_WARM, OCEnum::set_OC_ENUM_WARM),
    OCEnum::StaticAccessor("OC_ENUM_WASH", OCEnum::get_OC_ENUM_WASH, OCEnum::set_OC_ENUM_WASH),
    OCEnum::StaticAccessor("OC_ENUM_WET", OCEnum::get_OC_ENUM_WET, OCEnum::set_OC_ENUM_WET),
    OCEnum::StaticAccessor("OC_ENUM_WIND", OCEnum::get_OC_ENUM_WIND, OCEnum::set_OC_ENUM_WIND),
    OCEnum::StaticAccessor("OC_ENUM_WRINKLEPREVENT", OCEnum::get_OC_ENUM_WRINKLEPREVENT, OCEnum::set_OC_ENUM_WRINKLEPREVENT),
    OCEnum::StaticAccessor("OC_ENUM_ZIGZAG", OCEnum::get_OC_ENUM_ZIGZAG, OCEnum::set_OC_ENUM_ZIGZAG),

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

Napi::FunctionReference OCPositionDescription::constructor;

Napi::Function OCPositionDescription::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCPositionDescription", {
    OCPositionDescription::StaticAccessor("OC_POS_UNKNOWN", OCPositionDescription::get_OC_POS_UNKNOWN, OCPositionDescription::set_OC_POS_UNKNOWN),
    OCPositionDescription::StaticAccessor("OC_POS_TOP", OCPositionDescription::get_OC_POS_TOP, OCPositionDescription::set_OC_POS_TOP),
    OCPositionDescription::StaticAccessor("OC_POS_BOTTOM", OCPositionDescription::get_OC_POS_BOTTOM, OCPositionDescription::set_OC_POS_BOTTOM),
    OCPositionDescription::StaticAccessor("OC_POS_LEFT", OCPositionDescription::get_OC_POS_LEFT, OCPositionDescription::set_OC_POS_LEFT),
    OCPositionDescription::StaticAccessor("OC_POS_RIGHT", OCPositionDescription::get_OC_POS_RIGHT, OCPositionDescription::set_OC_POS_RIGHT),
    OCPositionDescription::StaticAccessor("OC_POS_CENTRE", OCPositionDescription::get_OC_POS_CENTRE, OCPositionDescription::set_OC_POS_CENTRE),
    OCPositionDescription::StaticAccessor("OC_POS_TOPLEFT", OCPositionDescription::get_OC_POS_TOPLEFT, OCPositionDescription::set_OC_POS_TOPLEFT),
    OCPositionDescription::StaticAccessor("OC_POS_BOTTOMLEFT", OCPositionDescription::get_OC_POS_BOTTOMLEFT, OCPositionDescription::set_OC_POS_BOTTOMLEFT),
    OCPositionDescription::StaticAccessor("OC_POS_CENTRELEFT", OCPositionDescription::get_OC_POS_CENTRELEFT, OCPositionDescription::set_OC_POS_CENTRELEFT),
    OCPositionDescription::StaticAccessor("OC_POS_CENTRERIGHT", OCPositionDescription::get_OC_POS_CENTRERIGHT, OCPositionDescription::set_OC_POS_CENTRERIGHT),
    OCPositionDescription::StaticAccessor("OC_POS_BOTTOMRIGHT", OCPositionDescription::get_OC_POS_BOTTOMRIGHT, OCPositionDescription::set_OC_POS_BOTTOMRIGHT),
    OCPositionDescription::StaticAccessor("OC_POS_TOPRIGHT", OCPositionDescription::get_OC_POS_TOPRIGHT, OCPositionDescription::set_OC_POS_TOPRIGHT),
    OCPositionDescription::StaticAccessor("OC_POS_TOPCENTRE", OCPositionDescription::get_OC_POS_TOPCENTRE, OCPositionDescription::set_OC_POS_TOPCENTRE),
    OCPositionDescription::StaticAccessor("OC_POS_BOTTOMCENTRE", OCPositionDescription::get_OC_POS_BOTTOMCENTRE, OCPositionDescription::set_OC_POS_BOTTOMCENTRE),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCPositionDescription::OCPositionDescription(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCPositionDescription::get_OC_POS_UNKNOWN(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_UNKNOWN);
}

void OCPositionDescription::set_OC_POS_UNKNOWN(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_TOP(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_TOP);
}

void OCPositionDescription::set_OC_POS_TOP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOM(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_BOTTOM);
}

void OCPositionDescription::set_OC_POS_BOTTOM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_LEFT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_LEFT);
}

void OCPositionDescription::set_OC_POS_LEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_RIGHT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_RIGHT);
}

void OCPositionDescription::set_OC_POS_RIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_CENTRE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_CENTRE);
}

void OCPositionDescription::set_OC_POS_CENTRE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_TOPLEFT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_TOPLEFT);
}

void OCPositionDescription::set_OC_POS_TOPLEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_BOTTOMLEFT);
}

void OCPositionDescription::set_OC_POS_BOTTOMLEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_CENTRELEFT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_CENTRELEFT);
}

void OCPositionDescription::set_OC_POS_CENTRELEFT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_CENTRERIGHT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_CENTRERIGHT);
}

void OCPositionDescription::set_OC_POS_CENTRERIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_BOTTOMRIGHT);
}

void OCPositionDescription::set_OC_POS_BOTTOMRIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_TOPRIGHT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_TOPRIGHT);
}

void OCPositionDescription::set_OC_POS_TOPRIGHT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_TOPCENTRE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_TOPCENTRE);
}

void OCPositionDescription::set_OC_POS_TOPCENTRE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCPositionDescription::get_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_POS_BOTTOMCENTRE);
}

void OCPositionDescription::set_OC_POS_BOTTOMCENTRE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}


Napi::FunctionReference OCInterfaceEvent::constructor;

Napi::Function OCInterfaceEvent::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCInterfaceEvent", {
    OCInterfaceEvent::StaticAccessor("NETWORK_INTERFACE_DOWN", OCInterfaceEvent::get_NETWORK_INTERFACE_DOWN, OCInterfaceEvent::set_NETWORK_INTERFACE_DOWN),
    OCInterfaceEvent::StaticAccessor("NETWORK_INTERFACE_UP", OCInterfaceEvent::get_NETWORK_INTERFACE_UP, OCInterfaceEvent::set_NETWORK_INTERFACE_UP),

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

Napi::FunctionReference OCSpTypesMask::constructor;

Napi::Function OCSpTypesMask::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSpTypesMask", {
    OCSpTypesMask::StaticAccessor("OC_SP_BASELINE", OCSpTypesMask::get_OC_SP_BASELINE, OCSpTypesMask::set_OC_SP_BASELINE),
    OCSpTypesMask::StaticAccessor("OC_SP_BLACK", OCSpTypesMask::get_OC_SP_BLACK, OCSpTypesMask::set_OC_SP_BLACK),
    OCSpTypesMask::StaticAccessor("OC_SP_BLUE", OCSpTypesMask::get_OC_SP_BLUE, OCSpTypesMask::set_OC_SP_BLUE),
    OCSpTypesMask::StaticAccessor("OC_SP_PURPLE", OCSpTypesMask::get_OC_SP_PURPLE, OCSpTypesMask::set_OC_SP_PURPLE),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSpTypesMask::OCSpTypesMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCSpTypesMask::get_OC_SP_BASELINE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SP_BASELINE);
}

void OCSpTypesMask::set_OC_SP_BASELINE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSpTypesMask::get_OC_SP_BLACK(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SP_BLACK);
}

void OCSpTypesMask::set_OC_SP_BLACK(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSpTypesMask::get_OC_SP_BLUE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SP_BLUE);
}

void OCSpTypesMask::set_OC_SP_BLUE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSpTypesMask::get_OC_SP_PURPLE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SP_PURPLE);
}

void OCSpTypesMask::set_OC_SP_PURPLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCRepValueType::constructor;

Napi::Function OCRepValueType::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCRepValueType", {
    OCRepValueType::StaticAccessor("OC_REP_NIL", OCRepValueType::get_OC_REP_NIL, OCRepValueType::set_OC_REP_NIL),
    OCRepValueType::StaticAccessor("OC_REP_INT", OCRepValueType::get_OC_REP_INT, OCRepValueType::set_OC_REP_INT),
    OCRepValueType::StaticAccessor("OC_REP_DOUBLE", OCRepValueType::get_OC_REP_DOUBLE, OCRepValueType::set_OC_REP_DOUBLE),
    OCRepValueType::StaticAccessor("OC_REP_BOOL", OCRepValueType::get_OC_REP_BOOL, OCRepValueType::set_OC_REP_BOOL),
    OCRepValueType::StaticAccessor("OC_REP_BYTE_STRING", OCRepValueType::get_OC_REP_BYTE_STRING, OCRepValueType::set_OC_REP_BYTE_STRING),
    OCRepValueType::StaticAccessor("OC_REP_STRING", OCRepValueType::get_OC_REP_STRING, OCRepValueType::set_OC_REP_STRING),
    OCRepValueType::StaticAccessor("OC_REP_OBJECT", OCRepValueType::get_OC_REP_OBJECT, OCRepValueType::set_OC_REP_OBJECT),
    OCRepValueType::StaticAccessor("OC_REP_ARRAY", OCRepValueType::get_OC_REP_ARRAY, OCRepValueType::set_OC_REP_ARRAY),
    OCRepValueType::StaticAccessor("OC_REP_INT_ARRAY", OCRepValueType::get_OC_REP_INT_ARRAY, OCRepValueType::set_OC_REP_INT_ARRAY),
    OCRepValueType::StaticAccessor("OC_REP_DOUBLE_ARRAY", OCRepValueType::get_OC_REP_DOUBLE_ARRAY, OCRepValueType::set_OC_REP_DOUBLE_ARRAY),
    OCRepValueType::StaticAccessor("OC_REP_BOOL_ARRAY", OCRepValueType::get_OC_REP_BOOL_ARRAY, OCRepValueType::set_OC_REP_BOOL_ARRAY),
    OCRepValueType::StaticAccessor("OC_REP_BYTE_STRING_ARRAY", OCRepValueType::get_OC_REP_BYTE_STRING_ARRAY, OCRepValueType::set_OC_REP_BYTE_STRING_ARRAY),
    OCRepValueType::StaticAccessor("OC_REP_STRING_ARRAY", OCRepValueType::get_OC_REP_STRING_ARRAY, OCRepValueType::set_OC_REP_STRING_ARRAY),
    OCRepValueType::StaticAccessor("OC_REP_OBJECT_ARRAY", OCRepValueType::get_OC_REP_OBJECT_ARRAY, OCRepValueType::set_OC_REP_OBJECT_ARRAY),

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

Napi::FunctionReference OCContentFormat::constructor;

Napi::Function OCContentFormat::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCContentFormat", {
    OCContentFormat::StaticAccessor("TEXT_PLAIN", OCContentFormat::get_TEXT_PLAIN, OCContentFormat::set_TEXT_PLAIN),
    OCContentFormat::StaticAccessor("TEXT_XML", OCContentFormat::get_TEXT_XML, OCContentFormat::set_TEXT_XML),
    OCContentFormat::StaticAccessor("TEXT_CSV", OCContentFormat::get_TEXT_CSV, OCContentFormat::set_TEXT_CSV),
    OCContentFormat::StaticAccessor("TEXT_HTML", OCContentFormat::get_TEXT_HTML, OCContentFormat::set_TEXT_HTML),
    OCContentFormat::StaticAccessor("IMAGE_GIF", OCContentFormat::get_IMAGE_GIF, OCContentFormat::set_IMAGE_GIF),
    OCContentFormat::StaticAccessor("IMAGE_JPEG", OCContentFormat::get_IMAGE_JPEG, OCContentFormat::set_IMAGE_JPEG),
    OCContentFormat::StaticAccessor("IMAGE_PNG", OCContentFormat::get_IMAGE_PNG, OCContentFormat::set_IMAGE_PNG),
    OCContentFormat::StaticAccessor("IMAGE_TIFF", OCContentFormat::get_IMAGE_TIFF, OCContentFormat::set_IMAGE_TIFF),
    OCContentFormat::StaticAccessor("AUDIO_RAW", OCContentFormat::get_AUDIO_RAW, OCContentFormat::set_AUDIO_RAW),
    OCContentFormat::StaticAccessor("VIDEO_RAW", OCContentFormat::get_VIDEO_RAW, OCContentFormat::set_VIDEO_RAW),
    OCContentFormat::StaticAccessor("APPLICATION_LINK_FORMAT", OCContentFormat::get_APPLICATION_LINK_FORMAT, OCContentFormat::set_APPLICATION_LINK_FORMAT),
    OCContentFormat::StaticAccessor("APPLICATION_XML", OCContentFormat::get_APPLICATION_XML, OCContentFormat::set_APPLICATION_XML),
    OCContentFormat::StaticAccessor("APPLICATION_OCTET_STREAM", OCContentFormat::get_APPLICATION_OCTET_STREAM, OCContentFormat::set_APPLICATION_OCTET_STREAM),
    OCContentFormat::StaticAccessor("APPLICATION_RDF_XML", OCContentFormat::get_APPLICATION_RDF_XML, OCContentFormat::set_APPLICATION_RDF_XML),
    OCContentFormat::StaticAccessor("APPLICATION_SOAP_XML", OCContentFormat::get_APPLICATION_SOAP_XML, OCContentFormat::set_APPLICATION_SOAP_XML),
    OCContentFormat::StaticAccessor("APPLICATION_ATOM_XML", OCContentFormat::get_APPLICATION_ATOM_XML, OCContentFormat::set_APPLICATION_ATOM_XML),
    OCContentFormat::StaticAccessor("APPLICATION_XMPP_XML", OCContentFormat::get_APPLICATION_XMPP_XML, OCContentFormat::set_APPLICATION_XMPP_XML),
    OCContentFormat::StaticAccessor("APPLICATION_EXI", OCContentFormat::get_APPLICATION_EXI, OCContentFormat::set_APPLICATION_EXI),
    OCContentFormat::StaticAccessor("APPLICATION_FASTINFOSET", OCContentFormat::get_APPLICATION_FASTINFOSET, OCContentFormat::set_APPLICATION_FASTINFOSET),
    OCContentFormat::StaticAccessor("APPLICATION_SOAP_FASTINFOSET", OCContentFormat::get_APPLICATION_SOAP_FASTINFOSET, OCContentFormat::set_APPLICATION_SOAP_FASTINFOSET),
    OCContentFormat::StaticAccessor("APPLICATION_JSON", OCContentFormat::get_APPLICATION_JSON, OCContentFormat::set_APPLICATION_JSON),
    OCContentFormat::StaticAccessor("APPLICATION_X_OBIX_BINARY", OCContentFormat::get_APPLICATION_X_OBIX_BINARY, OCContentFormat::set_APPLICATION_X_OBIX_BINARY),
    OCContentFormat::StaticAccessor("APPLICATION_CBOR", OCContentFormat::get_APPLICATION_CBOR, OCContentFormat::set_APPLICATION_CBOR),
    OCContentFormat::StaticAccessor("APPLICATION_VND_OCF_CBOR", OCContentFormat::get_APPLICATION_VND_OCF_CBOR, OCContentFormat::set_APPLICATION_VND_OCF_CBOR),

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

Napi::FunctionReference OCCoreResource::constructor;

Napi::Function OCCoreResource::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCCoreResource", {
    OCCoreResource::StaticAccessor("OCF_P", OCCoreResource::get_OCF_P, OCCoreResource::set_OCF_P),
    OCCoreResource::StaticAccessor("OCF_CON", OCCoreResource::get_OCF_CON, OCCoreResource::set_OCF_CON),
    OCCoreResource::StaticAccessor("OCF_INTROSPECTION_WK", OCCoreResource::get_OCF_INTROSPECTION_WK, OCCoreResource::set_OCF_INTROSPECTION_WK),
    OCCoreResource::StaticAccessor("OCF_INTROSPECTION_DATA", OCCoreResource::get_OCF_INTROSPECTION_DATA, OCCoreResource::set_OCF_INTROSPECTION_DATA),
    OCCoreResource::StaticAccessor("OCF_RES", OCCoreResource::get_OCF_RES, OCCoreResource::set_OCF_RES),
#if defined(OC_MNT)
    OCCoreResource::StaticAccessor("OCF_MNT", OCCoreResource::get_OCF_MNT, OCCoreResource::set_OCF_MNT),
#endif
#if defined(OC_CLOUD)
    OCCoreResource::StaticAccessor("OCF_COAPCLOUDCONF", OCCoreResource::get_OCF_COAPCLOUDCONF, OCCoreResource::set_OCF_COAPCLOUDCONF),
#endif
#if defined(OC_SOFTWARE_UPDATE)
    OCCoreResource::StaticAccessor("OCF_SW_UPDATE", OCCoreResource::get_OCF_SW_UPDATE, OCCoreResource::set_OCF_SW_UPDATE),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_DOXM", OCCoreResource::get_OCF_SEC_DOXM, OCCoreResource::set_OCF_SEC_DOXM),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_PSTAT", OCCoreResource::get_OCF_SEC_PSTAT, OCCoreResource::set_OCF_SEC_PSTAT),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_ACL", OCCoreResource::get_OCF_SEC_ACL, OCCoreResource::set_OCF_SEC_ACL),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_AEL", OCCoreResource::get_OCF_SEC_AEL, OCCoreResource::set_OCF_SEC_AEL),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_CRED", OCCoreResource::get_OCF_SEC_CRED, OCCoreResource::set_OCF_SEC_CRED),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_SDI", OCCoreResource::get_OCF_SEC_SDI, OCCoreResource::set_OCF_SEC_SDI),
#endif
#if defined(OC_SECURITY)
    OCCoreResource::StaticAccessor("OCF_SEC_SP", OCCoreResource::get_OCF_SEC_SP, OCCoreResource::set_OCF_SEC_SP),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    OCCoreResource::StaticAccessor("OCF_SEC_CSR", OCCoreResource::get_OCF_SEC_CSR, OCCoreResource::set_OCF_SEC_CSR),
#endif
#if defined(OC_SECURITY) && defined(OC_PKI)
    OCCoreResource::StaticAccessor("OCF_SEC_ROLES", OCCoreResource::get_OCF_SEC_ROLES, OCCoreResource::set_OCF_SEC_ROLES),
#endif
    OCCoreResource::StaticAccessor("OCF_D", OCCoreResource::get_OCF_D, OCCoreResource::set_OCF_D),

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

#if defined(OC_MNT)
Napi::Value OCCoreResource::get_OCF_MNT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_MNT);
}

void OCCoreResource::set_OCF_MNT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_CLOUD)
Napi::Value OCCoreResource::get_OCF_COAPCLOUDCONF(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_COAPCLOUDCONF);
}

void OCCoreResource::set_OCF_COAPCLOUDCONF(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SOFTWARE_UPDATE)
Napi::Value OCCoreResource::get_OCF_SW_UPDATE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SW_UPDATE);
}

void OCCoreResource::set_OCF_SW_UPDATE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_DOXM(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_DOXM);
}

void OCCoreResource::set_OCF_SEC_DOXM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_PSTAT(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_PSTAT);
}

void OCCoreResource::set_OCF_SEC_PSTAT(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_ACL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_ACL);
}

void OCCoreResource::set_OCF_SEC_ACL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_AEL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_AEL);
}

void OCCoreResource::set_OCF_SEC_AEL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_CRED(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_CRED);
}

void OCCoreResource::set_OCF_SEC_CRED(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_SDI(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_SDI);
}

void OCCoreResource::set_OCF_SEC_SDI(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY)
Napi::Value OCCoreResource::get_OCF_SEC_SP(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_SP);
}

void OCCoreResource::set_OCF_SEC_SP(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
Napi::Value OCCoreResource::get_OCF_SEC_CSR(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OCF_SEC_CSR);
}

void OCCoreResource::set_OCF_SEC_CSR(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}
#endif

#if defined(OC_SECURITY) && defined(OC_PKI)
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

Napi::FunctionReference OCEventCallbackResult::constructor;

Napi::Function OCEventCallbackResult::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCEventCallbackResult", {
    OCEventCallbackResult::StaticAccessor("OC_EVENT_DONE", OCEventCallbackResult::get_OC_EVENT_DONE, OCEventCallbackResult::set_OC_EVENT_DONE),
    OCEventCallbackResult::StaticAccessor("OC_EVENT_CONTINUE", OCEventCallbackResult::get_OC_EVENT_CONTINUE, OCEventCallbackResult::set_OC_EVENT_CONTINUE),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCEventCallbackResult::OCEventCallbackResult(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCEventCallbackResult::get_OC_EVENT_DONE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_EVENT_DONE);
}

void OCEventCallbackResult::set_OC_EVENT_DONE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCEventCallbackResult::get_OC_EVENT_CONTINUE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_EVENT_CONTINUE);
}

void OCEventCallbackResult::set_OC_EVENT_CONTINUE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCInterfaceMask::constructor;

Napi::Function OCInterfaceMask::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCInterfaceMask", {
    OCInterfaceMask::StaticAccessor("OC_IF_BASELINE", OCInterfaceMask::get_OC_IF_BASELINE, OCInterfaceMask::set_OC_IF_BASELINE),
    OCInterfaceMask::StaticAccessor("OC_IF_LL", OCInterfaceMask::get_OC_IF_LL, OCInterfaceMask::set_OC_IF_LL),
    OCInterfaceMask::StaticAccessor("OC_IF_B", OCInterfaceMask::get_OC_IF_B, OCInterfaceMask::set_OC_IF_B),
    OCInterfaceMask::StaticAccessor("OC_IF_R", OCInterfaceMask::get_OC_IF_R, OCInterfaceMask::set_OC_IF_R),
    OCInterfaceMask::StaticAccessor("OC_IF_RW", OCInterfaceMask::get_OC_IF_RW, OCInterfaceMask::set_OC_IF_RW),
    OCInterfaceMask::StaticAccessor("OC_IF_A", OCInterfaceMask::get_OC_IF_A, OCInterfaceMask::set_OC_IF_A),
    OCInterfaceMask::StaticAccessor("OC_IF_S", OCInterfaceMask::get_OC_IF_S, OCInterfaceMask::set_OC_IF_S),
    OCInterfaceMask::StaticAccessor("OC_IF_CREATE", OCInterfaceMask::get_OC_IF_CREATE, OCInterfaceMask::set_OC_IF_CREATE),

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

Napi::FunctionReference OCMethod::constructor;

Napi::Function OCMethod::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCMethod", {
    OCMethod::StaticAccessor("OC_GET", OCMethod::get_OC_GET, OCMethod::set_OC_GET),
    OCMethod::StaticAccessor("OC_POST", OCMethod::get_OC_POST, OCMethod::set_OC_POST),
    OCMethod::StaticAccessor("OC_PUT", OCMethod::get_OC_PUT, OCMethod::set_OC_PUT),
    OCMethod::StaticAccessor("OC_DELETE", OCMethod::get_OC_DELETE, OCMethod::set_OC_DELETE),

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

Napi::FunctionReference OCResourcePropertiesMask::constructor;

Napi::Function OCResourcePropertiesMask::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCResourcePropertiesMask", {
    OCResourcePropertiesMask::StaticAccessor("OC_DISCOVERABLE", OCResourcePropertiesMask::get_OC_DISCOVERABLE, OCResourcePropertiesMask::set_OC_DISCOVERABLE),
    OCResourcePropertiesMask::StaticAccessor("OC_OBSERVABLE", OCResourcePropertiesMask::get_OC_OBSERVABLE, OCResourcePropertiesMask::set_OC_OBSERVABLE),
    OCResourcePropertiesMask::StaticAccessor("OC_SECURE", OCResourcePropertiesMask::get_OC_SECURE, OCResourcePropertiesMask::set_OC_SECURE),
    OCResourcePropertiesMask::StaticAccessor("OC_PERIODIC", OCResourcePropertiesMask::get_OC_PERIODIC, OCResourcePropertiesMask::set_OC_PERIODIC),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCResourcePropertiesMask::OCResourcePropertiesMask(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCResourcePropertiesMask::get_OC_DISCOVERABLE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_DISCOVERABLE);
}

void OCResourcePropertiesMask::set_OC_DISCOVERABLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourcePropertiesMask::get_OC_OBSERVABLE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_OBSERVABLE);
}

void OCResourcePropertiesMask::set_OC_OBSERVABLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourcePropertiesMask::get_OC_SECURE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SECURE);
}

void OCResourcePropertiesMask::set_OC_SECURE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCResourcePropertiesMask::get_OC_PERIODIC(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_PERIODIC);
}

void OCResourcePropertiesMask::set_OC_PERIODIC(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::FunctionReference OCStatus::constructor;

Napi::Function OCStatus::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCStatus", {
    OCStatus::StaticAccessor("OC_STATUS_OK", OCStatus::get_OC_STATUS_OK, OCStatus::set_OC_STATUS_OK),
    OCStatus::StaticAccessor("OC_STATUS_CREATED", OCStatus::get_OC_STATUS_CREATED, OCStatus::set_OC_STATUS_CREATED),
    OCStatus::StaticAccessor("OC_STATUS_CHANGED", OCStatus::get_OC_STATUS_CHANGED, OCStatus::set_OC_STATUS_CHANGED),
    OCStatus::StaticAccessor("OC_STATUS_DELETED", OCStatus::get_OC_STATUS_DELETED, OCStatus::set_OC_STATUS_DELETED),
    OCStatus::StaticAccessor("OC_STATUS_NOT_MODIFIED", OCStatus::get_OC_STATUS_NOT_MODIFIED, OCStatus::set_OC_STATUS_NOT_MODIFIED),
    OCStatus::StaticAccessor("OC_STATUS_BAD_REQUEST", OCStatus::get_OC_STATUS_BAD_REQUEST, OCStatus::set_OC_STATUS_BAD_REQUEST),
    OCStatus::StaticAccessor("OC_STATUS_UNAUTHORIZED", OCStatus::get_OC_STATUS_UNAUTHORIZED, OCStatus::set_OC_STATUS_UNAUTHORIZED),
    OCStatus::StaticAccessor("OC_STATUS_BAD_OPTION", OCStatus::get_OC_STATUS_BAD_OPTION, OCStatus::set_OC_STATUS_BAD_OPTION),
    OCStatus::StaticAccessor("OC_STATUS_FORBIDDEN", OCStatus::get_OC_STATUS_FORBIDDEN, OCStatus::set_OC_STATUS_FORBIDDEN),
    OCStatus::StaticAccessor("OC_STATUS_NOT_FOUND", OCStatus::get_OC_STATUS_NOT_FOUND, OCStatus::set_OC_STATUS_NOT_FOUND),
    OCStatus::StaticAccessor("OC_STATUS_METHOD_NOT_ALLOWED", OCStatus::get_OC_STATUS_METHOD_NOT_ALLOWED, OCStatus::set_OC_STATUS_METHOD_NOT_ALLOWED),
    OCStatus::StaticAccessor("OC_STATUS_NOT_ACCEPTABLE", OCStatus::get_OC_STATUS_NOT_ACCEPTABLE, OCStatus::set_OC_STATUS_NOT_ACCEPTABLE),
    OCStatus::StaticAccessor("OC_STATUS_REQUEST_ENTITY_TOO_LARGE", OCStatus::get_OC_STATUS_REQUEST_ENTITY_TOO_LARGE, OCStatus::set_OC_STATUS_REQUEST_ENTITY_TOO_LARGE),
    OCStatus::StaticAccessor("OC_STATUS_UNSUPPORTED_MEDIA_TYPE", OCStatus::get_OC_STATUS_UNSUPPORTED_MEDIA_TYPE, OCStatus::set_OC_STATUS_UNSUPPORTED_MEDIA_TYPE),
    OCStatus::StaticAccessor("OC_STATUS_INTERNAL_SERVER_ERROR", OCStatus::get_OC_STATUS_INTERNAL_SERVER_ERROR, OCStatus::set_OC_STATUS_INTERNAL_SERVER_ERROR),
    OCStatus::StaticAccessor("OC_STATUS_NOT_IMPLEMENTED", OCStatus::get_OC_STATUS_NOT_IMPLEMENTED, OCStatus::set_OC_STATUS_NOT_IMPLEMENTED),
    OCStatus::StaticAccessor("OC_STATUS_BAD_GATEWAY", OCStatus::get_OC_STATUS_BAD_GATEWAY, OCStatus::set_OC_STATUS_BAD_GATEWAY),
    OCStatus::StaticAccessor("OC_STATUS_SERVICE_UNAVAILABLE", OCStatus::get_OC_STATUS_SERVICE_UNAVAILABLE, OCStatus::set_OC_STATUS_SERVICE_UNAVAILABLE),
    OCStatus::StaticAccessor("OC_STATUS_GATEWAY_TIMEOUT", OCStatus::get_OC_STATUS_GATEWAY_TIMEOUT, OCStatus::set_OC_STATUS_GATEWAY_TIMEOUT),
    OCStatus::StaticAccessor("OC_STATUS_PROXYING_NOT_SUPPORTED", OCStatus::get_OC_STATUS_PROXYING_NOT_SUPPORTED, OCStatus::set_OC_STATUS_PROXYING_NOT_SUPPORTED),
    OCStatus::StaticAccessor("__NUM_OC_STATUS_CODES__", OCStatus::get___NUM_OC_STATUS_CODES__, OCStatus::set___NUM_OC_STATUS_CODES__),
    OCStatus::StaticAccessor("OC_IGNORE", OCStatus::get_OC_IGNORE, OCStatus::set_OC_IGNORE),
    OCStatus::StaticAccessor("OC_PING_TIMEOUT", OCStatus::get_OC_PING_TIMEOUT, OCStatus::set_OC_PING_TIMEOUT),

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

Napi::FunctionReference OCSessionState::constructor;

Napi::Function OCSessionState::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSessionState", {
    OCSessionState::StaticAccessor("OC_SESSION_CONNECTED", OCSessionState::get_OC_SESSION_CONNECTED, OCSessionState::set_OC_SESSION_CONNECTED),
    OCSessionState::StaticAccessor("OC_SESSION_DISCONNECTED", OCSessionState::get_OC_SESSION_DISCONNECTED, OCSessionState::set_OC_SESSION_DISCONNECTED),

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

Napi::FunctionReference OCSoftwareUpdateResult::constructor;

Napi::Function OCSoftwareUpdateResult::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "OCSoftwareUpdateResult", {
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_IDLE", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_IDLE, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_IDLE),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_SUCCESS", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SUCCESS, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_SUCCESS),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_LESS_RAM", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_LESS_RAM),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_LESS_FLASH", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_LESS_FLASH),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_CONN_FAIL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_CONN_FAIL),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_SVV_FAIL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_SVV_FAIL),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_INVALID_URL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_INVALID_URL),
    OCSoftwareUpdateResult::StaticAccessor("OC_SWUPDATE_RESULT_UPGRADE_FAIL", OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL, OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_UPGRADE_FAIL),

  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
OCSoftwareUpdateResult::OCSoftwareUpdateResult(const Napi::CallbackInfo& info) : ObjectWrap(info)
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
Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_IDLE);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_IDLE(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_SUCCESS);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_SUCCESS(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_LESS_RAM);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_LESS_RAM(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_LESS_FLASH);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_LESS_FLASH(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_CONN_FAIL);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_CONN_FAIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_SVV_FAIL);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_SVV_FAIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_INVALID_URL);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_INVALID_URL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

Napi::Value OCSoftwareUpdateResult::get_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo& info)
{
  return Napi::Number::New(info.Env(), OC_SWUPDATE_RESULT_UPGRADE_FAIL);
}

void OCSoftwareUpdateResult::set_OC_SWUPDATE_RESULT_UPGRADE_FAIL(const Napi::CallbackInfo& info, const Napi::Value& value)
{

}

