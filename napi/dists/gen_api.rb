require 'rexml/document'
require 'rexml/formatters/pretty'
require 'pp'
require 'stringio'

require 'json'

struct_table = open(ARGV[0]) do |io|
  JSON.load(io)
end
enum_table = open(ARGV[1]) do |io|
  JSON.load(io)
end
func_table = open(ARGV[2]) do |io|
  JSON.load(io)
end

formatter = REXML::Formatters::Pretty.new

GETSETDECL = <<'GETSETDECL'
  Napi::Value get_VALNAME(const Napi::CallbackInfo&);
         void set_VALNAME(const Napi::CallbackInfo&, const Napi::Value&);
GETSETDECL

ENUMENTRYDECL = <<'ENUMENTRYDECL'
  static Napi::Value get_VALNAME(const Napi::CallbackInfo&);
  static        void set_VALNAME(const Napi::CallbackInfo&, const Napi::Value&);
ENUMENTRYDECL

CLSDECL = <<'CLSDECL'
class CLASSNAME : public Napi::ObjectWrap<CLASSNAME>
{
public:
  CLASSNAME(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator STRUCTNAME*() { return m_pvalue.get(); }
/* setget */
/* extra_value */
  std::shared_ptr<STRUCTNAME> m_pvalue;
};
CLSDECL

GETCLASSIMPL = <<'GETCLASSIMPL'
Napi::FunctionReference CLASSNAME::constructor;

Napi::Function CLASSNAME::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "CLASSNAME", {
/* accessor */
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
GETCLASSIMPL

ACCESSORIMPL = <<'ACCESSORIMPL'
    CLASSNAME::InstanceAccessor("VALNAME", &CLASSNAME::get_VALNAME, &CLASSNAME::set_VALNAME),
ACCESSORIMPL

ENUMACCESSORIMPL = <<'ENUMACCESSORIMPL'
    CLASSNAME::StaticAccessor("VALNAME", CLASSNAME::get_VALNAME, CLASSNAME::set_VALNAME),
ENUMACCESSORIMPL

GETCLSIMPL = <<'CLSIMPL'
Napi::Function CLASSNAME::GetClass(Napi::Env env) {
  auto func = DefineClass(env, "CLASSNAME", {
/* accessor */
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();

  return func;
}
CLSIMPL

CTORIMPL = <<'CTORIMPL'
CLASSNAME::CLASSNAME(const Napi::CallbackInfo& info) : ObjectWrap(info)
{
  if (info.Length() == 0) {
     m_pvalue = std::shared_ptr<STRUCTNAME>(new STRUCTNAME());
  }
  else if (info.Length() == 1 && info[0].IsExternal() ) {
     m_pvalue = *(info[0].As<Napi::External<std::shared_ptr<STRUCTNAME>>>().Data());
  }
  else {
        Napi::TypeError::New(info.Env(), "You need to name yourself")
          .ThrowAsJavaScriptException();
  }
}
CTORIMPL

SETGETIMPL = <<'SETTERIMPL'
Napi::Value CLASSNAME::get_VALNAME(const Napi::CallbackInfo& info)
{
#error getter
}

void CLASSNAME::set_VALNAME(const Napi::CallbackInfo& info, const Napi::Value& value)
{
#error setter
}
SETTERIMPL

GENERIC_GET = {           "bool"  => "  return Napi::Boolean::New(info.Env(), m_pvalue->VALNAME);",
                           "int"  => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                 "unsigned char"  => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                "unsigned short"  => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                       "uint8_t"  => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                       "uint16_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                       "uint32_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                       "uint64_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                        "int32_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                        "int64_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                         "double" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                "oc_clock_time_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
                         "size_t" => "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);",
}
GENERIC_SET = {           "bool"  => "  m_pvalue->VALNAME = value.As<Napi::Boolean>().Value();",
                           "int"  => "  m_pvalue->VALNAME = static_cast<int>(value.As<Napi::Number>());",
                 "unsigned char"  => "  m_pvalue->VALNAME = static_cast<unsigned char>(value.As<Napi::Number>().Uint32Value());",
                "unsigned short"  => "  m_pvalue->VALNAME = static_cast<unsigned short>(value.As<Napi::Number>().Uint32Value());",
                "uint8_t"  => "  m_pvalue->VALNAME = static_cast<uint8_t>(value.As<Napi::Number>().Uint32Value());",
                "uint16_t"  => "  m_pvalue->VALNAME = static_cast<uint16_t>(value.As<Napi::Number>().Uint32Value());",
                "uint32_t" => "  m_pvalue->VALNAME = static_cast<uint32_t>(value.As<Napi::Number>());",
                "uint64_t" => "  m_pvalue->VALNAME = static_cast<uint64_t>(value.As<Napi::Number>());",
                "int32_t" => "  m_pvalue->VALNAME = value.As<Napi::Number>().Int32Value();",
                "int64_t" => "  m_pvalue->VALNAME = value.As<Napi::Number>().Int64Value();",
                "double" => "  m_pvalue->VALNAME = value.As<Napi::Number>().DoubleValue();",
                "oc_clock_time_t" => "  m_pvalue->VALNAME = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());",
                "size_t" => "  m_pvalue->VALNAME = static_cast<uint32_t>(value.As<Napi::Number>().Uint32Value());",
}

STRUCT_SET = "  m_pvalue->VALNAME = *(*(value.As<Napi::External<std::shared_ptr<STRUCTNAME>>>().Data()));"

STRUCT_GET = "\
  std::shared_ptr<STRUCTNAME> sp(&m_pvalue->VALNAME);
  auto accessor = Napi::External<std::shared_ptr<STRUCTNAME>>::New(info.Env(), &sp);
  return WRAPNAME::constructor.New({accessor});"

ENUM_SET = "  m_pvalue->VALNAME = static_cast<STRUCTNAME>(value.As<Napi::Number>().Uint32Value());"
ENUM_GET = "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);"


STRUCTS = struct_table.keys

ENUMS = enum_table.keys

EXTRA_VALUE= {
  "oc_handler_t" => "\
  Napi::FunctionReference init;\n\
#if defined(OC_SERVER)\n\
  Napi::FunctionReference register_resources;\n\
#endif\n\
#if defined(OC_CLIENT)\n\
  Napi::FunctionReference requests_entry;\n\
#endif\
",
  "oc_swupdate_cb_t" => "\
  Napi::FunctionReference validate_purl;\n\
  Napi::FunctionReference check_new_version;\n\
  Napi::FunctionReference download_update;\n\
  Napi::FunctionReference perform_upgrade;\n\
",
}

SETGET_OVERRIDE = {
  "oc_separate_response_s::buffer" => {
    "set" => "\
m_pvalue->buffer =     value.As<Napi::Buffer<uint8_t>>().Data();",
    "get" =>
"return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, OC_MAX_APP_DATA_SIZE);"
  },
  "oc_response_buffer_s::buffer" => {
    "set" => "\
m_pvalue->buffer =     value.As<Napi::Buffer<uint8_t>>().Data();
m_pvalue->buffer_size = value.As<Napi::Buffer<uint8_t>>().Length();",
    "get" =>
"return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, m_pvalue->buffer_size);"
  },
  "oc_client_handler_t::discovery"=> {
    "set"=> "discovery_function = value;",
    "get"=> "return discovery_function;"
  },
  "oc_client_handler_t::discovery_all"=> {
    "set"=> "discovery_all_function = value;",
    "get"=> "return discovery_all_function;"
  },
  "oc_client_handler_t::response"=> {
    "set"=> "response_function = value;",
    "get"=> "return response_function;"
  },
  "oc_handler_t::init"=> {
    "set"=> "  init.Reset(value.As<Napi::Function>());\n",
    "get"=> "  return init.Value();"
  },
  "oc_handler_t::register_resources"=> {
    "set"=> "  register_resources.Reset(value.As<Napi::Function>());\n",
    "get"=> "  return register_resources.Value();"
  },
  "oc_handler_t::requests_entry"=> {
    "set"=> "  requests_entry.Reset(value.As<Napi::Function>());\n",
    "get"=> "  return requests_entry.Value();\n"
  },
  "oc_handler_t::signal_event_loop"=> {
    "set"=> "  signal_event_loop.Reset(value.As<Napi::Function>());\n",
    "get"=> "  return signal_event_loop.Value();\n"
  },
  "oc_swupdate_cb_t::check_new_version"=> {
    "set"=> "check_new_version_function = value;",
    "get"=> "return check_new_version_function ;"
  },
  "oc_swupdate_cb_t::validate_purl"=> {
    "set"=> "validate_purl_function = value;",
    "get"=> "return validate_purl_function;"
  },
  "oc_swupdate_cb_t::download_update"=> {
    "set"=> "download_update_function = value;",
    "get"=> "return download_update_function;"
  },
  "oc_swupdate_cb_t::perform_upgrade"=> {
    "set"=> "perform_upgrade_function = value;",
    "get"=> "return perform_upgrade_function;"
  },
  "oc_process::name"=> {
    "set"=>"  m_pvalue->VALNAME = value.As<Napi::String>().Utf8Value().c_str();",
    "get"=>"  return Napi::String::New(info.Env(), m_pvalue->VALNAME);"
  },
  "oc_blockwise_state_s::buffer"=> {
    "set"=> "for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->buffer[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
    "get"=> "return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->buffer, OC_MAX_APP_DATA_SIZE);"
  },
  "oc_message_s::data"=> {
    "set"=> "for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->data[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
    "get"=>"return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->data, OC_PDU_SIZE);"
  },
  "oc_request_t::_payload"=> {
    #"set"=> "for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->_payload[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
    "set" => "/* nop */",
    "get"=> "return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(m_pvalue->_payload), m_pvalue->_payload_len);"
  },
  "oc_client_response_t::_payload"=> {
    "set" => "\
m_pvalue->_payload =    value.As<Napi::Buffer<uint8_t>>().Data();
m_pvalue->_payload_len = value.As<Napi::Buffer<uint8_t>>().Length();",
    "get" =>
"return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(m_pvalue->_payload), m_pvalue->_payload_len);"
    #"set"=> "for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->_payload[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
    #"get"=> "return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->_payload, m_pvalue->_payload_len);"
  },
  "oc_uuid_t::id"=>
  {"set"=>
    "for(uint32_t i=0; i<16; i++) { m_pvalue->id[i] = info[0].As<Napi::Buffer<uint8_t>>().Data()[i]; }",
   "get"=>"return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->id, 16);"},
  "oc_blockwise_response_state_s::etag"=>
  {"set"=>
    "for(uint32_t i=0; i<COAP_ETAG_LEN; i++) { m_pvalue->VALNAME[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
   "get"=>"return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->etag, COAP_ETAG_LEN);"},
  "oc_blockwise_state_s::token"=>
  {"set"=>
    "for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) { m_pvalue->token[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
   "get"=>
    "return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);"},
  "oc_client_cb_t::token"=>
  {"set"=>
    "for(uint32_t i=0; i<COAP_TOKEN_LEN; i++) { m_pvalue->token[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
   "get"=>
    "return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->token, COAP_TOKEN_LEN);"},
  "oc_request_t::query"=>
  {#"set"=>
   # "for(uint32_t i=0; i<m_pvalue->query_len; i++) { m_pvalue->query[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
   "set"=> "/* nop */",
   "get"=>
    "return Napi::Buffer<char>::New(info.Env(), const_cast<char*>(m_pvalue->query), m_pvalue->query_len);"},
  "oc_memb::count"=>
  {"set"=>
    "for(uint32_t i=0; i<m_pvalue->num; i++) { m_pvalue->count[i] = value.As<Napi::Buffer<int8_t>>().Data()[i]; }",
   "get"=>"return Napi::Buffer<char>::New(info.Env(), m_pvalue->count, m_pvalue->num);"},
  "oc_le_addr_t::address"=>
  {"set"=>
    "m_pvalue->address[0] = value.As<Napi::Uint8Array>()[0];\n" +
    "m_pvalue->address[1] = value.As<Napi::Uint8Array>()[1];\n" +
    "m_pvalue->address[2] = value.As<Napi::Uint8Array>()[2];\n" +
    "m_pvalue->address[3] = value.As<Napi::Uint8Array>()[3];\n" +
    "m_pvalue->address[4] = value.As<Napi::Uint8Array>()[4];\n" +
    "m_pvalue->address[5] = value.As<Napi::Uint8Array>()[5];",
   "get"=>
    "auto array = Napi::Uint8Array::New(info.Env(), 6);\n" +
    "array[0] = m_pvalue->address[0];\n" +
    "array[1] = m_pvalue->address[1];\n" +
    "array[2] = m_pvalue->address[2];\n" +
    "array[3] = m_pvalue->address[3];\n" +
    "array[4] = m_pvalue->address[4];\n" +
    "array[5] = m_pvalue->address[5];\n" +
    "return array;"},
  "oc_ipv4_addr_t::address"=>
  {"set"=>
    "m_pvalue->address[0] = value.As<Napi::Uint8Array>()[0];\n" +
    "m_pvalue->address[1] = value.As<Napi::Uint8Array>()[1];\n" +
    "m_pvalue->address[2] = value.As<Napi::Uint8Array>()[2];\n" +
    "m_pvalue->address[3] = value.As<Napi::Uint8Array>()[3];",
   "get"=>
    "auto array = Napi::Uint8Array::New(info.Env(), 4);\n" +
    "array[0] = m_pvalue->address[0];\n" +
    "array[1] = m_pvalue->address[1];\n" +
    "array[2] = m_pvalue->address[2];\n" +
    "array[3] = m_pvalue->address[3];\n" +
    "return array;"},
  "oc_ipv6_addr_t::address"=>
  {"set"=>
    "m_pvalue->address[0] = value.As<Napi::Uint16Array>()[0];\n" +
    "m_pvalue->address[1] = value.As<Napi::Uint16Array>()[1];\n" +
    "m_pvalue->address[2] = value.As<Napi::Uint16Array>()[2];\n" +
    "m_pvalue->address[3] = value.As<Napi::Uint16Array>()[3];\n" +
    "m_pvalue->address[4] = value.As<Napi::Uint16Array>()[4];\n" +
    "m_pvalue->address[5] = value.As<Napi::Uint16Array>()[5];\n" +
    "m_pvalue->address[6] = value.As<Napi::Uint16Array>()[6];\n" +
    "m_pvalue->address[7] = value.As<Napi::Uint16Array>()[7];",
   "get"=>
    "auto array = Napi::Uint16Array::New(info.Env(), 8);\n" +
    "array[0] = m_pvalue->address[0];\n" +
    "array[1] = m_pvalue->address[1];\n" +
    "array[2] = m_pvalue->address[2];\n" +
    "array[3] = m_pvalue->address[3];\n" +
    "array[4] = m_pvalue->address[4];\n" +
    "array[5] = m_pvalue->address[5];\n" +
    "array[6] = m_pvalue->address[6];\n" +
    "array[7] = m_pvalue->address[7];\n" +
    "return array;"},
  "oc_collection_s::tag_pos_rel"=>
  {"set"=>
    "m_pvalue->tag_pos_rel[0] = value.As<Napi::Float64Array>()[0];\n" +
    "m_pvalue->tag_pos_rel[1] = value.As<Napi::Float64Array>()[1];\n" +
    "m_pvalue->tag_pos_rel[2] = value.As<Napi::Float64Array>()[2];",
   "get"=>
    "auto array = Napi::Float64Array::New(info.Env(), 3);\n" +
    "array[0] = m_pvalue->tag_pos_rel[0];\n" +
    "array[1] = m_pvalue->tag_pos_rel[1];\n" +
    "array[2] = m_pvalue->tag_pos_rel[2];\n" +
    "return array;"},
  "oc_resource_s::tag_pos_rel"=>
  {"set"=>
    "m_pvalue->tag_pos_rel[0] = value.As<Napi::Float64Array>()[0];\n" +
    "m_pvalue->tag_pos_rel[1] = value.As<Napi::Float64Array>()[1];\n" +
    "m_pvalue->tag_pos_rel[2] = value.As<Napi::Float64Array>()[2];",
   "get"=>
    "auto array = Napi::Float64Array::New(info.Env(), 3);\n" +
    "array[0] = m_pvalue->tag_pos_rel[0];\n" +
    "array[1] = m_pvalue->tag_pos_rel[1];\n" +
    "array[2] = m_pvalue->tag_pos_rel[2];\n" +
    "return array;"},
  "oc_cloud_context_t::user_data"=>
  {"set"=>
   "callback_data = value;",
   "get"=>
   "return callback_data;"},
  "oc_device_info_t::data"=>
  {"set"=>
   "add_device_cb_data = value;",
   "get"=>
   "return add_device_cb_data;"},
  "oc_event_callback_s::data"=>
  {"set"=>
   "callback_data = value;",
   "get"=>
   "return callback_data;"},
  "oc_request_handler_s::user_data"=>
  {"set"=>
   "cb_data = value;",
   "get"=>
   "return cb_data;"},
#  "oc_client_response_t::user_data"=>
#  {"set"=>
#   "client_cb_data = value;",
#   "get"=>
#   "return client_cb_data;"},
  "oc_platform_info_t::data"=>
  {"set"=>
   "init_platform_cb_data = value;",
   "get"=>
   "return init_platform_cb_data;"},
  "oc_sec_cred_t::chain"=>
  {"set"=> "  m_pvalue->chain = *(*(value.As<Napi::External<std::shared_ptr<oc_sec_cred_t*>>>().Data()));",
   "get"=> <<~STR
    //
      std::shared_ptr<oc_sec_cred_t*> sp(&m_pvalue->chain);
      auto accessor = Napi::External<std::shared_ptr<oc_sec_cred_t*>>::New(info.Env(), &sp);
      return OCCred::constructor.New({accessor});
   STR
  },
  "oc_sec_cred_t::child"=>
  {"set"=> "  m_pvalue->child = *(*(value.As<Napi::External<std::shared_ptr<oc_sec_cred_t*>>>().Data()));",
   "get"=> <<~STR
    //
      std::shared_ptr<oc_sec_cred_t*> sp(&m_pvalue->child);
      auto accessor = Napi::External<std::shared_ptr<oc_sec_cred_t*>>::New(info.Env(), &sp);
      return OCCred::constructor.New({accessor});
   STR
  }
}

FUNC_OVERRIDE = {
  'helper_rep_oc_array_to_int_array' => { 
    'invoke' => "\
      return Napi::Buffer<int64_t>::New(info.Env(), oc_int_array(*static_cast<oc_array_t*>(array)), oc_int_array_size(*(oc_array_t*)array));",
  },
  'helper_rep_oc_array_to_bool_array' => { 
    'invoke' => "\
      return Napi::Buffer<bool>::New(info.Env(), oc_bool_array(*static_cast<oc_array_t*>(array)), oc_bool_array_size(*(oc_array_t*)array));"
  },
  'helper_rep_oc_array_to_double_array' => { 
    'invoke' => "\
      return Napi::Buffer<double>::New(info.Env(), oc_double_array(*static_cast<oc_array_t*>(array)), oc_double_array_size(*(oc_array_t*)array));"
  },
  'helper_rep_oc_array_to_string_array' => { 
    'invoke' => "\
    size_t sz = oc_string_array_get_allocated_size(*(oc_array_t*)array);
    oc_string_array_t* strarray = reinterpret_cast<oc_string_array_t*>((oc_array_t*)array);
    auto buf = Napi::Array::New(info.Env(), sz);
    for(uint32_t i=0; i<sz; i++) {
      auto str = Napi::String::New(info.Env(), oc_string_array_get_item(*strarray, i));
      buf[i] = str;
    }
    return buf;"
  },
  'helper_rep_get_string' => { 
    'invoke' => "\
    return Napi::String::New(info.Env(), helper_rep_get_string(rep, key));"
  },
  'helper_rep_get_long_array' => { 
    'invoke' => "\
  size_t sz;
  const int64_t* data = helper_rep_get_long_array(rep, key, &sz);
  return Napi::Buffer<int64_t>::New(info.Env(), const_cast<int64_t*>(data), sz);"
  },
  'helper_rep_get_bool_array' => {
    'invoke' => "\
  size_t sz;
  const bool* data = helper_rep_get_bool_array(rep, key, &sz);
  return Napi::Buffer<bool>::New(info.Env(), const_cast<bool*>(data), sz);"
  },
  'helper_rep_get_double_array' => {
    'invoke' => "\
  size_t sz;
  const double* data = helper_rep_get_double_array(rep, key, &sz);
  return Napi::Buffer<double>::New(info.Env(), const_cast<double*>(data), sz);"
  },
  'helper_rep_get_byte_string_array' => {
    'invoke' => '//return xxx;'
  },
  'helper_rep_get_string_array' => {
    'invoke' => '//return xxx;'
  },
  'oc_rep_get_encoder_buf' => {
    'invoke' => 'return Napi::Buffer<uint8_t>::New(info.Env(), const_cast<uint8_t*>(oc_rep_get_encoder_buf()), oc_rep_get_encoded_payload_size() );'
  },
  'oc_resource_set_request_handler' => {
    '2' => "  oc_request_callback_t callback = oc_resource_set_request_handler_helper;\n",
    '3' => <<~STR
                   callback_helper_t* user_data = new_callback_helper_t(info, 2, 3);
                   if(!user_data) callback = nullptr;
              STR
  },
  'oc_resource_set_properties_cbs' => {
    '1' => "  oc_get_properties_cb_t get_properties = oc_resource_set_properties_cbs_get_helper;\n",
    '3' => "  oc_set_properties_cb_t set_properties = oc_resource_set_properties_cbs_set_helper;\n",
    '2' => <<~STR,
                 //
                   callback_helper_t* get_propr_user_data = new_callback_helper_t(info, 1, 2);
                   if(!get_propr_user_data) get_properties = nullptr;
              STR
    '4' => <<~STR,
                 //
                   callback_helper_t* set_props_user_data = new_callback_helper_t(info, 3, 4);
                   if(!set_props_user_data) set_properties = nullptr;
              STR
  },
  'oc_init_platform' => {
    '1' => "  oc_init_platform_cb_t init_platform_cb = oc_init_platform_helper;\n",
    '2' => <<~STR
                   callback_helper_t* data = new_callback_helper_t(info, 1, 2);
                   if(!data) init_platform_cb = nullptr;
              STR
  },
  'oc_add_device' => {
    '5' => "  oc_add_device_cb_t add_device_cb = oc_add_device_helper;\n",
    '6' => <<~STR
                   callback_helper_t* data = new_callback_helper_t(info, 5, 6);
                   if(!data) add_device_cb = nullptr;
              STR
  },
  'oc_main_init' => {
    'invoke' => <<~STR
//
  main_context = new main_context_t();

  handler.m_pvalue->signal_event_loop = [](){ main_context->helper_cv.notify_all(); };
  handler.m_pvalue->init = nullptr;
  handler.m_pvalue->register_resources = nullptr;
  handler.m_pvalue->requests_entry = nullptr;
  if(handler.init.Value().IsFunction() ) {
    main_context->oc_handler_init_ref.Reset(handler.init.Value());
    handler.m_pvalue->init = [](){
      Napi::Value ret = main_context->oc_handler_init_ref.Call({});
      if(ret.IsNumber()) return ret.As<Napi::Number>().Int32Value();
      return 0;
    };
  }
  else {
    Napi::TypeError::New(info.Env(), "init callback is not set.").ThrowAsJavaScriptException();
  }
  if(handler.register_resources.Value().IsFunction() ) {
    main_context->oc_handler_register_resources_ref.Reset(handler.register_resources.Value());
    handler.m_pvalue->register_resources = [](){ main_context->oc_handler_register_resources_ref.Call({}); };
  }
  if(handler.requests_entry.Value().IsFunction() ) {
    main_context->oc_handler_requests_entry_ref.Reset(handler.requests_entry.Value());
    handler.m_pvalue->requests_entry = [](){ main_context->oc_handler_requests_entry_ref.Call({}); };
  }

  try {
    main_context->helper_poll_event_thread = std::thread(helper_poll_event);
    main_context->helper_poll_event_thread.detach();
  }
  catch(system_error) {
    Napi::TypeError::New(info.Env(), "Fail to initialize poll_event thread.").ThrowAsJavaScriptException();
  }

  return Napi::Number::New(info.Env(), oc_main_init(handler));
STR
  },
  'oc_main_shutdown' => "\
  terminate_main_loop();\n\
  (void)oc_main_shutdown();\n\
  return info.Env().Undefined();\n" ,
  'oc_swupdate_set_impl' => {
    'invoke' => "\
  oc_swupdate_cb_validate_purl_ref.Reset(swupdate_impl.validate_purl.Value());\n\
  oc_swupdate_cb_check_new_version_ref.Reset(swupdate_impl.check_new_version.Value());\n\
  oc_swupdate_cb_download_update_ref.Reset(swupdate_impl.download_update.Value());\n\
  oc_swupdate_cb_perform_upgrade_ref.Reset(swupdate_impl.perform_upgrade.Value());\n\
  swupdate_impl.m_pvalue->validate_purl = oc_swupdate_cb_validate_purl_helper;\n\
  swupdate_impl.m_pvalue->check_new_version = oc_swupdate_cb_check_new_version_helper;\n\
  swupdate_impl.m_pvalue->download_update = oc_swupdate_cb_download_update_helper;\n\
  swupdate_impl.m_pvalue->perform_upgrade = oc_swupdate_cb_perform_upgrade_helper;\n\
  (void)oc_swupdate_set_impl(swupdate_impl);\n\
  return info.Env().Undefined();"
  },
}

WRAPPERNAME = { 'oc_ipv4_addr_t' => "OCIPv4Addr",
                'oc_ipv6_addr_t' => "OCIPv6Addr",
                'oc_le_addr_t' => "OCLEAddr",
                "oc_endpoint_t::dev_addr" => "DevAddr",
                'oc_sec_ace_t' => 'OCSecurityAce',
                'oc_sec_acl_s' => 'OCSecurityAcl',
                'oc_cps_t' => 'OCCloudPrivisoningStatus',
                'oc_pos_description_t' => 'OCPositionDescription',
                'oc_resource_properties_t' => 'OCResourcePropertiesMask',
                'oc_sp_types_t' => 'OCSpTypesMask',
                'oc_cloud_status_t' => 'OCCloudStatusMask',
                'oc_ace_permissions_t' => 'OCAcePermissionsMask',
                'oc_ace_res_t' => 'OCAceResource',
#                'oc_core_resource_t' => 'OCCoreRes',
                'oc_event_callback_retval_t' => 'OCEventCallbackResult',
                'oc_swupdate_cb_t' => 'OCSoftwareUpdateHandler',
                'oc_swupdate_result_t' => 'OCSoftwareUpdateResult',
                'ocf_version_t' => 'OCFVersion',
                'oc_client_cb_t' => 'OCClientCallback',
                'oc_sec_cred_t' => 'OCCred',
                'oc_sec_creds_t' => 'OCCreds',
                'oc_sec_credtype_t' => 'OCCredType',
                'oc_sec_credusage_t' => 'OCCredUsage',
                'oc_sec_encoding_t' => 'OCEncoding',
                'oc_rt_t' => 'OCResourceType',
                'transport_flags' => 'OCTransportFlags',
                'enum transport_flags' => 'OCTransportFlags',
                'oc_rep_s::oc_rep_value' => 'OCValue',
                'oc_rep_t*' => 'OCRepresentation',
                'oc_rep_s' => 'OCRepresentation',
                'oc_rep_s*' => 'OCRepresentation',
                'CborEncoder' => 'OCCborEncoder',
                'oc_array_t' => 'OCArray'
}

TYPEDEFS = {
  'oc_separate_response_t' => 'oc_separate_response_s',
  'oc_sec_acl_t' => 'oc_sec_acl_s',
  'oc_handle_t' => 'oc_mmem',
  'oc_string_t' => 'oc_mmem',
#  'oc_array_t' => 'oc_mmem',
  'oc_string_array_t' => 'oc_mmem',
  'oc_byte_string_array_t' => 'oc_mmem',
  'oc_blockwise_state_t' => 'oc_blockwise_state_s',
  'oc_response_buffer_t' => 'oc_response_buffer_s',
  'oc_resource_t' => 'oc_resource_s',
  'oc_request_handler_t' => 'oc_request_handler_s',
  'oc_response_handler_s' => 'oc_response_handler_t',
  'oc_message_t' => 'oc_message_s',
  'oc_link_t' => 'oc_link_s',
  'oc_rep_t' => 'oc_rep_s',
  'oc_collection_t' => 'oc_collection_s',
  'oc_cloud_cb_t' => 'void (*)(struct oc_cloud_context_t*, oc_cloud_status_t, void*)',
  'oc_core_add_device_cb_t' => 'void (*)(void*)',
  'oc_discovery_handler_t' => 'void (*)(const char*, const char*, oc_string_array_t, oc_interface_mask_t, oc_endpoint_t*, oc_resource_properties_t, void*)',
  'oc_discovery_all_handler_t' => 'oc_discovery_flags_t (*)(const char*, const char*, oc_string_array_t, oc_interface_mask_t, oc_endpoint_t*, oc_resource_properties_t, bool, void*)',
  'oc_response_handler_t' => 'void (*)(oc_client_response_t*)',
  'oc_request_callback_t' => 'void (*)(oc_request_t*, oc_interface_mask_t, void*)',
  'oc_trigger_t' => 'void (*)(void*)',
  'oc_core_init_platform_cb_t' => 'void (*)(void*)',
  'interface_event_handler_t' => 'void (*)(oc_interface_event_t event)',
  'oc_memb_buffers_avail_callback_t' => 'void (*)(int)',
  'session_event_handler_t' => 'void (*)(const oc_endpoint_t* endpoint, oc_session_state_t state)',
  }

IGNORE_TYPES = {
  "oc_handler_t" => [ /^signal_event_loop$/ ],
# nested type
  "oc_properties_cb_t" => [ /cb/, /get_props/, /set_props/, /user_data/ ],
  "oc_ace_subject_t" => [ /role/, /^authority$/ ],
  "oc_sec_cred_t" => [ /^role$/, /^authority$/, /ctx/, /^next$/],
# LIST
  "oc_separate_response_s" => [/.*OC_LIST_STRUCT.*/ ],
  "oc_collection_s" => [ /.*OC_LIST_STRUCT.*/, /^next$/],
  "oc_link_s" => [ /.*OC_LIST_STRUCT.*/, /^next$/, ],
  "oc_process" => [ /.*PT_THREAD.*/, /pt/, /^next$/ ],
  "oc_sec_ace_t" => [ /.*OC_LIST_STRUCT.*/, /^next$/],
  "oc_sec_acl_s" => [ /.*OC_LIST_STRUCT.*/ ],
  "oc_sec_creds_t" => [ /.*OC_LIST_STRUCT.*/ ],
  "oc_ace_res_t" => [/^next$/],
  "oc_cloud_context_t" => [/^next$/],
  "oc_endpoint_t" => [/^next$/],
  "oc_link_params_t" => [/^next$/],
  "oc_rt_t" => [/^next$/],
  "oc_etimer" => [/^next$/, ],
  "oc_event_callback_s" => [/^next$/],
  "oc_message_s" => [/^next$/],
  "oc_resource_s" => [/^next$/],
  "oc_role_t" => [/^next$/],
  "oc_blockwise_state_s" => [ /^next$/, ],
  "oc_network_interface_cb" => [/^next$/],
  "oc_session_event_cb" => [/^next$/],
  "oc_rep_s" => [/^next$/ ],

  "coap_transaction" => [/^next$/],
  "coap_observer" => [/^next$/, /^resource$/, /^token$/,],
  "coap_packet_t" => [/^alt_addr$/, /^buffer$/, /^etag$/, /^if_match$/, /^location_path$/, /^location_query$/, /^options$/, /^payload$/, /^proxy_scheme$/, /^proxy_uri$/, /^token$/, /^uri_host$/, /^uri_path$/, /^uri_query$/, ],
  "coap_separate" => [/^token$/, /^next$/],

# void pointer
  "oc_client_cb_t" => [ /user_data/, /^next$/],
  "oc_memb" => [/mem/, /buffers_avail_cb/],
  "oc_mmem" => [/ptr/, /^next$/],
# internal
  "oc_client_response_t" => [/^client_cb$/, /^user_data$/],

  "pool" => nil,
  "@3" => nil,
#  "oc_response_t" => [ /response_buffer/, ],
#  "oc_request_t" => [/^origin$/, /^request_payload$/, /^resource$/, /^response$/], 
#  "oc_blockwise_request_state_s" => nil,
#  "oc_blockwise_response_state_s" => nil,
#  "oc_blockwise_role_t" => nil,
#  "oc_blockwise_state_s" => nil,
#  "oc_etimer" => nil,
#  "oc_memb" => nil,
#  "oc_message_s" => nil,
#  "oc_timer" => nil,
}

IGNORE_FUNCS = [
  '_oc_memb_alloc',
  '_oc_memb_free',
  'PT_THREAD',
  'OC_PROCESS_NAME',

'oc_list_add',
'oc_list_chop',
'oc_list_copy',
'oc_list_head',
'oc_list_init',
'oc_list_insert',
'oc_list_item_next',
'oc_list_length',
'oc_list_pop',
'oc_list_push',
'oc_list_remove',
'oc_list_tail',
'_oc_copy_byte_string_to_array',
'_oc_byte_string_array_add_item',
'_oc_string_array_add_item',
'_oc_copy_string_to_array',

'coap_get_header_accept',
'coap_get_header_block1',
'coap_get_header_block2',
'coap_get_header_content_format',
'coap_get_header_etag',
'coap_get_header_if_match',
'coap_get_header_if_none_match',
'coap_get_header_location_path',
'coap_get_header_location_query',
'coap_get_header_max_age',
'coap_get_header_observe',
'coap_get_header_proxy_scheme',
'coap_get_header_proxy_uri',
'coap_get_header_size1',
'coap_get_header_size2',
'coap_get_header_uri_host',
'coap_get_header_uri_path',
'coap_get_header_uri_query',
'coap_get_mid',
'coap_get_payload',
'coap_get_post_variable',
'coap_get_query_variable',
'coap_init_connection',
'coap_send_message',
'coap_serialize_message',
'coap_set_header_accept',
'coap_set_header_block1',
'coap_set_header_block2',
'coap_set_header_content_format',
'coap_set_header_etag',
'coap_set_header_if_match',
'coap_set_header_if_none_match',
'coap_set_header_location_path',
'coap_set_header_location_query',
'coap_set_header_max_age',
'coap_set_header_observe',
'coap_set_header_proxy_scheme',
'coap_set_header_proxy_uri',
'coap_set_header_size1',
'coap_set_header_size2',
'coap_set_header_uri_host',
'coap_set_header_uri_path',
'coap_set_header_uri_query',
'coap_set_payload',
'coap_set_status_code',
'coap_set_token',
'coap_tcp_get_packet_size',
'coap_tcp_init_message',
'coap_tcp_parse_message',
'coap_udp_init_message',
'coap_udp_parse_message',
'coap_check_signal_message',
'coap_send_abort_message',
'coap_send_csm_message',
'coap_send_ping_message',
'coap_send_pong_message',
'coap_send_release_message',
'coap_signal_get_alt_addr',
'coap_signal_get_bad_csm',
'coap_signal_get_blockwise_transfer',
'coap_signal_get_custody',
'coap_signal_get_hold_off',
'coap_signal_get_max_msg_size',
'coap_signal_set_alt_addr',
'coap_signal_set_bad_csm',
'coap_signal_set_blockwise_transfer',
'coap_signal_set_custody',
'coap_signal_set_hold_off',
'coap_signal_set_max_msg_size',
'coap_init_engine',
'coap_receive',
'coap_free_all_observers',
'coap_get_observers',
'coap_notify_collection_baseline',
'coap_notify_collection_batch',
'coap_notify_collection_links_list',
'coap_notify_collection_observers',
'coap_notify_observers',
'coap_observe_handler',
'coap_remove_observer',
'coap_remove_observer_by_client',
'coap_remove_observer_by_mid',
'coap_remove_observer_by_resource',
'coap_remove_observer_by_token',
'coap_remove_observers_on_dos_change',
'coap_separate_accept',
'coap_separate_clear',
'coap_separate_resume',
'coap_check_transactions',
'coap_clear_transaction',
'coap_free_all_transactions',
'coap_free_transactions_by_endpoint',
'coap_get_transaction_by_mid',
'coap_new_transaction',
'coap_register_as_transaction_handler',
'coap_send_transaction',

]

IFDEF_TYPES = {
  'oc_handler_t' => { 'register_resources' => 'defined(OC_SERVER)',
                      'requests_entry' => 'defined(OC_CLIENT)', },
  'oc_sec_cred_t' => { 'chain' => 'defined(OC_PKI)',
                       'child' => 'defined(OC_PKI)',
                       'credusage' => 'defined(OC_PKI)',
                       'publicdata' => 'defined(OC_PKI)', },
  'oc_resource_s'  => { 'num_links' => 'defined(OC_COLLECTIONS)' },
  'oc_message_s'  => { 'read_offset' => 'defined(OC_TCP)',
                       'encrypted' => 'defined(OC_SECURITY)', },
  'oc_blockwise_state_s'  => { 'token_len' => 'defined(OC_CLIENT)',
                               'token' => 'defined(OC_CLIENT)',
                               'mid' => 'defined(OC_CLIENT)',
                               'client_cb' => 'defined(OC_CLEINT)',},
  'oc_blockwise_response_state_s'  => { 'observe_seq' => 'defined(OC_CLIENT)',},
  'oc_core_resource_t' => { 'OCF_MNT' => 'defined(OC_MNT)',
                            'OCF_COAPCLOUDCONF' => 'defined(OC_CLOUD)',
                            'OCF_SW_UPDATE' => 'defined(OC_SOFTWARE_UPDATE)',
                            'OCF_SEC_DOXM' => 'defined(OC_SECURITY)',
                            'OCF_SEC_PSTAT' => 'defined(OC_SECURITY)',
                            'OCF_SEC_ACL' => 'defined(OC_SECURITY)',
                            'OCF_SEC_AEL' => 'defined(OC_SECURITY)',
                            'OCF_SEC_CRED' => 'defined(OC_SECURITY)',
                            'OCF_SEC_SDI' => 'defined(OC_SECURITY)',
                            'OCF_SEC_SP' => 'defined(OC_SECURITY)',
                            'OCF_SEC_CSR' => 'defined(OC_SECURITY) && defined(OC_PKI)',
                            'OCF_SEC_ROLES' => 'defined(OC_SECURITY) && defined(OC_PKI)', },
  'tcp_csm_state_t' => 'defined(OC_TCP)',
}

IFDEF_FUNCS = {
  'oc_send_ping' => 'defined(OC_TCP)',
  'oc_collections_add_rt_factory' => 'defined(OC_COLLECTIONS_IF_CREATE)',
  'oc_collections_free_rt_factories' => 'defined(OC_COLLECTIONS_IF_CREATE)',
  'oc_tcp_get_csm_state' => 'defined(OC_TCP)',
  'oc_tcp_update_csm_state' => 'defined(OC_TCP)',
  'oc_ri_alloc_resource' => 'defined(OC_SERVER)',
  'oc_ri_add_resource' => 'defined(OC_SERVER)',
  'oc_ri_delete_resource' => 'defined(OC_SERVER)',
  'oc_swupdate_notify_upgrading' => 'defined(OC_SOFTWARE_UPDATE)',
  'oc_swupdate_notify_downloaded' => 'defined(OC_SOFTWARE_UPDATE)',
  'oc_swupdate_notify_done' => 'defined(OC_SOFTWARE_UPDATE)',
  'oc_swupdate_notify_new_version_available' => 'defined(OC_SOFTWARE_UPDATE)',
  'oc_swupdate_set_impl' => 'defined(OC_SOFTWARE_UPDATE)',
  'oc_mem_trace_add_pace' => 'defined(OC_MEMORY_TRACE)',
  'oc_mem_trace_shutdown' => 'defined(OC_MEMORY_TRACE)',
  'oc_mem_trace_init' => 'defined(OC_MEMORY_TRACE)',
  'oc_obt_ace_add_permission' => 'defined(OC_SECURITY)',
  'oc_obt_ace_new_resource' => 'defined(OC_SECURITY)',
  'oc_obt_ace_resource_set_href' => 'defined(OC_SECURITY)',
  'oc_obt_ace_resource_set_wc' => 'defined(OC_SECURITY)',
  'oc_obt_add_roleid' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_obt_delete_ace_by_aceid' => 'defined(OC_SECURITY)',
  'oc_obt_delete_cred_by_credid' => 'defined(OC_SECURITY)',
  'oc_obt_delete_own_cred_by_credid' => 'defined(OC_SECURITY)',
  'oc_obt_device_hard_reset' => 'defined(OC_SECURITY)',
  'oc_obt_discover_all_resources' => 'defined(OC_SECURITY)',
  'oc_obt_discover_owned_devices' => 'defined(OC_SECURITY)',
  'oc_obt_discover_owned_devices_realm_local_ipv6' => 'defined(OC_SECURITY)',
  'oc_obt_discover_owned_devices_site_local_ipv6' => 'defined(OC_SECURITY)',
  'oc_obt_discover_unowned_devices' => 'defined(OC_SECURITY)',
  'oc_obt_discover_unowned_devices_realm_local_ipv6' => 'defined(OC_SECURITY)',
  'oc_obt_discover_unowned_devices_site_local_ipv6' => 'defined(OC_SECURITY)',
  'oc_obt_free_ace' => 'defined(OC_SECURITY)',
  'oc_obt_free_acl' => 'defined(OC_SECURITY)',
  'oc_obt_free_creds' => 'defined(OC_SECURITY)',
  'oc_obt_free_roleid' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_obt_init' => 'defined(OC_SECURITY)',
  'oc_obt_new_ace_for_connection' => 'defined(OC_SECURITY)',
  'oc_obt_new_ace_for_role' => 'defined(OC_SECURITY)',
  'oc_obt_new_ace_for_subject' => 'defined(OC_SECURITY)',
  'oc_obt_perform_cert_otm' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_obt_perform_just_works_otm' => 'defined(OC_SECURITY)',
  'oc_obt_perform_random_pin_otm' => 'defined(OC_SECURITY)',
  'oc_obt_provision_ace' => 'defined(OC_SECURITY)',
  'oc_obt_provision_auth_wildcard_ace' => 'defined(OC_SECURITY)',
  'oc_obt_provision_identity_certificate' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_obt_provision_pairwise_credentials' => 'defined(OC_SECURITY)',
  'oc_obt_provision_role_certificate' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_obt_provision_role_wildcard_ace' => 'defined(OC_SECURITY)',
  'oc_obt_request_random_pin' => 'defined(OC_SECURITY)',
  'oc_obt_retrieve_acl' => 'defined(OC_SECURITY)',
  'oc_obt_retrieve_creds' => 'defined(OC_SECURITY)',
  'oc_obt_retrieve_own_creds' => 'defined(OC_SECURITY)',
  'oc_obt_set_sd_info' => 'defined(OC_SECURITY)',
  'oc_obt_shutdown' => 'defined(OC_SECURITY)',
  'oc_assert_all_roles' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_assert_role' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_auto_assert_roles' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_close_all_tls_sessions' => 'defined(OC_SECURITY)',
  'oc_close_all_tls_sessions_for_device' => 'defined(OC_SECURITY)',
  'oc_cred_credtype_string' => 'defined(OC_SECURITY)',
  'oc_cred_parse_credusage' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_cred_parse_encoding' => 'defined(OC_SECURITY)',
  'oc_cred_read_credusage' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_cred_read_encoding' => 'defined(OC_SECURITY)',
  'oc_get_all_roles' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_is_owned_device' => 'defined(OC_SECURITY)',
  'oc_pki_add_mfg_cert' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_pki_add_mfg_intermediate_cert' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_pki_add_mfg_trust_anchor' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_pki_add_trust_anchor' => 'defined(OC_SECURITY) && defined(OC_PKI)',
  'oc_pki_set_security_profile' => 'defined(OC_SECURITY)',
  'oc_remove_ownership_status_cb' => 'defined(OC_SECURITY)',
  'oc_reset' => 'defined(OC_SECURITY)',
  'oc_reset_device' => 'defined(OC_SECURITY)',
  'oc_resource_make_public' => 'defined(OC_SECURITY)',
  'oc_sec_pstat_set_current_mode' => 'defined(OC_SECURITY) && defined(OC_SOFTWARE_UPDATE)',
  'oc_set_random_pin_callback' => 'defined(OC_SECURITY)',
  'oc_add_ownership_status_cb' => 'defined(OC_SECURITY)',
  'oc_cloud_add_resource' => 'defined(OC_CLOUD)',
  'oc_cloud_delete_resource' => 'defined(OC_CLOUD)',
  'oc_cloud_deregister' => 'defined(OC_CLOUD)',
  'oc_cloud_discover_resources' => 'defined(OC_CLOUD)',
  'oc_cloud_get_context' => 'defined(OC_CLOUD)',
  'oc_cloud_get_token_expiry' => 'defined(OC_CLOUD)',
  'oc_cloud_login' => 'defined(OC_CLOUD)',
  'oc_cloud_logout' => 'defined(OC_CLOUD)',
  'oc_cloud_manager_start' => 'defined(OC_CLOUD)',
  'oc_cloud_manager_stop' => 'defined(OC_CLOUD)',
  'oc_cloud_provision_conf_resource' => 'defined(OC_CLOUD)',
  'oc_cloud_publish_resources' => 'defined(OC_CLOUD)',
  'oc_cloud_refresh_token' => 'defined(OC_CLOUD)',
  'oc_cloud_register' => 'defined(OC_CLOUD)',
  'oc_session_start_event' => 'defined(OC_TCP)',
  'oc_session_end_event' => 'defined(OC_TCP)',
  'oc_session_events_is_ongoing' => 'defined(OC_TCP)',
  'oc_session_events_set_event_delay' => 'defined(OC_TCP)',
  'oc_remove_ping_handler' => 'defined(OC_TCP)',
  'oc_connectivity_end_session' => 'defined(OC_TCP)',
  'oc_set_introspection_data' => 'defined(OC_IDD_API)',

  'coap_set_header_if_match'=>'0',
  'coap_set_header_proxy_scheme'=>'0',
  'coap_set_header_proxy_uri'=>'0',
  'coap_get_header_if_none_match'=>'0',
  'coap_set_header_location_path'=>'0',
  'coap_set_header_uri_host'=>'0',
  'coap_set_header_if_none_match'=>'0',

  'coap_get_observers'=>'defined(XXX)',
  'oc_blockwise_dispatch_block'=>'defined(XXX)',



}

PRIMITIVES_POINTER = [
  /^int[0-9]*_t(\*)?$/,
  /^uint[0-9]*_t(\*)?$/,
  /^const int[0-9]*_t(\*)?$/,
  /^const uint[0-9]*_t(\*)?$/,
]

PRIMITIVES = [
  /^int$/,
  /^int[0-9]*_t$/,
  /^uint[0-9]*_t$/,
  /^const int[0-9]*_t$/,
  /^const uint[0-9]*_t$/,
  /^size_t$/
]

FUNC_TYPEMAP = {
  "oc_clock_time_t" => "uint64_t"
}

def gen_classname(typename)
  if match_any?(typename, PRIMITIVES_POINTER)
    return typename
  end
  if WRAPPERNAME.keys.include?(typename)
    return WRAPPERNAME[typename]
  end

  return (typename.gsub(/_t$/,"").gsub(/_t:/,":").gsub(/_t\*$/,"*").gsub(/_s$/,"").gsub(/_s:/,":").gsub(/_([a-z])/){ $1.upcase}).gsub(/^oc/, "OC")
end

def gen_setget_decl(type, ftable)
  list = ftable.collect do |k, v|
    decl = GETSETDECL.gsub(/VALNAME/, k)

    v.gsub!(/^enum /,"") if v.start_with?("enum ")
    t = v
    t = TYPEDEFS[v] if TYPEDEFS[v] != nil

    if t =~ /\(\*\)/
      decl += "  Napi::Value #{k}_function; Napi::Value #{k}_data;\n\n" #TODO
    end

    if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(Hash) and IFDEF_TYPES[type].has_key?(k)
      decl = "#if #{IFDEF_TYPES[type][k]}\n" + decl + "#endif\n"
    end
    decl
  end
  list.join()
end

def gen_extra_value_decl(type, ftable)
    if EXTRA_VALUE[type] != nil
      "#{EXTRA_VALUE[type]}\n"
    else
      ""
    end
end


def gen_accessor(type, ftable)
  list = ftable.collect do |k, v|
    accr = ACCESSORIMPL.gsub(/VALNAME/, k)
    if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(Hash) and IFDEF_TYPES[type].has_key?(k)
      accr = "#if #{IFDEF_TYPES[type][k]}\n" + accr+ "#endif\n"
    end
    accr
  end
  list.join()
end

def gen_enumaccessor(type, ftable)
  list = ftable.collect do |k, v|
    accr = ENUMACCESSORIMPL.gsub(/VALNAME/, k)
    if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(Hash) and IFDEF_TYPES[type].has_key?(k)
      accr = "#if #{IFDEF_TYPES[type][k]}\n" + accr+ "#endif\n"
    end
    accr
  end
  list.join()
end

def match_any?(str, pats)
  pats.each do |pat|
    if str =~ pat
      return true
    end
  end
  return false
end

def format_ignore(key, h)
  if IGNORE_TYPES[key] != nil
    hh = {}
    h.each do |k,v|
      #p "IGNORE_TYPES #{key} #{k} #{v} #{IGNORE_TYPES[key]}"
      if match_any?(k, IGNORE_TYPES[key])
        #p "match #{k}"
        next
      end
      hh[k] = v
    end
    return hh
  else
    return h
  end
end

def gen_classdecl(key, h)
  return "" if IGNORE_TYPES.has_key?(key) and IGNORE_TYPES[key] == nil
  hh = format_ignore(key, h)

  decl = CLSDECL.gsub(/STRUCTNAME/, key).gsub(/CLASSNAME/, gen_classname(key)).gsub(/\/\* setget \*\//, gen_setget_decl(key, hh)).gsub(/\/\* extra_value \*\//, gen_extra_value_decl(key, hh))
  if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(String)
    decl = "#if #{IFDEF_TYPES[key]}\n" + decl + "#endif\n"
  end
  decl
end

def typedef_map(ty)
  if TYPEDEFS[ty] != nil
    TYPEDEFS[ty] 
  else
    ty
  end
end

def gen_getter_impl(key, k, v)
  if SETGET_OVERRIDE[key+ "::" +k] != nil
    SETGET_OVERRIDE[key + "::" +k]["get"]
  elsif GENERIC_GET[v] != nil
    GENERIC_GET[v]
  elsif STRUCTS.include?( typedef_map(v) )
    STRUCT_GET
  elsif STRUCTS.include?( typedef_map(v.gsub(/\*$/,"")) )
    STRUCT_GET
  elsif ENUMS.include?( typedef_map(v) )
    ENUM_GET 
  elsif v =~ /\(\*\)/
    "  return #{k}_function;"
  else
    "#error #{v} CLASSNAME::#{k} gen_getter_impl"
  end
end

def gen_setter_impl(key, k, v)
  if SETGET_OVERRIDE[key+ "::" +k] != nil
    SETGET_OVERRIDE[key + "::" +k]["set"]
  elsif GENERIC_SET[v] != nil
    GENERIC_SET[v]
  elsif STRUCTS.include?( typedef_map(v) )
    STRUCT_SET
  elsif STRUCTS.include?( typedef_map(v.gsub(/\*$/,""))  )
    STRUCT_SET
  elsif ENUMS.include?( typedef_map(v) )
    ENUM_SET 
  elsif v =~ /\(\*\)/
    "  #{k}_function = value;"
  else
    "#error #{v} CLASSNAME::#{k} gen_setter_impl"
  end
end

def gen_setget_impl(key, h)
  list = h.collect do |k, v|

    v.gsub!(/^enum /,"") if v.start_with?("enum ")
    t = v
    t = TYPEDEFS[v] if TYPEDEFS[v] != nil

    impl = SETGETIMPL.gsub(/^\#error getter/, gen_getter_impl(key, k, t)).gsub(/^#error setter/, gen_setter_impl(key, k, t)).gsub(/STRUCTNAME/, t).gsub(/CLASSNAME/, gen_classname(key)).gsub(/VALNAME/, k).gsub(/WRAPNAME/, gen_classname(t).gsub(/\*+$/, '') )


    if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(Hash) and IFDEF_TYPES[key].has_key?(k)
      impl = "#if #{IFDEF_TYPES[key][k]}\n" + impl + "#endif\n"
    end
    impl
  end
  list.join("\n")
end

def gen_enum_entry_impl(key, h)
  list = h.collect do |k, v|
    v.gsub!(/^enum /,"") if v.start_with?("enum ")
    t = v
    t = TYPEDEFS[v] if TYPEDEFS[v] != nil

    impl = SETGETIMPL.gsub(/^\#error getter/, "  return Napi::Number::New(info.Env(), #{k});").gsub(/^#error setter/, '').gsub(/STRUCTNAME/, t).gsub(/CLASSNAME/, gen_classname(key)).gsub(/VALNAME/, k)
    if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(Hash) and IFDEF_TYPES[key].has_key?(k)
      impl = "#if #{IFDEF_TYPES[key][k]}\n" + impl + "#endif\n"
    end
    impl
  end
  list.join("\n")
end

def gen_classimpl(type, h)
  return "" if IGNORE_TYPES.has_key?(type) and IGNORE_TYPES[type] == nil
  hh = format_ignore(type, h)

  impl = GETCLASSIMPL.gsub(/\/\* accessor \*\//, gen_accessor(type, hh)).gsub(/CLASSNAME/, gen_classname(type))
  impl += CTORIMPL.gsub(/STRUCTNAME/, type).gsub(/CLASSNAME/, gen_classname(type))
  impl += gen_setget_impl(type, hh)

  if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(String)
    impl = "#if #{IFDEF_TYPES[type]}\n" + impl + "#endif\n"
  end
  return impl
end

def gen_enumclassimpl(type, h)
  return "" if IGNORE_TYPES.has_key?(type) and IGNORE_TYPES[type] == nil
  hh = format_ignore(type, h)

  impl = GETCLASSIMPL.gsub(/\/\* accessor \*\//, gen_enumaccessor(type, hh)).gsub(/CLASSNAME/, gen_classname(type))
  impl += CTORIMPL.gsub(/STRUCTNAME/, type).gsub(/CLASSNAME/, gen_classname(type))
  impl += gen_enum_entry_impl(type, hh)

  if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(String)
    impl = "#if #{IFDEF_TYPES[type]}\n" + impl + "#endif\n"
  end
  return impl
end

def gen_enum_classdecl(key, h)
  return "" if IGNORE_TYPES.has_key?(key) and IGNORE_TYPES[key] == nil
  hh = format_ignore(key, h)

  decl = CLSDECL.gsub(/STRUCTNAME/, key).gsub(/ENUMNAME/, key).gsub(/CLASSNAME/, gen_classname(key)).gsub(/\/\* setget \*\//, gen_enum_entry_decl(hh)).gsub(/\/\* extra_value \*\//, gen_extra_value_decl(key, hh))
  if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(String)
    decl = "#if #{IFDEF_TYPES[key]}\n" + decl + "#endif\n"
  end
  decl
end

def gen_enum_entry_decl(hh)
  list = hh .collect do |k, v|
    ENUMENTRYDECL.gsub(/VALNAME/, k)
  end
  list.join()
end

def gen_funcdecl(name, param)
  "Napi::Value N_#{name}(const Napi::CallbackInfo&);"
end

def is_struct_ptr?(ty)
  if (ty =~ /\*\s*$/) != nil
    raw_ty = ty.gsub(/\*$/, "")
    raw_ty = raw_ty.gsub(/^struct /, "")
    raw_ty = raw_ty.gsub(/^const /, "")
    raw_ty = TYPEDEFS[raw_ty] if TYPEDEFS.keys.include?(raw_ty)
    if STRUCTS.include?(raw_ty)
      return true
    end
  end

  return false
end

def gen_funcimpl(name, param)
  type = param['type']
  type = FUNC_TYPEMAP[type] if FUNC_TYPEMAP.include?(type)

  check = true
  args = []
  decl = "Napi::Value N_#{name}(const Napi::CallbackInfo& info) {\n"
  
  if FUNC_OVERRIDE[name] and FUNC_OVERRIDE[name].is_a?(String)
    decl += FUNC_OVERRIDE[name]
    decl += "}\n"
    return decl
  end

  param['param'].each.with_index do |(n, ty), i|
    #p ty
    if FUNC_OVERRIDE[name] and FUNC_OVERRIDE[name][i.to_s]
      #p ty + " OVERRIDE"
      decl +=  FUNC_OVERRIDE[name][i.to_s]
      args.append(n)
    elsif ty == 'uint8_t' or ty == 'uint16_t' or ty == 'uint32_t' or ty == 'size_t'
      decl += "  #{ty} #{n} = static_cast<#{ty}>(info[#{i}].As<Napi::Number>().Uint32Value());\n"
      args.append(n)
    elsif ty == 'double'
      decl += "  #{ty} #{n} = info[#{i}].As<Napi::Number>().DoubleValue();\n"
      args.append(n)
    elsif ty == 'oc_clock_time_t'
      decl += "  #{ty} #{n} = static_cast<uint64_t>(info[#{i}].As<Napi::Number>().Int64Value());\n"
      args.append(n)
    elsif ty == 'void*'
      decl += "  #{ty} #{n} = info[#{i}];\n"
      args.append(n)
    elsif ty == 'const char*'
      decl += "  std::string #{n}_ = info[#{i}].As<Napi::String>().Utf8Value();\n  #{ty} #{n} = #{n}_.c_str();\n"
      args.append(n)
    elsif ty == 'char*'
      decl += "  #{ty} #{n} = const_cast<char*>(info[#{i}].As<Napi::String>().Utf8Value().c_str());\n"
      args.append(n)
    elsif ty == 'const char'
      decl += "  #{ty} #{n} = static_cast<uint8_t>(info[#{i}].As<Napi::Number>().Uint32Value());\n"
      args.append(n)
    elsif ty == 'const unsigned char*'
      decl += "  #{ty} #{n} = info[#{i}].As<Napi::Buffer<const uint8_t>>().Data();\n"
      args.append(n)
    elsif ty == 'const uint8_t*'
      decl += "  #{ty} #{n} = info[#{i}].As<Napi::Buffer<const uint8_t>>().Data();\n"
      args.append(n)
    elsif ty == 'uint8_t*'
      decl += "  #{ty} #{n} = info[#{i}].As<Napi::Buffer<uint8_t>>().Data();\n"
      args.append(n)
    elsif ty == 'size_t*'
      decl += "  #{ty} #{n} = reinterpret_cast<size_t*>(info[#{i}].As<Napi::Uint32Array>().Data());\n"
      args.append(n)
    elsif ty == 'bool'
      decl += "  #{ty} #{n} = info[#{i}].As<Napi::Boolean>().Value();\n"
      args.append(n)
    elsif ty == 'oc_response_handler_t' or
          ty == 'interface_event_handler_t' or
#          ty == 'oc_add_device_cb_t' or
          ty == 'oc_cloud_cb_t' or
          ty == 'oc_con_write_cb_t' or
          ty == 'oc_core_add_device_cb_t' or
          ty == 'oc_core_init_platform_cb_t' or
          ty == 'oc_discovery_all_handler_t' or
          ty == 'oc_discovery_handler_t' or
          ty == 'oc_factory_presets_cb_t' or
#          ty == 'oc_get_properties_cb_t' or
#          ty == 'oc_init_platform_cb_t' or
          ty == 'oc_memb_buffers_avail_callback_t' or
          ty == 'oc_obt_acl_cb_t' or
          ty == 'oc_obt_creds_cb_t' or
          ty == 'oc_obt_device_status_cb_t' or
          ty == 'oc_obt_discovery_cb_t' or
          ty == 'oc_obt_status_cb_t' or
          ty == 'oc_ownership_status_cb_t' or
          ty == 'oc_random_pin_cb_t' or
          ty == 'oc_request_callback_t' or
#          ty == 'oc_set_properties_cb_t' or
          ty == 'oc_trigger_t' or
          ty == 'session_event_handler_t'
      decl += "  #{ty} #{n} = nullptr;\n"
      decl += "  Napi::Function #{n}_ = info[#{i}].As<Napi::Function>();\n"
      args.append(n)
    elsif match_any?(ty, PRIMITIVES)
      #p ty + " PRIMITIVES"
      decl += "  #{ty} #{n} = static_cast<#{ty}>(info[#{i}].As<Napi::Number>());\n"
      args.append(n)
    elsif is_struct_ptr?(ty)
      #p ty + " struct_ptr"
      raw_ty = ty.gsub(/\*$/, "")
      raw_ty = raw_ty.gsub(/^struct /, "")
      raw_ty = raw_ty.gsub(/^const /, "")
      raw_ty = TYPEDEFS[raw_ty] if TYPEDEFS.keys.include?(raw_ty)
      decl += "  #{gen_classname(raw_ty)}& #{n} = *#{gen_classname(raw_ty)}::Unwrap(info[#{i}].As<Napi::Object>());\n"

      args.append(n)
    elsif ENUMS.include?(typedef_map(ty.gsub(/^enum /,'') ) )
      decl += "  #{ty} #{n} = static_cast<#{ty}>(info[#{i}].As<Napi::Number>().Uint32Value());\n"
      args.append(n)
    else
      decl += "// #{i} #{n}, #{ty}\n"
      check = false
    end
  end

  call_func = "0"
  call_func = name + "(" + args.join(", ") + ")" if check
  invoke = ''
  if type == 'void'
    invoke += "  (void)#{call_func};\n"
    invoke += "  return info.Env().Undefined();\n"
  elsif type == 'bool' or
        type == 'const bool'
    invoke += "  return Napi::Boolean::New(info.Env(), #{call_func});\n"
  elsif type == 'long' or
        type == 'double' or
        type == 'int64_t' or
        type == 'const int64_t' or
        type == 'unsigned int' or
        type == 'unsigned long' or
        type == 'CborError' or
        match_any?(type, PRIMITIVES)
    invoke += "  return Napi::Number::New(info.Env(), #{call_func});\n"
  elsif type == 'const char*'
    invoke += "  return Napi::String::New(info.Env(), #{call_func});\n"
  elsif type == 'void*'
    invoke += "  //func return void*\n"
  elsif type == 'const void*'
    invoke += "  //func return const void*\n"
  elsif type == 'const uint8_t*'
    invoke += "  //func return const uint8_t*\n"
  elsif type == 'const char*'
    invoke += "  //func return const char*\n"
  elsif type =~ /.*\*$/
    #p type
    type = type.gsub(/\*$/, "")
    invoke += "  std::shared_ptr<#{type}> sp(#{call_func});\n"
    invoke += "  auto args = Napi::External<std::shared_ptr<#{type}>>::New(info.Env(), &sp);\n"
    invoke += "  return #{gen_classname(type).gsub(/\*+$/,'')}::constructor.New({args});\n"
  elsif ENUMS.include?(type)
    invoke += "  return Napi::Number::New(info.Env(), #{call_func});\n"
  else
    invoke += "  //func return unknown #{type}\n"
  end

  if FUNC_OVERRIDE[name] and FUNC_OVERRIDE[name]['invoke']
    decl +=  FUNC_OVERRIDE[name]['invoke'] + "\n" #+ "  /*\n " + invoke + "  */\n"
  else
    decl += invoke
  end
  decl += "}\n"
end


File.open('src/structs.h', 'w') do |f|
  f.print "#pragma once\n"

  f.print "#include <napi.h>\n"
  f.print "#include <memory>\n"
  f.print "extern \"C\" {\n"
  f.print "#include <oc_api.h>\n"
  f.print "#include <oc_base64.h>\n"
  f.print "#include <oc_blockwise.h>\n"
  f.print "#include <oc_buffer.h>\n"
  f.print "#include <oc_buffer_settings.h>\n"
  f.print "#include <oc_client_state.h>\n"
  f.print "#include <oc_clock_util.h>\n"
  f.print "#include <oc_cloud.h>\n"
  f.print "#include <oc_collection.h>\n"
  f.print "#include <oc_core_res.h>\n"
  f.print "#include <oc_cred.h>\n"
  f.print "#include <oc_discovery.h>\n"
  f.print "#include <oc_endpoint.h>\n"
  f.print "#include <oc_enums.h>\n"
  f.print "#include <oc_helpers.h>\n"
  f.print "#include <oc_introspection.h>\n"
  f.print "#include <oc_network_events.h>\n"
  f.print "#include <oc_network_monitor.h>\n"
  f.print "#include <oc_obt.h>\n"
  f.print "#include <oc_pki.h>\n"
  f.print "#include <oc_rep.h>\n"
  f.print "#include <oc_ri.h>\n"
  f.print "#include <oc_session_events.h>\n"
  f.print "#include <oc_signal_event_loop.h>\n"
  f.print "#include <oc_swupdate.h>\n"
  f.print "#include <oc_uuid.h>\n"
#  f.print "#include <server_introspection.dat.h>\n"
  f.print "#include <oc_connectivity.h>\n"
  f.print "#include <oc_assert.h>\n"
  f.print "#include <oc_mem_trace.h>\n"
  f.print "#include <coap.h>\n"
  f.print "#include <coap_signal.h>\n"
  f.print "#include <constants.h>\n"
  f.print "#include <engine.h>\n"
  f.print "#include <observe.h>\n"
  f.print "#include <oc_coap.h>\n"
  f.print "#include <separate.h>\n"
  f.print "#include <transactions.h>\n"
  f.print "}\n"

  struct_table.each do |key, h|
    f.print gen_classdecl(key, h)
    f.print "\n"
  end

  enum_table.each do |key, h|
    f.print gen_enum_classdecl(key, h)
    f.print "\n"
  end
end

File.open('src/structs.cc', 'w') do |f|
  f.print "#include \"structs.h\"\n"
  f.print "#include \"helper.h\"\n"

  struct_table.each do |key, h|
    f.print gen_classimpl(key, h)
    f.print "\n"
  end


  enum_table.each do |key, h|
    f.print gen_enumclassimpl(key, h)
    f.print "\n"
  end
end

File.open('src/functions.h', 'w') do |f|
  f.print "#include \"helper.h\"\n"

  #func_table.each do |key, h|
  #  if not IFDEF_FUNCS.include?(key) #TODO
  #    f.print gen_funcdecl(key, h) + "\n"
  #  end
  #end 

  func_table.each do |key, h|
    next if IGNORE_FUNCS.include?(key)
    expset = gen_funcdecl(key, h) + "\n"
    if IFDEF_FUNCS.include?(key)
      expset = "#if #{IFDEF_FUNCS[key]}\n" + expset + "#endif\n"
    end
    f.print "#{expset}"
  end

end


File.open('src/functions.cc', 'w') do |f|
  f.print "#include \"functions.h\"\n"
  f.print "#include \"iotivity_lite.h\"\n"
  f.print "#include \"helper.h\"\n"

  #func_table.each do |key, h|
  #  if not IFDEF_FUNCS.include?(key)
  #    f.print gen_funcimpl(key, h) + "\n"
  #  end
  #end 
  func_table.each do |key, h|
    next if IGNORE_FUNCS.include?(key)
    expset = gen_funcimpl(key, h)
    if IFDEF_FUNCS.include?(key)
      expset = "#if #{IFDEF_FUNCS[key]}\n" + expset + "#endif\n"
    end
    f.print "#{expset}\n"
  end
end


File.open('src/binding.cc', 'w') do |f|
  f.print "#include \"structs.h\"\n"
  f.print "#include \"functions.h\"\n"

  f.print "Napi::Object module_init(Napi::Env env, Napi::Object exports) {\n"
  struct_table.each do |key, h|
    if not (IGNORE_TYPES.has_key?(key) and IGNORE_TYPES[key] == nil)
      impl = "  exports.Set(\"#{gen_classname(key)}\", #{gen_classname(key)}::GetClass(env));\n"
      if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(String)
        impl = "#ifdef #{IFDEF_TYPES[key]}\n" + impl + "#endif\n"
      end
      f.print "#{impl}"
    end
  end


  enum_table.each do |key, h|
    if not (IGNORE_TYPES.has_key?(key) and IGNORE_TYPES[key] == nil)
      impl = "  exports.Set(\"#{gen_classname(key)}\", #{gen_classname(key)}::GetClass(env));\n"
      if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(String)
        impl = "#if #{IFDEF_TYPES[key]}\n" + impl + "#endif\n"
      end
      f.print "#{impl}"
    end
  end


  func_table.each do |key, h|
    next if IGNORE_FUNCS.include?(key)
    expset = "  exports.Set(\"#{key}\", Napi::Function::New(env, N_#{key}));\n"
    if IFDEF_FUNCS.include?(key)
      expset = "#if #{IFDEF_FUNCS[key]}\n" + expset + "#endif\n"
    end
    f.print "#{expset}"
  end

  f.print "  return exports;\n"
  f.print "}\n"
end

File.open('lib/iotivity-lite.js', 'w') do |f|

  f.print <<STR
var path = '../build/Release/';
if (process.env.IOTIVITY_LITE_DEBUG == '1') { path = '../build/Debug/'; }
const addon = require(path + 'iotivity-lite-native');
module.exports = addon;
STR
=begin
  f.print "module.exports = [\n"
  struct_table.each do |key, h|
    if not (IGNORE_TYPES.has_key?(key) and IGNORE_TYPES[key] == nil)
      f.print "  addon.#{gen_classname(key)},\n"
    end
  end
  func_table.each do |key, h|
    if not IFDEF_FUNCS.include?(key)
      f.print "  addon.#{gen_classname(key)},\n"
    end
  end
  f.print "  addon.IotivityLite\n"
  f.print "];\n"
  f.print "\n"
=end
end
