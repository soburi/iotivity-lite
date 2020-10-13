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

CLSDECL = <<'CLSDECL'
class CLASSNAME : public Napi::ObjectWrap<CLASSNAME>
{
public:
  CLASSNAME(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
  static Napi::FunctionReference constructor;
  operator STRUCTNAME*() { return m_pvalue.get(); }
private:
/* setget */
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
    CLASSNAME::InstanceAccessor("VALNAME", &CLASSNAME::get_VALNAME, &CLASSNAME::set_VALNAME),
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

SETGET_OVERRIDE = {
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
    "set"=> "init_function = value;",
    "get"=> "return init_function;"
  },
  "oc_handler_t::register_resources"=> {
    "set"=> "register_resources_function = value;",
    "get"=> "return register_resources_function ;"
  },
  "oc_handler_t::requests_entry"=> {
    "set"=> "requests_entry_function = value;",
    "get"=> "return requests_entry_function;"
  },
  "oc_handler_t::signal_event_loop"=> {
    "set"=> "signal_event_loop_function = value;",
    "get"=> "return signal_event_loop_function;"
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
    "set"=> "for(uint32_t i=0; i<value.As<Napi::Buffer<uint8_t>>().Length(); i++) { m_pvalue->_payload[i] = value.As<Napi::Buffer<uint8_t>>().Data()[i]; }",
    "get"=> "return Napi::Buffer<uint8_t>::New(info.Env(), m_pvalue->_payload, m_pvalue->_payload_len);"
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
   "return init_platform_cb_data;"}
}

FUNC_OVERRIDE = {
  'oc_init_platform' => {
    '1' => "  oc_init_platform_cb_t init_platform_cb = oc_init_platform_helper;\n",
    '2' => "  callback_helper_t* data = new callback_helper_t(info[1].As<Napi::Function>(), info[2].As<Napi::Value>());\n",
  }
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
                'oc_core_resource_t' => 'OCCoreRes',
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
}

TYPEDEFS = {
  'oc_separate_response_t' => 'oc_separate_response_s',
  'oc_sec_acl_t' => 'oc_sec_acl_s',
  'oc_handle_t' => 'oc_mmem',
  'oc_string_t' => 'oc_mmem',
  'oc_array_t' => 'oc_mmem',
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
#'interface_event_handler_t' => 'void (*)(oc_interface_event_t event)',
#'oc_memb_buffers_avail_callback_t' => 'void (*)(int)',
#'session_event_handler_t' => 'void (*)(const oc_endpoint_t* endpoint, oc_session_state_t state)',
  }

IGNORE_TYPES = {
# nested type
  "oc_response_t" => [ /response_buffer/, /separate_response/ ],
  "oc_properties_cb_t" => [ /cb/, /get_props/, /set_props/, /user_data/ ],
  "oc_ace_subject_t" => [ /role/, /^authority$/ ],
  "oc_sec_cred_t" => [ /^role$/, /^authority$/, /ctx/, /^next$/],
# LIST
  "oc_collection_s" => [ /.*OC_LIST_STRUCT.*/, /^next$/],
  "oc_link_s" => [ /.*OC_LIST_STRUCT.*/, /^next$/, /^resource$/],
  "oc_process" => [ /.*PT_THREAD.*/, /pt/, /^next$/ ],
  "oc_sec_ace_t" => [ /.*OC_LIST_STRUCT.*/, /^next$/],
  "oc_sec_acl_s" => [ /.*OC_LIST_STRUCT.*/ ],
  "oc_sec_creds_t" => [ /.*OC_LIST_STRUCT.*/ ],
  "oc_ace_res_t" => [/^next$/],
  "oc_cloud_context_t" => [/^next$/, /cloud_conf/, /cloud_ep/, /rd_delete_resources/, /rd_publish_resources/, /rd_published_resources/],
  "oc_endpoint_t" => [/^next$/],
  "oc_link_params_t" => [/^next$/],
  "oc_rt_t" => [/^next$/],
  "oc_etimer" => [/^next$/, /^p$/],
  "oc_event_callback_s" => [/^next$/],
  "oc_message_s" => [/^next$/, /^pool$/],
  "oc_resource_s" => [/^next$/],
  "oc_role_t" => [/^next$/],
# void pointer
  "oc_blockwise_state_s" => [ /^next$/ ],
  "oc_client_cb_t" => [ /endpoint/, /user_data/, /^next$/],
  "oc_memb" => [/mem/, /buffers_avail_cb/],
  "oc_mmem" => [/ptr/, /^next$/],
# internal
  "oc_network_interface_cb" => [ /handler/, /^next$/],
  "oc_session_event_cb" => [/handler/, /^next$/],
  "oc_rep_s" => [/value/, /^next$/ ],
  "oc_rep_s::oc_rep_value" => nil,
  "oc_client_response_t" => [/endpoint/, /payload/, /client_cb/, /user_data/],
  "oc_request_t" => [/^origin$/, /^request_payload$/, /^resource$/, /^response$/], 

  "pool" => nil,
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

]

IFDEF_TYPES = {
  "oc_sec_cred_t" => { "chain" => "OC_PKI",
                       "child" => "OC_PKI",
                       "credusage" => "OC_PKI",
                       "publicdata" => "OC_PKI", },
  "oc_resource_s"  => { "num_links" => "OC_COLLECTIONS" },
  "oc_message_s"  => { "read_offset" => "OC_TCP",
                       "encrypted" => "OC_SECURITY", },
  "oc_blockwise_state_s"  => { "token_len" => "OC_CLIENT",
                               "token" => "OC_CLIENT",
                               "mid" => "OC_CLIENT",
                               "client_cb" => "OC_CLEINT",},
  "oc_blockwise_response_state_s"  => { "observe_seq" => "OC_CLIENT",},
  "oc_core_resource_t" => { "OCF_MNT" => "OC_MNT",
                            "OCF_COAPCLOUDCONF" => "OC_CLOUD",
                            "OCF_SW_UPDATE" => "OC_SOFTWARE_UPDATE",
                            "OCF_SEC_DOXM" => "OC_SECURITY",
                            "OCF_SEC_PSTAT" => "OC_SECURITY",
                            "OCF_SEC_ACL" => "OC_SECURITY",
                            "OCF_SEC_AEL" => "OC_SECURITY",
                            "OCF_SEC_CRED" => "OC_SECURITY",
                            "OCF_SEC_SDI" => "OC_SECURITY",
                            "OCF_SEC_SP" => "OC_SECURITY",
                            "OCF_SEC_CSR" => "OC_PKI",
                            "OCF_SEC_ROLES" => "OC_PKI", },
  "tcp_csm_state_t" => "OC_TCP",
}

IFDEF_FUNCS = {
  "oc_send_ping" => "OC_TCP",
  "oc_collections_add_rt_factory" => "OC_COLLECTIONS_IF_CREATE",
  'oc_collections_free_rt_factories' => 'OC_COLLECTIONS_IF_CREATE',
  "oc_tcp_get_csm_state" => "OC_TCP",
  "oc_tcp_update_csm_state" => "OC_TCP",
  'oc_ri_alloc_resource' => 'OC_SERVER',
  'oc_ri_add_resource' => 'OC_SERVER',
  'oc_ri_delete_resource' => 'OC_SERVER',

"PT_THREAD" => "XXX",
"OC_PROCESS_NAME" => "XXX",

'oc_list_add' => "XXX",
'oc_list_chop' => "XXX",
'oc_list_copy' => "XXX",
'oc_list_head' => "XXX",
'oc_list_init' => "XXX",
'oc_list_insert' => "XXX",
'oc_list_item_next' => "XXX",
'oc_list_length' => "XXX",
'oc_list_pop' => "XXX",
'oc_list_push' => "XXX",
'oc_list_remove' => "XXX",
'oc_list_tail' => "XXX",


'oc_get_diagnostic_message'=>'XXX',
'oc_get_query_value'=>'XXX',
'oc_get_request_payload_raw'=>'XXX',
'oc_get_response_payload_raw'=>'XXX',
'oc_iterate_query'=>'XXX',
'oc_iterate_query_get_values'=>'XXX',
'oc_send_separate_response'=>'XXX',
'oc_set_separate_response_buffer'=>'XXX',
'oc_blockwise_dispatch_block'=>'XXX',
'oc_ri_alloc_client_cb'=>'XXX',
'oc_ri_invoke_client_cb'=>'XXX',
'oc_ri_process_discovery_payload'=>'XXX',
'oc_dns_lookup'=>'XXX',
'oc_core_encode_interfaces_mask'=>'XXX',
'oc_endpoint_list_copy'=>'XXX',
'oc_parse_rep'=>'XXX',
'oc_rep_get_bool'=>'XXX',
'oc_rep_get_bool_array'=>'XXX',
'oc_rep_get_byte_string'=>'XXX',
'oc_rep_get_double'=>'XXX',
'oc_rep_get_double_array'=>'XXX',
'oc_rep_get_int'=>'XXX',
'oc_rep_get_int_array'=>'XXX',
'oc_rep_get_object'=>'XXX',
'oc_rep_get_object_array'=>'XXX',
'oc_rep_get_string'=>'XXX',
'oc_rep_get_encoder_buf' => 'xxx',
'oc_rep_get_cbor_errno' => 'xxx',
'oc_ri_get_query_nth_key_value'=>'XXX',
'oc_ri_get_query_value'=>'XXX',
'oc_indicate_separate_response'=>'XXX',
'_oc_copy_byte_string_to_array'=>'xxx',
'_oc_byte_string_array_add_item'=>'xxx',
'_oc_string_array_add_item'=>'xxx',
'_oc_copy_string_to_array'=>'xxx',
'oc_random_value' => 'xxx',

'oc_swupdate_notify_upgrading' => 'OC_SOFTWARE_UPDATE',
'oc_swupdate_notify_downloaded' => 'OC_SOFTWARE_UPDATE',
'oc_swupdate_notify_done' => 'OC_SOFTWARE_UPDATE',
'oc_swupdate_notify_new_version_available' => 'OC_SOFTWARE_UPDATE',
'oc_swupdate_set_impl' => 'OC_SOFTWARE_UPDATE',
'oc_mem_trace_add_pace' => 'OC_MEMORY_TRACE',
'oc_mem_trace_shutdown' => 'OC_MEMORY_TRACE',
'oc_mem_trace_init' => 'OC_MEMORY_TRACE',

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
      decl += "  Napi::Value #{k}_function; Napi::Value #{k}_data;\n\n"
    end

    if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(Hash) and IFDEF_TYPES[type].has_key?(k)
      decl = "#ifdef #{IFDEF_TYPES[type][k]}\n" + decl + "#endif\n"
    end
    decl
  end
  list.join()
end

def gen_accessor(type, ftable)
  list = ftable.collect do |k, v|
    accr = ACCESSORIMPL.gsub(/VALNAME/, k)
    if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(Hash) and IFDEF_TYPES[type].has_key?(k)
      accr = "#ifdef #{IFDEF_TYPES[type][k]}\n" + accr+ "#endif\n"
    end
    accr
  end
  list.join()
end

def gen_enumaccessor(type, ftable)
  list = ftable.collect do |k, v|
    accr = ENUMACCESSORIMPL.gsub(/VALNAME/, k)
    if IFDEF_TYPES.has_key?(type) and IFDEF_TYPES[type].is_a?(Hash) and IFDEF_TYPES[type].has_key?(k)
      accr = "#ifdef #{IFDEF_TYPES[type][k]}\n" + accr+ "#endif\n"
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

  decl = CLSDECL.gsub(/STRUCTNAME/, key).gsub(/CLASSNAME/, gen_classname(key)).gsub(/\/\* setget \*\//, gen_setget_decl(key, hh))
  if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(String)
    decl = "#ifdef #{IFDEF_TYPES[key]}\n" + decl + "#endif\n"
  end
  decl
end

def gen_getter_impl(key, k, v)
  if SETGET_OVERRIDE[key+ "::" +k] != nil
    SETGET_OVERRIDE[key + "::" +k]["get"]
  elsif GENERIC_GET[v] != nil
    GENERIC_GET[v]
  elsif STRUCTS.include?(v)
    STRUCT_GET
  elsif ENUMS.include?(v)
    ENUM_GET 
  elsif v =~ /\(\*\)/
    "  return #{k}_function;"
  else
    "#error #{v} CLASSNAME::#{k}"
  end
end

def gen_setter_impl(key, k, v)
  if SETGET_OVERRIDE[key+ "::" +k] != nil
    SETGET_OVERRIDE[key + "::" +k]["set"]
  elsif GENERIC_SET[v] != nil
    GENERIC_SET[v]
  elsif STRUCTS.include?(v)
    STRUCT_SET
  elsif ENUMS.include?(v)
    ENUM_SET 
  elsif v =~ /\(\*\)/
    "  #{k}_function = value;"
  else
    "#error #{v} CLASSNAME::#{k}"
  end
end

def gen_setget_impl(key, h)
  list = h.collect do |k, v|

    v.gsub!(/^enum /,"") if v.start_with?("enum ")
    t = v
    t = TYPEDEFS[v] if TYPEDEFS[v] != nil

    impl = SETGETIMPL.gsub(/^\#error getter/, gen_getter_impl(key, k, t)).gsub(/^#error setter/, gen_setter_impl(key, k, t)).gsub(/STRUCTNAME/, t).gsub(/CLASSNAME/, gen_classname(key)).gsub(/VALNAME/, k).gsub(/WRAPNAME/, gen_classname(t))


    if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(Hash) and IFDEF_TYPES[key].has_key?(k)
      impl = "#ifdef #{IFDEF_TYPES[key][k]}\n" + impl + "#endif\n"
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
      impl = "#ifdef #{IFDEF_TYPES[key][k]}\n" + impl + "#endif\n"
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
    impl = "#ifdef #{IFDEF_TYPES[type]}\n" + impl + "#endif\n"
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
    impl = "#ifdef #{IFDEF_TYPES[type]}\n" + impl + "#endif\n"
  end
  return impl
end

def gen_enum_classdecl(key, h)
  return "" if IGNORE_TYPES.has_key?(key) and IGNORE_TYPES[key] == nil
  hh = format_ignore(key, h)

  decl = ENUMCLSDECL.gsub(/ENUMNAME/, key).gsub(/CLASSNAME/, gen_classname(key)).gsub(/\/\* setget \*\//, gen_enum_entry_decl(hh))
  if IFDEF_TYPES.has_key?(key) and IFDEF_TYPES[key].is_a?(String)
    decl = "#ifdef #{IFDEF_TYPES[key]}\n" + decl + "#endif\n"
  end
  decl
end

def gen_enum_entry_decl(hh)
  list = ftable.collect do |k, v|
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
    if FUNC_OVERRIDE[name] and FUNC_OVERRIDE[name][i.to_s]
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
      decl += "  #{ty} #{n} = info[#{i}].As<Napi::String>().Utf8Value().c_str();\n"
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
          ty == 'oc_add_device_cb_t' or
          ty == 'oc_cloud_cb_t' or
          ty == 'oc_con_write_cb_t' or
          ty == 'oc_core_add_device_cb_t' or
          ty == 'oc_core_init_platform_cb_t' or
          ty == 'oc_discovery_all_handler_t' or
          ty == 'oc_discovery_handler_t' or
          ty == 'oc_factory_presets_cb_t' or
          ty == 'oc_get_properties_cb_t' or
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
          ty == 'oc_set_properties_cb_t' or
          ty == 'oc_trigger_t' or
          ty == 'session_event_handler_t'
      decl += "  #{ty} #{n} = nullptr;\n"
      decl += "  Napi::Function #{n}_ = info[#{i}].As<Napi::Function>();\n"
      args.append(n)
    elsif match_any?(ty, PRIMITIVES)
      decl += "  #{ty} #{n} = static_cast<#{ty}>(info[#{i}].As<Napi::Number>());\n"
      args.append(n)
    elsif is_struct_ptr?(ty)
      raw_ty = ty.gsub(/\*$/, "")
      raw_ty = raw_ty.gsub(/^struct /, "")
      raw_ty = raw_ty.gsub(/^const /, "")
      raw_ty = TYPEDEFS[raw_ty] if TYPEDEFS.keys.include?(raw_ty)
      decl += "  #{gen_classname(raw_ty)}& #{n} = *#{gen_classname(raw_ty)}::Unwrap(info[#{i}].As<Napi::Object>());\n"

      args.append(n)
    elsif ENUMS.include?(ty)
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
  elsif type == 'bool'
    invoke += "  return Napi::Boolean::New(info.Env(), #{call_func});\n"
  elsif type == 'long'
    invoke += "  return Napi::Number::New(info.Env(), #{call_func});\n"
  elsif type == 'unsigned long'
    invoke += "  return Napi::Number::New(info.Env(), #{call_func});\n"
  elsif type == 'const char*'
  elsif type == 'void*'
  elsif type == 'const void*'
  elsif type == 'const uint8_t*'
  elsif type == 'const char*'
    invoke += "  return Napi::String::New(info.Env(), #{call_func});\n"
  elsif match_any?(type, PRIMITIVES)
    invoke += "  return Napi::Number::New(info.Env(), #{call_func});\n"
  elsif type =~ /.*\*$/
    type = type.gsub(/\*$/, "")
    invoke += "  std::shared_ptr<#{type}> sp(#{call_func});\n"
    invoke += "  auto args = Napi::External<std::shared_ptr<#{type}>>::New(info.Env(), &sp);\n"
    invoke += "  return #{gen_classname(type)}::constructor.New({args});\n"
  end

  if FUNC_OVERRIDE[name] and FUNC_OVERRIDE[name]['invoke']
    decl +=  FUNC_OVERRIDE[name]['invoke'] + "  /*\n " + invoke + "  */\n"
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
  f.print "}\n"

  struct_table.each do |key, h|
    f.print gen_classdecl(key, h)
    f.print "\n"
  end

  enum_table.each do |key, h|
    f.print gen_classdecl(key, h)
    f.print "\n"
  end
end

File.open('src/structs.cc', 'w') do |f|
  f.print "#include \"structs.h\"\n"

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

  func_table.each do |key, h|
    if not IFDEF_FUNCS.include?(key) #TODO
      f.print gen_funcdecl(key, h) + "\n"
    end
  end 
end


File.open('src/functions.cc', 'w') do |f|
  f.print "#include \"functions.h\"\n"

  func_table.each do |key, h|
    if not IFDEF_FUNCS.include?(key)
      f.print gen_funcimpl(key, h) + "\n"
    end
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
        impl = "#ifdef #{IFDEF_TYPES[key]}\n" + impl + "#endif\n"
      end
      f.print "#{impl}"
    end
  end


  func_table.each do |key, h|
    if not IFDEF_FUNCS.include?(key)
      f.print "  exports.Set(\"#{key}\", Napi::Function::New(env, N_#{key}));"
      f.print "\n"
    end
  end

  f.print "  return exports;\n"
  f.print "}\n"
end

File.open('lib/iotivity-lite.js', 'w') do |f|

  f.print "const addon = require('../build/Release/iotivity-lite-native');\n"
  f.print "module.exports = addon;\n"
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
