require 'rexml/document'
require 'rexml/formatters/pretty'
require 'pp'
require 'stringio'

require 'json'

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
  
private:
/* setget */
  std::shared_ptr<STRUCTNAME> m_pvalue;
};
CLSDECL

GETCLASSIMPL = <<'GETCLASSIMPL'
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
    CLASSNAME::InstanceAccessor("VALNAME", &CLASSNAME::get_VALNAME, nullptr),
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

GENERIC_GET = { "bool"  => "  return Napi::Boolean::New(info.Env(), m_pvalue->VALNAME);",
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
GENERIC_SET = { "bool"  => "  m_pvalue->VALNAME = value.As<Napi::Boolean>().Value();",
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
  return CLASSNAME::constructor.New({accessor});"

ENUM_SET = "  m_pvalue->VALNAME = static_cast<STRUCTNAME>(value.As<Napi::Number>().Uint32Value());"
ENUM_GET = "  return Napi::Number::New(info.Env(), m_pvalue->VALNAME);"

struct_table = open(ARGV[0]) do |io|
  JSON.load(io)
end
enum_table = open(ARGV[1]) do |io|
  JSON.load(io)
end

STRUCTS = struct_table.keys

ENUMS = enum_table.keys

MAPPER = {
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
    "array[2] = m_pvalue->tag_pos_rel[2];"},
  "oc_resource_s::tag_pos_rel"=>
  {"set"=>
    "m_pvalue->tag_pos_rel[0] = value.As<Napi::Float64Array>()[0];\n" +
    "m_pvalue->tag_pos_rel[1] = value.As<Napi::Float64Array>()[1];\n" +
    "m_pvalue->tag_pos_rel[2] = value.As<Napi::Float64Array>()[2];",
   "get"=>
    "auto array = Napi::Float64Array::New(info.Env(), 3);\n" +
    "array[0] = m_pvalue->tag_pos_rel[0];\n" +
    "array[1] = m_pvalue->tag_pos_rel[1];\n" +
    "array[2] = m_pvalue->tag_pos_rel[2];"},
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

WRAPPERNAME = { 'oc_ipv4_addr_t' => "OCIPv4Addr",
                'oc_ipv6_addr_t' => "OCIPv6Addr",
                'oc_le_addr_t' => "OCLEAddr",
                "oc_endpoint_t::dev_addr" => "DevAddr",
                "pool" => "OCPool",
}

TYPEDEFS = {
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

IGNORES = {
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
}

IFDEFS = {
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



def gen_classname(typename)
  if WRAPPERNAME.keys.include?(typename)
    return WRAPPERNAME[typename]
  end

  return (typename.gsub(/_t$/,"").gsub(/_t:/,":").gsub(/_s$/,"").gsub(/_s:/,":").gsub(/_([a-z])/){ $1.upcase}).gsub(/^oc/, "OC")
end

def gen_setget_decl(ftable)
  list = ftable.collect do |k, v|
    x = GETSETDECL.gsub(/VALNAME/, k)

    v.gsub!(/^enum /,"") if v.start_with?("enum ")
    t = v
    t = TYPEDEFS[v] if TYPEDEFS[v] != nil

    if t =~ /\(\*\)/
      x += "  Napi::Value #{k}_function; Napi::Value #{k}_data;\n\n"
    end

    x
  end
  list.join()
end

def gen_accessor(ftable)
  list = ftable.collect do |k, v|
    ACCESSORIMPL.gsub(/VALNAME/, k)
  end
  list.join()
end

def gen_enumaccessor(ftable)
  list = ftable.collect do |k, v|
    ENUMACCESSORIMPL.gsub(/VALNAME/, k)
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
  if IGNORES[key] != nil
    hh = {}
    h.each do |k,v|
      #p "IGNORES #{key} #{k} #{v} #{IGNORES[key]}"
      if match_any?(k, IGNORES[key])
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
  return "" if IGNORES.has_key?(key) and IGNORES[key] == nil
  hh = format_ignore(key, h)

  decl = CLSDECL.gsub(/STRUCTNAME/, key).gsub(/CLASSNAME/, gen_classname(key)).gsub(/\/\* setget \*\//, gen_setget_decl(hh))
  if IFDEFS.has_key?(key) and IFDEFS[key].is_a?(String)
    decl = "#ifdef #{IFDEFS[key]}\n" + decl + "#endif\n"
  end
  decl
end

def gen_getter_impl(key, k, v)
  if MAPPER[key+ "::" +k] != nil
    MAPPER[key + "::" +k]["get"]
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
  if MAPPER[key+ "::" +k] != nil
    MAPPER[key + "::" +k]["set"]
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

    impl = SETGETIMPL.gsub(/^\#error getter/, gen_getter_impl(key, k, t)).gsub(/^#error setter/, gen_setter_impl(key, k, t)).gsub(/STRUCTNAME/, t).gsub(/CLASSNAME/, gen_classname(key)).gsub(/VALNAME/, k)


    if IFDEFS.has_key?(key) and IFDEFS[key].is_a?(Hash) and IFDEFS[key].has_key?(k)
      impl = "#ifdef #{IFDEFS[key][k]}\n" + impl + "#endif\n"
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

    impl = SETGETIMPL.gsub(/^\#error getter/, "return Napi::Number::New(info.Env(), #{k});").gsub(/^#error setter/, '').gsub(/STRUCTNAME/, t).gsub(/CLASSNAME/, gen_classname(key)).gsub(/VALNAME/, k)
    if IFDEFS.has_key?(key) and IFDEFS[key].is_a?(Hash) and IFDEFS[key].has_key?(k)
      impl = "#ifdef #{IFDEFS[key][k]}\n" + impl + "#endif\n"
    end
    impl
  end
  list.join("\n")
end

def gen_classimpl(type, h)
  return "" if IGNORES.has_key?(type) and IGNORES[type] == nil
  hh = format_ignore(type, h)

  impl = GETCLASSIMPL.gsub(/\/\* accessor \*\//, gen_accessor(hh)).gsub(/CLASSNAME/, gen_classname(type))
  impl += CTORIMPL.gsub(/STRUCTNAME/, type).gsub(/CLASSNAME/, gen_classname(type))
  impl += gen_setget_impl(type, hh)

  if IFDEFS.has_key?(type) and IFDEFS[type].is_a?(String)
    impl = "#ifdef #{IFDEFS[type]}\n" + impl + "#endif\n"
  end
  return impl
end

def gen_enumclassimpl(type, h)
  return "" if IGNORES.has_key?(type) and IGNORES[type] == nil
  hh = format_ignore(type, h)

  impl = GETCLASSIMPL.gsub(/\/\* accessor \*\//, gen_enumaccessor(hh)).gsub(/CLASSNAME/, gen_classname(type))
  impl += CTORIMPL.gsub(/STRUCTNAME/, type).gsub(/CLASSNAME/, gen_classname(type))
  impl += gen_enum_entry_impl(type, hh)

  if IFDEFS.has_key?(type) and IFDEFS[type].is_a?(String)
    impl = "#ifdef #{IFDEFS[type]}\n" + impl + "#endif\n"
  end
  return impl
end

def gen_enum_classdecl(key, h)
  return "" if IGNORES.has_key?(key) and IGNORES[key] == nil
  hh = format_ignore(key, h)

  decl = ENUMCLSDECL.gsub(/ENUMNAME/, key).gsub(/CLASSNAME/, gen_classname(key)).gsub(/\/\* setget \*\//, gen_enum_entry_decl(hh))
  if IFDEFS.has_key?(key) and IFDEFS[key].is_a?(String)
    decl = "#ifdef #{IFDEFS[key]}\n" + decl + "#endif\n"
  end
  decl
end

def gen_enum_entry_decl(hh)
  list = ftable.collect do |k, v|
    ENUMENTRYDECL.gsub(/VALNAME/, k)
  end
  list.join()
end

File.open('src/structs.h', 'w') do |f|
  f.print "#pragma once\n"

  f.print "#include <napi.h>\n"
  f.print "#include <memory>\n"
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
  f.print "#include <server_introspection.dat.h>\n"
  f.print "#include <oc_connectivity.h>\n"

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
