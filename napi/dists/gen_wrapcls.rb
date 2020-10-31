require 'rexml/document'
require 'rexml/formatters/pretty'
require 'pp'
require 'stringio'

require 'json'

apis = open(ARGV[0]) do |io|
  JSON.load(io)
end

CLSDECL = <<CLSDECL
class CLASS : public Napi::ObjectWrap<CLASS>
{
public:
  CLASS(const Napi::CallbackInfo&);
  static Napi::Function GetClass(Napi::Env);
CLSDECL
MTDDECL = <<MTDDECL
  static Napi::Value CLASS::METHOD(const Napi::CallbackInfo& info);
MTDDECL

MTDIMPL = <<MTDIMPL
Napi::Value CLASS::METHOD(const Napi::CallbackInfo& info) { return N_PREFIXMETHOD(info); };
MTDIMPL

BINDIMPL = <<BINDIMPL
CLASS::CLASS(const Napi::CallbackInfo& info) : ObjectWrap(info) { }

Napi::Function CLASS::GetClass(Napi::Env env) {
    return DefineClass(env, "CLASS", {
BINDIMPL

MTDBIND = <<MTDBIND
        CLASS::StaticMethod("METHOD", &CLASS::METHOD),
MTDBIND

CCPROLOGUE = <<CCPROLOGUE
#include "iotivity_lite.h"
#include "structs.h"
#include "functions.h"
using namespace Napi;

Napi::Object module_init(Napi::Env env, Napi::Object exports);
Napi::Object Init(Napi::Env env, Napi::Object exports);
NODE_API_MODULE(addon, Init)

Napi::Object Init(Napi::Env env, Napi::Object exports) {
CCPROLOGUE

HPROLOGUE = <<HPROLOGUE
#pragma once

#include <napi.h>
#include <oc_endpoint.h>
#include <oc_uuid.h>
#include <memory>

using namespace std;

HPROLOGUE

EXPORTIMPL = <<EXPORTIMPL
    exports.Set("CLASS", CLASS::GetClass(env));
EXPORTIMPL

if ARGV[1] == "-h"
  print HPROLOGUE
  apis.keys.each do |cls|
    print CLSDECL.gsub(/CLASS/, cls)
    apis[cls].keys.each do |mtd|
      print MTDDECL.gsub(/CLASS/, cls).gsub(/METHOD/, mtd)
    end
    print "};\n"
  end
elsif ARGV[1] == "-cc"
  print CCPROLOGUE
  apis.keys.each do |cls|
    print EXPORTIMPL.gsub(/CLASS/, cls)
  end
  print "    return module_init(env, exports);\n"
  print "}\n"

  apis.keys.each do |cls|
    print BINDIMPL.gsub(/CLASS/, cls)
    apis[cls].keys.each do |mtd|
      print MTDBIND.gsub(/CLASS/, cls).gsub(/METHOD/, mtd).gsub(/PREFIX/, apis[cls][mtd])
    end
    print "    });\n"
    print "}\n"

    print "\n"
    apis[cls].keys.each do |mtd|
      print MTDIMPL.gsub(/CLASS/, cls).gsub(/METHOD/, mtd).gsub(/PREFIX/, apis[cls][mtd])
    end
    print "\n"
    print "\n"
  end
end


