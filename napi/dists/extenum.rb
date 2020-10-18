require 'rexml/document'
require 'rexml/formatters/pretty'
require 'pp'
require 'stringio'

require 'json'

formatter = REXML::Formatters::Pretty.new

table = {}

ARGV.each do |file|
  xml = REXML::Document.new(File.new(file))

  REXML::XPath.each(xml, "/doxygen/compounddef/sectiondef") do |e|
    if e.attributes['kind'] and (e.attributes['kind'] == "enum")
      #print e
      #structname = e.elements['compoundname'].text
      #table[structname] = {}

      e.elements.each('memberdef') do |member|
        enumname = member.elements['name'].text
        table[enumname] = {}

        member.elements.each('enumvalue') do |ev|
          name = ev.elements['name'].text
          table[enumname][name] = ""
        end

        #type = member.elements['type'].text
        #if member.elements['type'].elements['ref'] != nil
        #  type = member.elements['type'].elements['ref'].text
        #end

        #if type =~ /\([^\)]*$/
        #  type += member.elements['argsstring'].text.gsub(/^\s*/, "")
        #end

        #if type == nil
          #print "unknown #{type}-#{name}\n"
        #  table[structname]["UNKNOWN_#{name}"] = "UNKNOWN"
        #  next
        #end



        #type.gsub!(/\s*\*/, "* ")
        #type.gsub!(/\s*$/, "")
        #type.gsub!(/\s[A-z0-9_]*([\),])/, '\1')


        #print "#{type}-#{name}\n"

      end
    end
  end
  output = StringIO.new

end


puts JSON.pretty_generate(table)
