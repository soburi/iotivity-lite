require 'rexml/document'
require 'rexml/formatters/pretty'
require 'pp'
require 'stringio'

require 'json'

class REXML::Element
  def inner_text
    REXML::XPath.match(self,'.//text()').join
  end
end

formatter = REXML::Formatters::Pretty.new

table = {}

ARGV.each do |file|
  xml = REXML::Document.new(File.new(file))

  REXML::XPath.each(xml, "/doxygen/compounddef/sectiondef") do |e|
    if e.attributes['kind'] and (e.attributes['kind'] == "func")
      #structname = e.elements['compoundname'].text
      #table[structname] = {}

      e.elements.each('memberdef') do |member|
        #print member
        funcname = member.elements['name'].text
        table[funcname] = {}
        table[funcname]['type'] = member.elements['type'].inner_text.gsub(/\ \*/, "*")
        table[funcname]['param'] = {}

        member.elements.each('param') do |param|
          if param.elements['declname'] != nil and param.elements['type'] != nil
            table[funcname]['param'][param.elements['declname'].text] = param.elements['type'].inner_text.gsub(/\ \*/, "*")
          end
          #name = param.elements['type'].text
          #table[func][name] = ""
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
