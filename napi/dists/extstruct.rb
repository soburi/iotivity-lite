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

  REXML::XPath.each(xml, "/doxygen/compounddef") do |e|
    if e.attributes['kind'] and (e.attributes['kind'] == "struct" or e.attributes['kind'] == 'union')
      structname = e.elements['compoundname'].text
      #print structname 
      table[structname] = {}

      e.elements.each('sectiondef/memberdef') do |member|
        name = member.elements['name'].text

        type = member.elements['type'].inner_text.gsub(/^struct /, '').gsub(/^union /, '')

        #if type =~ /\([^\)]*$/
        if member.elements['argsstring'].text != nil
          if type != nil
            type += member.elements['argsstring'].text.gsub(/^\s*/, "")
          else
            p member
          end
        end

        if type == nil
          #print "unknown #{type}-#{name}\n"
          table[structname]["UNKNOWN_#{name}"] = "UNKNOWN"
          next
        end

        table[structname][name] = type


        type.gsub!(/\s*\*/, "* ")
        type.gsub!(/\s*$/, "")
        type.gsub!(/\s[A-z0-9_]*([\),])/, '\1')


        #print "#{type}-#{name}\n"

      end
    end
  end
  output = StringIO.new

end


puts JSON.pretty_generate(table)
