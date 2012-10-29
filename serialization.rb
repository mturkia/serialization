#!/usr/bin/jruby

# Decode and re-encode JAVA Object Serialization
#
# Allows users to view and modify Java serialized data. Editing is done in XML
# format and available in different Burp tools (like Proxy and Intruder).
#
# (C) miika.turkia@nixu.com
# serialization.rb v1.3 2012-10-12
#
# Fulfilling the dependencies (Debian way):
#
# sudo apt-get install jruby
# sudo jruby -S gem install buby
# sudo jruby -S gem install rbkb
# sudo apt-get install libxstream-java
# mkdir lib
# ln -s /usr/share/java/xstream-1.3.1.jar lib/
# ln -s /opt/burp/burpsuite_pro_v1.5rc3.jar burp.jar
#
# Start in a directory with serialization.rb:
# $ jruby serialization.rb
#
# The directory named *lib* should contain the jar files of the fat client or
# server performing the serialized communication
#
# Thanks to Manish S. Saindane for publishing DSer, that tool inspired
# the work on the serialization.rb

include Java
require 'rubygems'
require 'irb'
require 'irb/completion'
require 'buby'
require 'rbkb'

Dir[File.join(File.dirname(__FILE__), 'lib', '*.jar')].each {|file| require file }
import com.thoughtworks.xstream.io.xml.DomDriver
import com.thoughtworks.xstream.XStream

# http://errtheblog.com/posts/9-drop-to-irb
# Drop to IRB shell for e.g. tuning the debug level or doing any
# modifications on-the-fly
module IRB
	def self.start_session(binding)
		unless $irb
		IRB.setup(nil)
		IRB.conf[:PROMPT][:SERIALIZE] = {
			:PROMPT_I => "[SER]>> ",
			:PROMPT_S => "[SER]%l>> ",
			:PROMPT_C => "[SER]*> ",
			:PROMPT_N =>"[SER]> ",
			:RETURN => "=> %s\n"
		}
		IRB.conf[:USE_READLINE] = true
		IRB.conf[:AUTO_INDENT] = true
		IRB.conf[:PROMPT_MODE] = :SERIALIZE
		end
		
		workspace = WorkSpace.new(binding)

		if @CONF[:SCRIPT]
		$irb = Irb.new(workspace, @CONF[:SCRIPT])
		else
		$irb = Irb.new(workspace)
		end

		@CONF[:IRB_RC].call($irb.context) if @CONF[:IRB_RC]
		@CONF[:MAIN_CONTEXT] = $irb.context
		
		trap("SIGINT") do
		$irb.signal_handle
		end

		catch(:IRB_EXIT) do
		$irb.eval_input
		end
	end
end

# 0	no debugging
# 1	minimal debugging, mainly URLs
# 2	more verbose output of contents
# 3	output full data, including hexdumping the serialized content

$debug = 0

# A module to de-code Java Serialized Objects and transform them to XML for
# working with them within Burp. The XML is afterwards re-serialized. Thus the
# XML must be valid and we must respect the XML tags in fuzzing the values.
# However, there is no reason not to change int values to double or what not...
module Serialize

	# Hook that is called from BurpSuite when new message (other
	# than Proxy message) is received
	def evt_http_message(tool_name, is_req, message_info)

		puts "*"*80 if ($debug > 1)
		puts "# evt_http_message" if ($debug > 1)
		if is_req
			puts "# OUT Request: #{message_info.url.toString}" if ($debug > 0)
			req = ::String.from_java_bytes(message_info.getRequest)
			req.replace enc_http(req)
			message_info.setRequest(req.to_java_bytes)
		else
			puts "# OUT Response: #{message_info.url.toString}" if ($debug > 0)
			rsp = ::String.from_java_bytes(message_info.getResponse)
			rsp.replace dec_http(rsp, is_req)
			message_info.setResponse(rsp.to_java_bytes)
		end

		puts tool_name if ($debug > 1)
		puts "evt_http_message done" if ($debug > 1)
		begin
			return super(tool_name, is_req, message_info).dup
		rescue => e
			if ($debug > 2)
				puts "ERROR"
				p e.message
				p e.backtrace
			end
		end
	end

	# Hook that is called from BurpSuite when a Proxy mesage is
	# received
	def evt_proxy_message(*param)
		puts "# evt_proxy_message" if ($debug > 1)
		msg_ref, is_req, rhost, rport, is_https, http_meth, url,
		resourceType, status, req_content_type, msg, action = param

		puts "#"*80 if ($debug > 1)
		if is_req
			puts "# IN Request: #{url}" if ($debug > 0)
			msg.replace dec_http(msg, is_req)
		else
			puts "action: #{action[0]}" if ($debug > 1)

			# Encode message after it has been to Proxy
			if (action[0] != 0)
				puts "# IN Response: #{url}" if ($debug > 1)
				msg.replace enc_http(msg)
			else
				action[0] = Buby::ACTION_FOLLOW_RULES_AND_REHOOK
			end
		end
		puts "#"*80 if ($debug > 1)

		puts "evt_proxy_message done" if ($debug > 1)
		begin
			return super(*param).dup
		rescue => e
			if ($debug > 2)
				puts "ERROR"
				p e.message
				p e.backtrace
			end
		end
	end

	# Function to re-serialize message body, takes the full HTTP
	# message with body in XML format as input and outputs the HTTP
	# headers and serialized body
	def enc_http(msg)
		(head, body) = msg.split(/\r\n\r\n/, 2)

		puts "#{head}" if ($debug > 1)

		if head =~ /^X-Burp: Decoded/
			puts "# PLAIN DATA (decoded):\n#{head}\n#{body}" if ($debug  > 2)
			puts "trying to re-encode\n" if ($debug > 1)
			bos = java.io.ByteArrayOutputStream.new()
			java.io.ObjectOutputStream.new(bos).writeObject(XStream.new(DomDriver.new()).from_xml(body))
			enc_body = ::String.from_java_bytes(bos.toByteArray())

			puts "re-encode done, dumping...\n#{enc_body.hexdump(:out => StringIO.new)}\n" if ($debug > 2)
			head.gsub!( /^X-Burp: Decoded\r\n(Content-Length:) (\d+)/, "\\1 #{enc_body.size}" )

			msg = "#{head}\r\n\r\n#{enc_body}"
			puts "# enc_http ENCODED DATA:\n" if ($debug > 2)
			puts "#{head}\n#{enc_body.hexdump(:out => StringIO.new)}\n" if ($debug > 2)
		else
			puts "# PLAIN DATA:\n#{head}\n#{body}" if ($debug > 2)
		end

		puts "enc_http done" if ($debug > 1)
		return msg
	end

	# Function to de-serialize message body, takes a full HTTP
	# message as input (serialized) and returns the HTTP headers and
	# body de-serialized into XML
	def dec_http(message, is_req)
		(head, body) = message.split(/\r\n\r\n/, 2)
		msg = message.to_java_bytes

		if (is_req && head =~ /^POST/) ||
			(is_req == false && (head =~ /Content-Type: application\/octet-stream/ ||
				head =~ /Content-Type: application\/x-java-serialized-object/))

			puts "matching POST or content type" if ($debug > 1)

			puts "# dec_http ENCODED DATA: \n" if ($debug > 2)
			puts "#{head}\n#{body.hexdump(:out => StringIO.new)}\n" if ($debug > 2)

			# Look for "magic" of serialized data. The
			# p_start variable will contain the starting
			# postion of the serialized data after this.
			p_start = msg.find_index(-84) if msg.find_index(-19) == (msg.find_index(-84) + 1)
			bis = java.io.ByteArrayInputStream.new(msg[p_start..-1], 0, msg[p_start..-1].size)
			obj = java.io.ObjectInputStream.new(bis).read_object
			
			dec_body = XStream.new(DomDriver.new()).to_xml(obj)
			head.gsub!( /(Content-Length:) (\d+)/,
				"X-Burp: Decoded\r\n\\1 #{dec_body.size}" )

			msg = "#{head}\r\n\r\n#{dec_body}"
			puts "# decd PLAIN DATA:\n#{head}\n#{dec_body}" if ($debug > 2)
		else
			puts "# pure PLAIN DATA:\n#{head}\n#{body}" if ($debug > 2)
		end

		puts "dec_http done" if ($debug > 1)
		return msg
	end
end

# Reload all jars from lib directory
class JarMenuItem
	def menu_item_clicked(*params)
		Dir[File.join(File.dirname(__FILE__), 'lib', '*.jar')].each {|file| require file }
	end
end

# Drop to IRB shell
class IRBMenuItem
	def menu_item_clicked(*params)
		IRB.start_session(binding)
	end
end

# Reaload serialization.rb
class SerMenuItem
	def menu_item_clicked(*params)
		load 'serialization.rb'
	end
end

if __FILE__ == $0
	initialized = 0

	# Initializing Burp
	$burp = Buby.new()
	$burp.extend(Serialize)
	$burp.start_burp()

	# Loop until we are able to register the menu items
	while initialized == 0
		begin
			$burp.registerMenuItem("Reload JARs", JarMenuItem.new);
			$burp.registerMenuItem("Drob to IRB", IRBMenuItem.new);
			$burp.registerMenuItem("Reload serialization.rb", SerMenuItem.new);
			initialized = 1
		rescue
			puts "Registering menu item failed - retrying" if ($debug > 0)
			sleep(1)
		end
	end

end
