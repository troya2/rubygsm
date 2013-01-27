#!/usr/bin/env ruby
# vim: noet

module Gsm
	class Incoming
		attr_reader :device, :sender, :time_sent, :received, :text
		
		#example usage: msg = Gsm::Incoming.new(self, from, sent, msg_text)
		
		def initialize(device, sender, time_sent, text)
			
			# move all arguments into read-only
			# attributes. ugly, but Struct only
			# supports read/write attrs
			@device = device
			@sender = sender
			@time_sent = time_sent
			@text = text
			
			# assume that the message was
			# received right now, since we
			# don't have an incoming buffer
			@received = Time.now
		end
		
		# Returns the sender of this message,
		# so incoming and outgoing messages
		# can be logged in the same way.
		def number
			sender
		end
	end
end
