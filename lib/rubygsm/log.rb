#!/usr/bin/env ruby
# vim: noet

module Gsm
class Modem
	private
	
	# Symbols accepted by the Gsm::Modem.new _verbosity_
	# argument. Each level includes all of the levels
	# below it (ie. :debug includes all :warn messages)
	LOG_LEVELS = {
		:file    => 5,
		:traffic => 4,
		:debug   => 3,
		:warn    => 2,
		:error   => 1 }
	
	def log_init filename = nil, log_file_verbosity = :debug
		@log_file_verbosity = log_file_verbosity
		
		if @port
			
		# build a log filename based on the device's
		# path (ttyS0, ttyUSB1, etc) and date/time
		fn_port = File.basename(@port)
		filename = filename || "rubygsm.#{fn_port}.log"
		
		# if the port path is unknown, log to
		# the same file each time. TODO: we
		# really need a proper logging solution
		else
			filename = filename || "rubygsm.log"
		end
		
		# (re-) open the log file
		@log = File.new filename, "w+"
		
		# dump some useful information
		# at the top, for debugging
		log "RUBYGSM"
		log "  port: #{@port}"
		log "  timeout: #{@read_timeout}"
		log "  verbosity: #{@verbosity}"
		log "  started at: #{Time.now}"
		log "===="
	end
	
	def log(msg, level=:debug)
		
		# abort if logging isn't
		# enabled yet (or ever?)
		return false if\
			@log.nil?
		
		ind = "  " * (@log_indents[Thread.current] or 0)
		
		# create a 
		thr = Thread.current["name"]
		thr = (thr.nil?) ? "" : "[#{thr}] "
		
		# dump (almost) everything to file
		if LOG_LEVELS[level] >= LOG_LEVELS[@log_file_verbosity]\
		or level == :file
		
			@log.puts thr + ind + msg
			@log.flush
		end
		
		# also print to the rolling
		# screen log, if necessary
		if LOG_LEVELS[@verbosity] >= LOG_LEVELS[level]
			$stderr.puts thr + ind + msg
		end
	end
	
	# log a message, and increment future messages
	# in this thread. useful for nesting logic
	def log_incr(*args)
		log(*args) unless args.empty?
		@log_indents[Thread.current] += 1
	end
	
	# close the logical block, and (optionally) log
	def log_decr(*args)
		@log_indents[Thread.current] -= 1\
			if @log_indents[Thread.current] > 0
		log(*args) unless args.empty?
	end
	
	# the last message in a logical block
	def log_then_decr(*args)
		log(*args)
		log_decr
	end
end # Modem
end # Gsm
