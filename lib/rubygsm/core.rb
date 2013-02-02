#!/usr/bin/env ruby
#:include:../../README.rdoc
#:title:Ruby GSM
#--
# vim: noet
#++

# standard library
require "timeout.rb"
require "date.rb"

# gems (we're using the ruby-serialport gem
# now, so we can depend upon it in our spec)
require "rubygems"
require "serialport"

# declare constants
# ASCII values
CR = 13 #Carriage return
LF = 10 #Line feed
Null = 0 #null

module Gsm
  class Modem
    include Timeout
  
  
    attr_accessor :verbosity, :read_timeout
    attr_reader :device, :port
    
    # call-seq:
    #   Gsm::Modem.new(port, verbosity=:warn)
    #
    # Create a new instance, to initialize and communicate exclusively with a
    # single modem device via the _port_ (which is usually either /dev/ttyS0
    # or /dev/ttyUSB0), and start logging to *rubygsm.log* in the chdir.
    #
    # Possible options are:
    # :port :: defaults to :auto, but another sane value would be something like "/dev/ttyUSB0"
    # :verbosity :: defaults to :warn, see LOG_LEVELS in log.rb for other possibilities
    # :baud :: defaults to 9600
    # :cmd_delay :: defaults to 0.1
    # :log_file :: defaults to nil, which means it uses the port and launch time and makes a log file in the cwd
    # :skip_default_at_commands :: defaults to false - if true, no initialization AT commands are sent to the modem
    # :at_preinit_commands :: defaults to [] - array of AT commands to send to the modem before our default init commands
    # :at_postinit_commands :: defaults to [] - array of AT commands to send to the modem after our default init commands
    def initialize *args
      if args.count == 1 && args.first.kind_of?(Hash)
        # options is a hash of possible settings
        options = args.first
      else
        # Support the legacy definition of initialize:
        # def initialize(port=:auto, verbosity=:warn, baud=9600, cmd_delay=0.1)
        options = {}
        options[:port] = args.count > 0 ? args[0] : :auto
        options[:verbosity] = args.count > 1 ? args[1] : :warn
        options[:baud] = args.count > 2 ? args[2] :  9600
        options[:cmd_delay] = args.count > 3 ? args[3] :  0.1
      end

      port = options[:port] || :auto
      verbosity = options[:verbosity] || :warn
      baud = options[:baud] || 9600
      cmd_delay = options[:cmd_delay] || 0.1
      log_file = options[:log_file]
      skip_default_at_commands = options[:skip_default_at_commands] || false
      at_preinit_commands = options[:at_preinit_commands] || []
      at_postinit_commands = options[:at_postinit_commands] || []

      # if no port was specified, we'll attempt to iterate
      # all of the serial ports that i've ever seen gsm
      # modems mounted on. this is kind of shaky, and
      # only works well with a single modem. for now,
      # we'll try: ttyS0, ttyUSB0, ttyACM0, ttyS1...
      if port == :auto
        @device, @port = find_a_port baud
        puts "[rubygsm]: found port #{@port}"

      # if the port was a port number or file
      # name, initialize a serialport object
      elsif port.is_a?(String) or port.is_a?(Fixnum)
        @device = SerialPort.new(port, baud, 8, 1, SerialPort::NONE)
        @port = port
        
      # otherwise, we'll assume that the object passed
      # was an object ready to quack like a serial modem
      else
        @device = port
        @port = nil
      end
      
      @cmd_delay = cmd_delay
      @verbosity = verbosity
      @locked_to = false

      # how long should we wait for the modem to
      # respond before raising a timeout error?
      @read_timeout = 10
      
      # how many times should we retry commands (after
      # they fail, or time out) before giving up?
      @retry_commands = 4

      # when the maximum number of retries is exceeded,
      # should the modem AT+CFUN (hard reset), or allow
      # the exception to propagate?
      @reset_on_failure = true

      # keep track of the depth which each
      # thread is indented in the log
      @log_indents = {}
      @log_indents.default = 0
      
      # to keep multi-part messages until
      # the last part is delivered
      @multipart = {}
      
      # start logging to file
      log_init log_file
      
      # to store incoming messages
      # until they're dealt with by
      # someone else, like a commander
      @incoming = []
      
      at_preinit_commands.each{|cmd| try_command cmd}

      perform_default_at_initialization unless skip_default_at_commands

      at_postinit_commands.each{|cmd| try_command cmd}
    end

    #call seq
    #  convert_string_from_ascii_to_char(ascii_string) => char string
    # 
    # This function assumes the ascii_string contains a series of ascii values
    # in 2 hex digits. It converts the ascii_string into a character string, 
    # and strips away the NULL, CR, and LF characters.
    def self.convert_string_from_ascii_to_char(ascii_string)
      char_string =""
      ascii_string_length = ascii_string.length
      offset = 0
      sub_len = 2
      while (offset < ascii_string_length)
        ascii_val_as_char = ascii_string[offset, sub_len]
        ascii_val_in_dec = ascii_val_as_char.to_i(16)
        if (ascii_val_in_dec != CR && ascii_val_in_dec != LF && ascii_val_in_dec != Null)
          #reconstruct the character string, but remove Null, Carriage return, and Line feed.
          char_string += ascii_val_in_dec.chr
        end
        #puts ascii_val_as_char + " " + ascii_val_in_dec.to_s + " " + char_string
        offset += sub_len
      end
      #puts char_string.length.to_s + " chars"
      return char_string
    end
  
  
  private
  
  def find_a_port baud
    catch(:found) do
      possibilities = []
      possibilities += Dir.glob("/dev/ttyUSB*") # Linux
      possibilities += Dir.glob("/dev/cu.LJADeviceInterface*") # Mac
      possibilities += Dir.glob("/dev/tty.ZTEUSBModem_") # ZTE on Mac

      possibilities.each do |try_port|
        begin
          puts "[rubygsm]: try port #{try_port}"

          # serialport args: port, baud, data bits, stop bits, parity
          device = SerialPort.new(try_port, baud, 8, 1, SerialPort::NONE)
          throw :found, [device, try_port]
        
        rescue ArgumentError, Errno::ENOENT
          # do nothing, just continue to
          # try the next port in order
        end
      end

      # tried all ports, nothing worked
      raise AutoDetectError
    end
  end

  def perform_default_at_initialization
    # initialize the modem; rubygsm is (supposed to be) robust enough to function
    # without these working (hence the "try_"), but they make different modems more
    # consistant, and the logs a bit more sane.
    try_command "ATE0"      # echo off
    try_command "AT+CMEE=1" # useful errors

    #[khw]: AT+WIND command isn't supported by my Zoom modem, comment out this line
    #try_command "AT+WIND=0" # no notifications
    
    # PDU mode isn't supported right now (although
    # it should be, because it's quite simple), so
    # switching to text mode (mode 1) is MANDATORY
    command "AT+CMGF=1"

    #auto select operator
    command "AT+COPS=0" #0=automatic selection, 2=numeric id, 310410, 2=current
    
    #select TE character set, which must be "IRA" for sending SMS to work
    #IRA is International Reference Alphabet. 
    #Setting CSCS to "IRA" is necessary for sending SMS to work. Occassionally, the setting is USC2 after
    #powering up the modem
    command "AT+CSCS=\"IRA\""
    
    #select the storage areas
    # SMS reading&deleting: SM, which has space of 30 messages
    # SMS sending&writing: ME, which has space of 0
    # SMS status: SM, which has space of 30 messages
    command "AT+CPMS=\"SM\",\"ME\",\"SM\""
  end

  
  INCOMING_FMT = "%y/%m/%d,%H:%M:%S%Z" #:nodoc:
  CMGL_STATUS = "REC UNREAD" #:nodoc:


  def parse_incoming_timestamp(ts)
    # extract the weirdo quarter-hour timezone,
    # convert it into a regular hourly offset
    ts.sub! /(\d+)$/ do |m|
      sprintf("%02d", (m.to_i/4))
    end
    
    # parse the timestamp, and attempt to re-align
    # it according to the timezone we extracted
    DateTime.strptime(ts, INCOMING_FMT)
  end
  
  def parse_incoming_sms!(lines)
    n = 0
    
    # iterate the lines like it's 1984
    # (because we're patching the array,
    # which is hard work for iterators)
    while n < lines.length
      
      # not a CMT string? ignore it
      unless lines && lines[n] && lines[n][0,5] == "+CMT:"
        n += 1
        next
      end
      
      # since this line IS a CMT string (an incoming
      # SMS), parse it and store it to deal with later
      unless m = lines[n].match(/^\+CMT: "(.+?)",.*?,"(.+?)".*?$/)
        
        # the CMT data couldn't be parsed, so scrap it
        # and move on to the next line.  we'll lose the
        # incoming message, but it's better than blowing up
        log "Couldn't parse CMT data: #{lines[n]}", :warn
        lines.slice!(n, 2)
        n -= 1
        next
      end
      
      # extract the meta-info from the CMT line,
      # and the message from the FOLLOWING line
      from, timestamp = *m.captures
      msg_text = lines[n+1].strip
      
      # notify the network that we accepted
      # the incoming message (for read receipt)
      # BEFORE pushing it to the incoming queue
      # (to avoid really ugly race condition if
      # the message is grabbed from the queue
      # and responded to quickly, before we get
      # a chance to issue at+cnma)
      begin
        command "AT+CNMA"
        
      # not terribly important if it
      # fails, even though it shouldn't
      rescue Gsm::Error
        log "Receipt acknowledgement (CNMA) was rejected"
      end
      
      # we might abort if this part of a
      # multi-part message, but not the last
      catch :skip_processing do
      
        # multi-part messages begin with ASCII char 130
        if (msg_text[0] == 130) and (msg_text[1].chr == "@")
          text = msg_text[7,999]
          
          # ensure we have a place for the incoming
          # message part to live as they are delivered
          @multipart[from] = []\
            unless @multipart.has_key?(from)
          
          # append THIS PART
          @multipart[from].push(text)
          
          # add useless message to log
          part = @multipart[from].length
          log "Received part #{part} of message from: #{from}"
          
          # abort if this is not the last part
          throw :skip_processing\
            unless (msg_text[5] == 173)
          
          # last part, so switch out the received
          # part with the whole message, to be processed
          # below (the sender and timestamp are the same
          # for all parts, so no change needed there)
          msg_text = @multipart[from].join("")
          @multipart.delete(from)
        end
        
        # just in case it wasn't already obvious...
        log "Received message from #{from}: #{msg_text.inspect}"
      
        # store the incoming data to be picked up
        # from the attr_accessor as a tuple (this
        # is kind of ghetto, and WILL change later)
        sent = parse_incoming_timestamp(timestamp)
        msg = Gsm::Incoming.new(self, from, sent, msg_text)
        @incoming.push(msg)
      end
      
      # drop the two CMT lines (meta-info and message),
      # and patch the index to hit the next unchecked
      # line during the next iteration
      lines.slice!(n,2)
      n -= 1
    end
  end
  
  
  # write a string to the modem immediately,
  # without waiting for the lock
  def write(str)
    log "Write: #{str.inspect}", :traffic
    
    begin
      str.each_byte do |b|
        @device.putc(b.chr)
      end
    
    # the device couldn't be written to,
    # which probably means that it has
    # crashed or been unplugged
    rescue Errno::EIO
      raise Gsm::WriteError
    end
  end
  
  
  # read from the modem (blocking) until
  # the term character is hit, and return
  def read(term=nil)
    term = "\r\n" if term==nil
    term = [term] unless term.is_a? Array
    buf = ""
    
    # include the terminator in the traffic dump,
    # if it's anything other than the default
    #suffix = (term != ["\r\n"]) ? " (term=#{term.inspect})" : ""
    #log_incr "Read" + suffix, :traffic
    
    begin
      timeout(@read_timeout) do
        while true do
          char = @device.getc
          
          # die if we couldn't read
          # (nil signifies an error)
          raise Gsm::ReadError\
            if char.nil?
          
          # convert the character to ascii,
          # and append it to the tmp buffer
          buf << sprintf("%c", char)
        
          # if a terminator was just received,
          # then return the current buffer
          term.each do |t|
            len = t.length
            if buf[-len, len] == t
              log "Read: #{buf.inspect}", :traffic
              return buf.strip
            end
          end
        end
      end
    
    # reading took too long, so intercept
    # and raise a more specific exception
    rescue Timeout::Error
      log = "Read: Timed out", :warn
      raise TimeoutError
    end
  end
  
  
  def command(cmd, *args)
    tries = 0
    out = []
    
    begin
      # attempt to issue the command, which
      # might blow up, if the modem is angry
      log_incr "Command: #{cmd} (##{tries+1} of #{@retry_commands+1})"
      out = command!(cmd, *args)
      
    rescue Exception => err
      log_then_decr "Rescued (in #command): #{err}"
      
      if (tries += 1) <= @retry_commands
        delay = (2**tries)/2

        log "Sleeping for #{delay}"
        sleep(delay)
        retry
      end
      
      # when things just won't work, reboot the modem,
      # then try again. if the reboot fails, there is
      # nothing that we can do; so propagate
      # reboot the modem. this happens more often
      if @reset_on_failure
        log_then_decr "Resetting the modem"
        retry if reset!

        # failed to reboot :'(
        log "Couldn't rese"
        raise

      else
        # we've retried enough times, but don't
        # want to auto reset. let's hope that
        # someone upstream has a better idea
        log_decr "Propagating exception"
        raise
      end
    end
  
    # the command was successful
    log_decr "=#{out.inspect} // command"
    return out
  end
  
  
  # issue a single command, and wait for the response. if the command
  # fails (CMS or CME error is returned by the modem), a Gsm::Error
  # will be raised, and allowed to propagate. see Modem#command to
  # automatically retry failing commands
  def command!(cmd, resp_term=nil, write_term="\r")
    begin
      out = ""
      log_incr "Command!: #{cmd}"
      
      exclusive do
        write(cmd + write_term)
        out = wait(resp_term)
      end
    
      # some hardware (my motorola phone) adds extra CRLFs
      # to some responses. i see no reason that we need them
      out.delete ""
    
      # for the time being, ignore any unsolicited
      # status messages. i can't seem to figure out
      # how to disable them (AT+WIND=0 doesn't work)
      out.delete_if do |line|
        (line[0,6] == "+WIND:") or
        (line[0,6] == "+CREG:") or
        (line[0,7] == "+CGREG:")
      end
    
      # parse out any incoming sms that were bundled
      # with this data (to be fetched later by an app)
      parse_incoming_sms!(out)
    
      # log the modified output
      log_decr "=#{out.inspect} // command!"
    
      # rest up for a bit (modems are
      # slow, and get confused easily)
      sleep(@cmd_delay)
      return out
    
    # if the 515 (please wait) error was thrown,
    # then automatically re-try the command after
    # a short delay. for others, propagate
    rescue Error => err
      log_then_decr "Rescued (in #command!): #{err}"
      
      if (err.type == "CMS") and (err.code == 515)
        sleep 2
        retry
      end
      
      log_decr
      raise
    end
  end
  
  
  # proxy a single command to #command, but catch any
  # Gsm::Error exceptions that are raised, and return
  # nil. This should be used to issue commands which
  # aren't vital - of which there are VERY FEW.
  def try_command(cmd, *args)
    begin
      log_incr "Trying Command: #{cmd}"
      out = command(cmd, *args)
      log_decr "=#{out.inspect} // try_command"
      return out
      
    rescue Error => err
      log_then_decr "Rescued (in #try_command): #{err}"
      return nil
    end
  end
  
  
  def query(cmd)
    log_incr "Query: #{cmd}"
    out = command cmd
  
    # only very simple responses are supported
    # (on purpose!) here - [response, crlf, ok]
    if (out.length==2) and (out[1]=="OK")
      log_decr "=#{out[0].inspect}"
      return out[0]
    
    else
      err = "Invalid response: #{out.inspect}"
      raise RuntimeError.new(err)
    end
  end
  
  
  # just wait for a response, by reading
  # until an OK or ERROR terminator is hit
  def wait(term=nil)
    buffer = []
    log_incr "Waiting for response"
    
    while true do
      buf = read(term)
      buffer.push(buf)
      
      # some errors contain useful error codes,
      # so raise a proper error with a description
      if m = buf.match(/^\+(CM[ES]) ERROR: (\d+)$/)
        log_then_decr "!! Raising Gsm::Error #{$1} #{$2}"
        raise Error.new(*m.captures)
      end
    
      # some errors are not so useful :|
      if buf == "ERROR"
        log_then_decr "!! Raising Gsm::Error"
        raise Error
      end
    
      # most commands return OK upon success, except
      # for those which prompt for more data (CMGS)
      if (buf=="OK") or (buf==">")
        log_decr "=#{buffer.inspect}"
        return buffer
      end
    
      # some commands DO NOT respond with OK,
      # even when they're successful, so check
      # for those exceptions manually
      if m = buf.match(/^\+CPIN: (.+)$/)
        log_decr "=#{buffer.inspect}"
        return buffer
      end
    end
  end
  
  
  def exclusive &blk
    old_lock = nil
    
    begin
      
      # prevent other threads from issuing
      # commands TO THIS MODDEM while this
      # block is working. this does not lock
      # threads, just the gsm device
      if @locked_to and (@locked_to != Thread.current)
        log "Locked by #{@locked_to["name"]}, waiting..."
      
        # wait for the modem to become available,
        # so we can issue commands from threads
        while @locked_to
          sleep 0.05
        end
      end
      
      # we got the lock!
      old_lock = @locked_to
      @locked_to = Thread.current
      log_incr "Got lock"
    
      # perform the command while
      # we have exclusive access
      # to the modem device
      yield
      
    
    # something went bang, which happens, but
    # just pass it on (after unlocking...)
    rescue Gsm::Error
      raise
    
    
    # no message, but always un-
    # indent subsequent log messages
    # and RELEASE THE LOCK
    ensure
      @locked_to = old_lock
      Thread.pass
      log_decr
    end
  end
  
  
  
  
  public
  
  
  # call-seq:
  #   reset! => true or false
  #
  # Resets the modem software, or raises Gsm::ResetError.
  def reset!
    begin
      return command!("AT+CFUN=1")
  
    # if the reset fails, we'll wrap the exception in
    # a Gsm::ResetError, so it can be caught upstream.
    # this usually indicates a serious problem.
    rescue Exception
      raise ResetError  
    end
  end
  
  
  # call-seq:
  #   hardware => hash
  #
  # Returns a hash of containing information about the physical
  # modem. The contents of each value are entirely manufacturer
  # dependant, and vary wildly between devices.
  #
  #   modem.hardware => { :manufacturer => "Multitech".
  #                       :model        => "MTCBA-G-F4", 
  #                       :revision     => "123456789",
  #                       :serial       => "ABCD" }
  def hardware
    return {
      :manufacturer => query("AT+CGMI"),
      :model        => query("AT+CGMM"),
      :revision     => query("AT+CGMR"),
      :serial       => query("AT+CGSN") }
  end
  
  
  # The values accepted and returned by the AT+WMBS
  # command, mapped to frequency bands, in MHz. Copied
  # directly from the MultiTech AT command-set reference
  Bands = {
    0 => "850",
    1 => "900",
    2 => "1800",
    3 => "1900",
    4 => "850/1900",
    5 => "900E/1800",
    6 => "900E/1900"
  }
  
  # call-seq:
  #   bands_available => array
  #
  # Returns an array containing the bands supported by
  # the modem.
  def bands_available
    data = query("AT+WMBS=?")
    
    # wmbs data is returned as something like:
    #  +WMBS: (0,1,2,3,4,5,6),(0-1)
    #  +WMBS: (0,3,4),(0-1)
    # extract the numbers with a regex, and
    # iterate each to resolve it to a more
    # readable description
    if m = data.match(/^\+WMBS: \(([\d,]+)\),/)
      return m.captures[0].split(",").collect do |index|
        Bands[index.to_i]
      end
    
    else
      # Todo: Recover from this exception
      err = "Not WMBS data: #{data.inspect}"
      raise RuntimeError.new(err)
    end
  end
  
  # call-seq:
  #   band => string
  #
  # Returns a string containing the band
  # currently selected for use by the modem.
  def band
    data = query("AT+WMBS?")
    if m = data.match(/^\+WMBS: (\d+),/)
      return Bands[m.captures[0].to_i]
      
    else
      # Todo: Recover from this exception
      err = "Not WMBS data: #{data.inspect}"
      raise RuntimeError.new(err)
    end
  end
  
  BandAreas = {
    :usa     => 4,
    :africa  => 5,
    :europe  => 5,
    :asia    => 5,
    :mideast => 5
  }
  
  # call-seq:
  #   band=(_numeric_band_) => string
  #
  # Sets the band currently selected for use
  # by the modem, using either a literal band
  # number (passed directly to the modem, see
  # Gsm::Modem.Bands) or a named area from
  # Gsm::Modem.BandAreas:
  #
  #   m = Gsm::Modem.new
  #   m.band = :usa    => "850/1900"
  #   m.band = :africa => "900E/1800"
  #   m.band = :monkey => ArgumentError
  #
  # (Note that as usual, the United States of
  # America is wearing its ass backwards.)
  #
  # Raises ArgumentError if an unrecognized band was
  # given, or raises Gsm::Error if the modem does
  # not support the given band.
  def band=(new_band)
    
    # resolve named bands into numeric
    # (mhz values first, then band areas)
    unless new_band.is_a?(Numeric)
      
      if Bands.has_value?(new_band.to_s)
        new_band = Bands.index(new_band.to_s)
      
      elsif BandAreas.has_key?(new_band.to_sym)
        new_band = BandAreas[new_band.to_sym]
        
      else
        err = "Invalid band: #{new_band}"
        raise ArgumentError.new(err)
      end
    end
    
    # set the band right now (second wmbs
    # argument is: 0=NEXT-BOOT, 1=NOW). if it
    # fails, allow Gsm::Error to propagate
    command("AT+WMBS=#{new_band},1")
  end
  
  # call-seq:
  #   pin_required? => true or false
  #
  # Returns true if the modem is waiting for a SIM PIN. Some SIM cards will refuse
  # to work until the correct four-digit PIN is provided via the _use_pin_ method.
  def pin_required?
    not command("AT+CPIN?").include?("+CPIN: READY")
  end
  
  
  # call-seq:
  #   use_pin(pin) => true or false
  #
  # Provide a SIM PIN to the modem, and return true if it was accepted.
  def use_pin(pin)
    
    # if the sim is already ready,
    # this method isn't necessary
    if pin_required?
      begin
        command "AT+CPIN=#{pin}"
    
      # if the command failed, then
      # the pin was not accepted
      rescue Gsm::Error
        return false
      end
    end
    
    # no error = SIM
    # PIN accepted!
    true
  end
  
  
  # call-seq:
  #   signal => fixnum or nil
  #
  # Returns an fixnum between 1 and 99, representing the current
  # signal strength of the GSM network, or nil if we don't know.
  def signal_strength
    data = query("AT+CSQ")
    if m = data.match(/^\+CSQ: (\d+),/)
      
      # 99 represents "not known or not detectable",
      # but we'll use nil for that, since it's a bit
      # more ruby-ish to test for boolean equality
      csq = m.captures[0].to_i
      return (csq<99) ? csq : nil
      
    else
      # Todo: Recover from this exception
      err = "Not CSQ data: #{data.inspect}"
      raise RuntimeError.new(err)
    end
  end
  
  
  # call-seq:
  #   wait_for_network
  #
  # Blocks until the signal strength indicates that the
  # device is active on the GSM network. It's a good idea
  # to call this before trying to send or receive anything.
  def wait_for_network
    
    # keep retrying until the
    # network comes up (if ever)
    until csq = signal_strength
      sleep 1
    end
    
    # return the last
    # signal strength
    return csq
  end
  
  
  # call-seq:
  #   send_sms(message) => true or false
  #   send_sms(recipient, text) => true or false
  #
  # Sends an SMS message via _send_sms!_, but traps
  # any exceptions raised, and returns false instead.
  # Use this when you don't really care if the message
  # was sent, which is... never.
  def send_sms(*args)
    begin
      send_sms!(*args)
      return true
    
    # something went wrong
    rescue Gsm::Error
      return false
    end
  end
  
  
  # call-seq:
  #   send_sms!(message) => true or raises Gsm::Error
  #   send_sms!(receipt, text) => true or raises Gsm::Error
  #
  # Sends an SMS message, and returns true if the network
  # accepted it for delivery. We currently can't handle read
  # receipts, so have no way of confirming delivery. If the
  # device or network rejects the message, a Gsm::Error is
  # raised containing (hopefully) information about what went
  # wrong.
  #
  # Note: the recipient is passed directly to the modem, which
  # in turn passes it straight to the SMSC (sms message center).
  # For maximum compatibility, use phone numbers in international
  # format, including the *plus* and *country code*.
  def send_sms!(*args)
    
    # extract values from Outgoing object.
    # for now, this does not offer anything
    # in addition to the recipient/text pair,
    # but provides an upgrade path for future
    # features (like FLASH and VALIDITY TIME)
    if args.length == 1\
    and args[0].is_a? Gsm::Outgoing
      to = args[0].recipient
      msg = args[0].text
    
    # the < v0.4 arguments. maybe
    # deprecate this one day
    elsif args.length == 2
      to, msg = *args
    
    else
      raise ArgumentError,\
        "The Gsm::Modem#send_sms method accepts" +\
        "a single Gsm::Outgoing instance, " +\
        "or recipient and text strings"
    end
    
    # the number must be in the international
    # format for some SMSCs (notably, the one
    # i'm on right now) so maybe add a PLUS
    #to = "+#{to}" unless(to[0,1]=="+")
    
    # 1..9 is a special number which does notm
    # result in a real sms being sent (see inject.rb)
    if to == "+123456789"
      log "Not sending test message: #{msg}"
      return false
    end
    
    # block the receiving thread while
    # we're sending. it can take some time
    exclusive do
      tries = 0
      
      begin
        log_incr "Sending SMS to #{to}: #{msg}"
        log "Attempt #{tries+1} of #{@retry_commands}"
      
        # initiate the sms, and wait for either
        # the text prompt or an error message
        command! "AT+CMGS=\"#{to}\"", ["\r\n", "> "]
      
        # send the sms, and wait until
        # it is accepted or rejected
        write "#{msg}#{26.chr}"
        wait
        
        
      # if something went wrong, we are
      # be stuck in entry mode (which will
      # result in someone getting a bunch
      # of AT commands via sms!) so send
      # an escpae, to... escape
      rescue Exception, Timeout::Error => err
        log "Rescued #{err}"
        write 27.chr
        
        if (tries +=1) < @retry_commands
          log_decr
          sleep((2**tries)/2)
          retry
        end
        
        # allow the error to propagate,
        # so the application can catch
        # it for more useful info
        raise
        
      ensure
        log_decr
      end
    end
        
    # if no error was raised,
    # then the message was sent
    return true
  end
  
  
  # call-seq:
  #   receive(callback_method, interval=5, join_thread=false)
  #
  # Starts a new thread, which polls the device every _interval_
  # seconds to capture incoming SMS and call _callback_method_
  # for each, and polls the device's internal storage for incoming
  # SMS that we weren't notified about (some modems don't support
  # that).
  #
  #   class Receiver
  #     def incoming(msg)
  #       puts "From #{msg.sender} at #{msg.time_sent}:", msg.text
  #     end
  #   end
  #   
  #   # create the instances,
  #   # and start receiving
  #   rcv = Receiver.new
  #   m = Gsm::Modem.new "/dev/ttyS0"
  #   m.receive rcv.method :incoming
  #   
  #   # block until ctrl+c
  #   while(true) { sleep 2 }
  #
  # Note: New messages may arrive at any time, even if this method's
  # receiver thread isn't waiting to process them. They are not lost,
  # but cached in @incoming until this method is called.
  def receive(callback, interval=5, join_thread=false)
    @polled = 0
    
    @thr = Thread.new do
      Thread.current["name"] = "receiver"
      
      # keep on receiving forever
      while true
        command "AT"

        # enable new message notification mode every ten intevals, in case the
        # modem "forgets" (power cycle, etc)
        if (@polled % 10) == 0

          #AT+CNMI=2,2,0,0,0 isn't supported by Zoom modem
          #try_command("AT+CNMI=2,2,0,0,0")

          # use AT+CMNI=2,1,0,0,0 instead, which configures the modem
          # to notify new incoming SMS using unsolicited code +CMTI: "SM", <index>
          try_command("AT+CNMI=2,1,0,0,0")
        end
        
        # check for new messages lurking in the device's
        # memory (in case we missed them (yes, it happens))
        if (@polled % 4) == 0
          fetch_stored_messages
        end
        
        # if there are any new incoming messages,
        # iterate, and pass each to the receiver
        # in the same format that they were built
        # back in _parse_incoming_sms!_
        unless @incoming.empty?
          @incoming.each do |msg|
            begin
              callback.call(msg)
              
            rescue StandardError => err
              log "Error in callback: #{err}"
            end
          end
          
          # we have dealt with all of the pending
          # messages. todo: this is a ridiculous
          # race condition, and i fail at ruby
          @incoming.clear

                #delete all READ messages from the storage area
            try_command("AT+CMGD=,1")
            #check the available space in the storage area
            try_command("AT+CPMS?")
        end
        
        # re-poll every
        # five seconds
        sleep(interval)
        @polled += 1
      end
    end
    
    # it's sometimes handy to run single-
    # threaded (like debugging handsets)
    @thr.join if join_thread
  end
  

    # call-seq:
    #   fetch_stored_messages
    #
    # This method called by receive()
  def fetch_stored_messages
    
    # fetch all/unread (see constant) messages
    lines = command('AT+CMGL="%s"' % CMGL_STATUS)
    n = 0
    
    # if the last line returned is OK
    # (and it SHOULD BE), remove it
    lines.pop if lines[-1] == "OK"
    
    # keep on iterating the data we received,
    # until there's none left. if there were no
    # stored messages waiting, this done nothing!
    while n < lines.length
      
      # fix or workaround for bug #47
      # (http://spires_sms_app.lighthouseapp.com/projects/80171/tickets/47-modem_controller-crashed-due-to-incoming-att-msg)
      # 
      # rubygsm crashes when the incoming unsolicited message has extra CMTI info at the begnning
      # "", "+CMTI: \"SM\",0", "", "+CMGL: 0,\"REC UNREAD\",\"7535\",,\"12/10/26,15:12:52-28\"", "AT&T Free Msg:..."
      # which receiver reads as
      # [receiver]         Read: "\r\n"
      # [receiver]         Read: "+CMTI: \"SM\",0\r\n"
      # [receiver]         Read: "\r\n"
      # [receiver]         Read: "+CMGL: 0,\"REC UNREAD\",\"7535\",,\"12/10/26,15:12:52-28\"\r\n"
      # [receiver]         Read: "AT&T Free Msg: your unlimited messaging pkg was not renewed on 10/26/12 due to lack of balance. Refill your GoPhone acct today and re-enroll in auto-renew.\r\n"
      #
      #
      # as oppose to
      # "", "+CMGL: 0,\"REC UNREAD\",\"28887777\",,\"12/09/26,17:00:53-28\"", "AT&T Free Msg:..." 
      #
      # [receiver]         Read: "\r\n"
      # [receiver]         Read: "+CMGL: 0,\"REC UNREAD\",\"28887777\",,\"12/09/26,17:00:53-28\"\r\n"
      # [receiver]         Read: "AT&T Free Msg: your unlimited messaging pkg was not renewed on 10/26/12 due to lack of balance. Refill your GoPhone acct today and re-enroll in auto-renew.\r\n"
      #
      # Two extra lines are added :"", "+CMTI: \"SM\",0",
      # The workaround is if the string "CMTI" is detected in the current line (n), skip 2 lines to get to the CMGL line (n+2).
      if m = lines[n].match(/^\+CMTI:/)
        if (n + 2) < lines.length
        n = n + 2          
        end
      end
  
      # attempt to parse the CMGL line (we're skipping
      # two lines at a time in this loop, so we will
      # always land at a CMGL line here) - they look like:
      #   +CMGL: 0,"REC READ","+13364130840",,"09/03/04,21:59:31-20"
      unless m = lines[n].match(/^\+CMGL: (\d+),"(.+?)","(.+?)",*?,"(.+?)".*?$/)
        puts "[rubygsm]: couldn't parse CMGL data: #{lines[n]}"
        err = "couldn't parse CMGL data: #{lines[n]}"
        raise RuntimeError.new(err)
      end
      
      # find the index of the next
      # CMGL line, or the end
      nn = n+1
      nn += 1 until\
        nn >= lines.length ||\
        lines[nn][0,6] == "+CMGL:"
      
      # extract the meta-info from the CMGL line, and the
      # message text from the lines between _n_ and _nn_
      index, status, from, timestamp = *m.captures
      msg_text = lines[(n+1)..(nn-1)].join("\n").strip
      
      # log the incoming message
      log "Fetched stored message from #{from}: #{msg_text.inspect}"
      log "message index: |#{index}|"
      log "message status: |#{status}|"
      log "message from: |#{from}|"
      log "message timestamp: |#{timestamp}|"
      log "message text: |#{msg_text.inspect}|"
      
      # store the incoming data to be picked up
      # from the attr_accessor as a tuple (this
      # is kind of ghetto, and WILL change later)
      time_sent = timestamp
      msg = Gsm::Incoming.new(self, from, time_sent, msg_text)
      @incoming.push(msg)
    
      # skip over the messge line(s),
      # on to the next CMGL line
      n = nn
    end
  end
end # Modem
end # Gsm
