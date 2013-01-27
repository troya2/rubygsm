Gem::Specification.new do |s|
	s.name     = "rubygsm"
	s.version  = "0.54"
	s.date     = "2013-01-27"
	s.summary  = "Send and receive SMS with a GSM modem"
	s.email    = "troy@elbowroomstudios.com"
	s.homepage = "http://github.com/troya2/rubygsm"
	s.authors  = ["Adam Mckaig", "khwang1", "Troy Anderson"]
	s.has_rdoc = true
	
	s.files = [
		"rubygsm.gemspec",
		"README.rdoc",
		"lib/rubygsm.rb",
		"lib/rubygsm/core.rb",
		"lib/rubygsm/errors.rb",
		"lib/rubygsm/log.rb",
		"lib/rubygsm/msg/incoming.rb",
		"lib/rubygsm/msg/outgoing.rb",
		"bin/gsm-modem-band",
		"bin/sms"
	]
	
	s.executables = [
		"gsm-modem-band",
		"sms"
	]
	
	s.add_dependency("serialport", ["> 0.7.1"])
end
