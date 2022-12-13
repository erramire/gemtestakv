require 'GemAKV'
require 'Extraction'

#Extraction.initialize()


#s= Extraction::get_value("env",nil)
Extraction.initialize()
s= Extraction.get_value("env")
puts(s)