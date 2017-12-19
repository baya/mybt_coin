#!/usr/bin/env ruby
# str = "18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725"
# str = "16:26:07:83:e4:0b:16:73:16:73:62:2a:c8:a5:b0:45:fc:3e:a4:af:70:f7:27:f3:f9:e9:2b:dd:3a:1d:dc:42"
str = ARGV[0]

tokens_list = []
count = 0
if str.include?(":")
  tokens = str.split(":")
else
  tokens = str.scan(/../)
end
bstr_list = tokens.map {|tkn| "0x#{tkn}" }.each_with_index {|item, i|

  tokens_list[count] ||= []
  tokens_list[count] << item

  if (i+1) % 16 == 0
    count += 1
  end

}

tstr = tokens_list.map {|tokens|
  tokens.join(", ")
}.join(",\n")


puts tstr

