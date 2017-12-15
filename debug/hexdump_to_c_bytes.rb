#!/usr/bin/env ruby

data = []
ARGF.each_line {|line|
  data << line[7..-1].split(' ').map {|b| "0x#{b}"}.join(", ")
}

puts data.join(",\n")


