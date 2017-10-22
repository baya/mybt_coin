#!/usr/bin/env ruby

require 'bitcoin'

raw_tx = File.open(ARGV[0], 'rb') {|f| f.read }
tx = Bitcoin::Protocol::Tx.new(raw_tx)
puts "tx hash: #{tx.hash}"
puts "txin size: #{tx.in.size}"

puts tx.to_hash.inspect
tx.in.each {|txin|
  puts txin.script_length
}
puts tx.to_json
