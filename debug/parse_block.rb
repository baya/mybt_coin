#!/usr/bin/env ruby
# coding: utf-8

require 'bitcoin'

raw_blk = File.open(ARGV[0], 'rb') {|f| f.read }

begin
  blk = Bitcoin::Protocol::Block.new(raw_blk[8..-1])
rescue Exception => e
  puts e.inspect
  # 去掉文件开头的 magic no 和 block size 总共 8 个字节
  blk = Bitcoin::Protocol::Block.new(raw_blk[8..-1])
end
# puts Bitcoin::Protocol::Block.from_json( blk.to_json )
puts blk.to_json
