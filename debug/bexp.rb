#!/usr/bin/env ruby

require 'net/http'
require 'json'
require 'pp'

BASE_URL = 'https://blockexplorer.com/api'

uri = URI([BASE_URL, ARGV[0]].join('/'))

begin
  resp = Net::HTTP.get(uri)
  pp JSON.parse(resp)
rescue JSON::ParserError
  puts resp
end


