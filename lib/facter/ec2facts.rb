#!/usr/bin/env ruby

require 'net/http'
require 'net/https'
require 'openssl'
require 'base64'
require 'rexml/document'
require 'json'

def uri_encode(component)
  if URI.respond_to? :encode_www_form_component
    URI.encode_www_form_component(component)
  else
    URI.encode(component).gsub('=', '%3D').gsub(':', '%3A').gsub('/', '%2F').gsub('+', '%2B')
  end
end

def get_instance_document
  url = URI.parse('http://169.254.169.254/latest/dynamic/instance-identity/document')
  response = Net::HTTP.get_response(url)

  return nil if response.code != "200"

  return JSON.parse(response.body)
end

def get_instance_id
  url = URI.parse('http://169.254.169.254/latest/meta-data/instance-id')
  response = Net::HTTP.get_response(url)

  return nil if response.code != "200"

  return response.body
end

def get_instance_role
  url = URI.parse('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  response = Net::HTTP.get_response(url)

  return nil if response.code != "200"

  body = response.body

  role = body.lines.first
  response = Net::HTTP::get_response(url+role)

  return nil if response.code != "200"

  role = JSON.parse(response.body)
end

def query(parameters, endpoint, access_key, secret_key, token = nil)
  timestamp = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')

  parameters += [
    ['AWSAccessKeyId',    access_key          ],
    ['SignatureVersion',  '2'                 ],
    ['SignatureMethod',   'HmacSHA256'        ],
    ['Timestamp',         timestamp           ],
  ]
  if token
    parameters.push(['SecurityToken', token])
  end

  sorted_parameters    = parameters.sort_by    {|k,v| k }
  sorted_params_string = sorted_parameters.map {|k,v| "#{uri_encode(k)}=#{uri_encode(v)}" }.join('&')
  params_string        = parameters.map        {|k,v| "#{uri_encode(k)}=#{uri_encode(v)}" }.join('&')

  canonical_query = [
    'GET',
    endpoint,
    '/',
    sorted_params_string
  ].join("\n")

  sha256    = OpenSSL::Digest::Digest.new('sha256')
  signature = OpenSSL::HMAC.digest(sha256, secret_key, canonical_query)
  signature = Base64.encode64(signature).strip
  signature = uri_encode(signature)

  req_path = "/?#{params_string}&Signature=#{signature}"
  req = Net::HTTP::Get.new(req_path)

  http = Net::HTTP.new(endpoint, 443)
  http.use_ssl = true

  response = http.start { http.request(req) }

  if response.code != "200"
    $stderr.puts response
    $stderr.puts response.body
    exit 1
  end

  response
end

def query_instance_tags(instance_id, endpoint, access_key, secret_key, token = nil)
  parameters = [
    ['Action',            'DescribeInstances' ],
    ['InstanceId.1',      instance_id         ],
    ['Version',           '2014-10-01'        ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  doc = REXML::Document.new(response.body)

  tags = {}
  doc.get_elements('//tagSet/item').each do |item|
    key = item.get_elements('key')[0].text
    value = item.get_elements('value')[0].text
    tags[key] = value
  end

  return tags
end

def query_autoscale_group(group_id, endpoint, access_key, secret_key, token)
  parameters = [
    ['Action',                            'DescribeAutoScalingGroups' ],
    ['AutoScalingGroupNames.member.1',      group_id                    ],
    ['Version',                           '2011-01-01'                ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  doc = REXML::Document.new(response.body)

  min_size = doc.get_elements('//MinSize')[0].text
  max_size = doc.get_elements('//MaxSize')[0].text
  desired  = doc.get_elements('//DesiredCapacity')[0].text

  return min_size, max_size, desired
end

if File.exists?('/etc/ec2_version')
  facts = {}
  open('/etc/ec2_version', 'r') do |io|
    facts['ec2_version'] = io.read.strip
  end

  instance    = get_instance_document
  instance_id = instance['instanceId']
  region      = instance['region']
  role        = get_instance_role

  access_key  = role['AccessKeyId']     || ENV['AWS_ACCESS_KEY_ID']
  secret_key  = role['SecretAccessKey'] || ENV['AWS_SECRET_ACCESS_KEY']
  token       = role['Token']

  tags = query_instance_tags(instance_id, "ec2.#{region}.amazonaws.com", access_key, secret_key, token)

  tags.each do |tag, value|
    next if tag.start_with?('aws:')

    facts["ec2_tag_#{tag}"] = value
  end

  if tags.has_key? 'aws:autoscaling:groupName'
    autoscale_group = tags['aws:autoscaling:groupName']

    facts['autoscaling_group_name'] = autoscale_group

    min_size, max_size, desired = query_autoscale_group(autoscale_group, "autoscaling.#{region}.amazonaws.com", access_key, secret_key, token)
    facts['autoscaling_min_size']         = min_size
    facts['autoscaling_max_size']         = max_size
    facts['autoscaling_desired_capacity'] = desired
  end

  if tags.has_key? 'aws:cloudformation:stack-name'
    facts['cloudformation_stack_name'] = tags['aws:cloudformation:stack-name']
  end

  if defined? Facter
    facts.each do |fact, value|
      Facter.add(fact) do
        setcode { value }
      end
    end
  elsif binding.respond_to? :pry
    binding.pry
  else
    facts.each do |fact, value|
      puts "#{fact} => #{value}"
    end
  end
end
