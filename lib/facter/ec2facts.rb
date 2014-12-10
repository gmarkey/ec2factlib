#!/usr/bin/env ruby

require 'net/http'
require 'net/https'
require 'openssl'
require 'base64'
require 'rexml/document'
require 'json'

# Escape URI form components.
# URI.encode_www_form_component doesn't exist on Ruby 1.8, so we fall back to
# URI.encode + gsub
def uri_encode(component)
  if URI.respond_to? :encode_www_form_component
    URI.encode_www_form_component(component)
  else
    URI.encode(component).gsub('=', '%3D').gsub(':', '%3A').gsub('/', '%2F').gsub('+', '%2B')
  end
end

# The instance document tells us our instance id, region, etc
def get_instance_document
  url = URI.parse('http://169.254.169.254/latest/dynamic/instance-identity/document')
  response = Net::HTTP.get_response(url)

  return nil if response.code != "200"

  return JSON.parse(response.body)
end

# If an IAM role is available for the instance, we will attempt to query it.
# We return an empty Hash on failure. Keys may be available via enviroment
# variables as a fallback.
def get_instance_role
  url = URI.parse('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
  response = Net::HTTP.get_response(url)

  return {} if response.code != "200"

  body = response.body

  role = body.lines.first
  response = Net::HTTP::get_response(url+role)

  return {} if response.code != "200"

  role = JSON.parse(response.body)
end

# Sign and send a request to the AWS REST API. Method is defined as an "Action" parameter.
# parameters is an array because order is important for the signing process.
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

  response
end

# Queries the tags from the provided EC2 instance id.
def query_instance_tags(instance_id, endpoint, access_key, secret_key, token = nil)
  parameters = [
    ['Action',            'DescribeInstances' ],
    ['InstanceId.1',      instance_id         ],
    ['Version',           '2014-10-01'        ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  if response.code != "200"
    Facter.debug("DescribeInstances returned #{response.code} #{response.message}")
    return {}
  end

  doc = REXML::Document.new(response.body)

  tags = {}
  doc.get_elements('//tagSet/item').each do |item|
    key = item.get_elements('key')[0].text
    value = item.get_elements('value')[0].text
    tags[key] = value
  end

  return tags
end

# Queries the min/max/desired size of the provided autoscaling group.
def query_autoscale_group(group_id, endpoint, access_key, secret_key, token)
  parameters = [
    ['Action',                            'DescribeAutoScalingGroups' ],
    ['AutoScalingGroupNames.member.1',      group_id                    ],
    ['Version',                           '2011-01-01'                ],
  ]
  response = query(parameters, endpoint, access_key, secret_key, token)

  if response.code != "200"
    Facter.debug("DescribeAutoScalingGroups returned #{response.code} #{response.message}")
    return {}
  end

  doc = REXML::Document.new(response.body)

  # Note: These params get merged into the facts Hash, so the keys should match the fact names
  params = {}

  min_size_elem = doc.get_elements('//MinSize')[0]
  if min_size_elem.nil?
    Facter.debug("No MinSize found for autoscaling group #{group_id}")
    return nil
  else
    params['autoscaling_min_size'] = min_size_elem.text
  end

  max_size_elem = doc.get_elements('//MinSize')[0]
  if max_size_elem.nil?
    Facter.debug("No MinSize found for autoscaling group #{group_id}")
    return nil
  else
    params['autoscaling_max_size'] = max_size_elem.text
  end

  desired_cap_elem = doc.get_elements('//MinSize')[0]
  if desired_cap_elem.nil?
    Facter.debug("No MinSize found for autoscaling group #{group_id}")
    return nil
  else
    params['autoscaling_desired_capacity'] = desired_cap_elem.text
  end

  return params
end

# Look for our EC2 instance ID, then query the tags assigned to the instance.
# If there is an autoscaling group tag (aws:autoscaling:groupName), also query
# the autoscaling group min/max/desired size parameters.
def check_facts
  facts = {}
  open('/etc/ec2_version', 'r') do |io|
    facts['ec2_version'] = io.read.strip
  end

  instance    = get_instance_document
  if instance.nil?
    Facter.debug("Didn't get instance document from http://169.254.169.254/latest/dynamic/instance-identity/document")
    return
  end

  instance_id = instance['instanceId']
  region      = instance['region']
  role        = get_instance_role

  access_key  = role['AccessKeyId']     || ENV['AWS_ACCESS_KEY_ID']
  secret_key  = role['SecretAccessKey'] || ENV['AWS_SECRET_ACCESS_KEY']
  token       = role['Token']

  if access_key.nil? || secret_key.nil?
    Facter.debug("No authentication key available")
    return
  end

  tags = query_instance_tags(instance_id, "ec2.#{region}.amazonaws.com", access_key, secret_key, token)
  tags.each do |tag, value|
    next if tag.start_with?('aws:')

    facts["ec2_tag_#{tag}"] = value
  end

  if tags.has_key? 'aws:autoscaling:groupName'
    autoscale_group = tags['aws:autoscaling:groupName']

    facts['autoscaling_group_name'] = autoscale_group

    asg_params = query_autoscale_group(autoscale_group, "autoscaling.#{region}.amazonaws.com", access_key, secret_key, token)
    facts = facts.merge(asg_params)
  end

  if tags.has_key? 'aws:cloudformation:stack-name'
    facts['cloudformation_stack_name'] = tags['aws:cloudformation:stack-name']
  end

  facts.each do |fact, value|
    Facter.add(fact) do
      setcode { value }
    end
  end
rescue rescue StandardError => e
  Facter.debug("Unhandled #{e.class}: #{e.message}")
end

# This file seems to exist on our EC2 instances. There may be a better way to
# determine if we are running on EC2.
# We mostly want to avoid waiting for http://169.254.169.254/ to time out if we are not on EC2.
if File.exists?('/etc/ec2_version')
  check_facts
end
