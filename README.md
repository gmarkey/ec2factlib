# ec2factlib - EC2 Facts library

A puppet/facter plugin to expose EC2 instance details as facts.

The plugin is written in (almost) vanilla/stdlib ruby to make it suitable for
initial bootstrap without the aws-sdk gem installed.

Facts currently include:
* EC2 version string from `/etc/ec2_version` (`ec2_version`)
* EC2 instance tags (`ec2_tag_*`)
* CloudFormation stack name (`cloudformation_stack_name`)
* Autoscaling group name (`autoscaling_group_name`)
* Autoscaling group min/max/desired size (`autoscaling_(min|max)_size`, `autoscaling_desired_capacity`)
