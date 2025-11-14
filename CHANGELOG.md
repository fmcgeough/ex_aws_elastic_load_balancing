v3.0.0 
* Remove unneeded opts parameter for:
  - `ExAws.ElasticLoadBalancingV2.delete_listener/1`
  - `ExAws.ElasticLoadBalancingV2.modify_load_balancer_attributes/2`
  - `ExAws.ElasticLoadBalancingV2.modify_target_group_attributes/2`
  - `ExAws.ElasticLoadBalancingV2.register_targets/2`
  - `ExAws.ElasticLoadBalancingV2.remove_listener_certificates/2`
  - `ExAws.ElasticLoadBalancingV2.remove_tags/2`
  - `ExAws.ElasticLoadBalancingV2.set_ip_address_type/2`
  - `ExAws.ElasticLoadBalancingV2.set_rule_priorities/1` 
* `ExAws.ElasticLoadBalancingV2.add_trust_store_revocations/2` modified. The parameter `revocation_contents` is not required. The signature of the function was modified to allow passing just `trust_store_arn` as the sole parameter.
* `ExAws.ElasticLoadBalancingV2.create_target_group/2` modified. The 
  parameter `vpc_id` is not required. It can be passed in the optional
  opts parameter if needed.
  Note: The `vpc_id` is the identifier of the virtual private cloud (VPC). If the target is a Lambda function, this parameter does not apply. Otherwise, this parameter is required.
* Added functions:
  - `ExAws.ElasticLoadBalancingV2.describe_trust_store_revocations/2`
  - `ExAws.ElasticLoadBalancingV2.describe_trust_store_associations/2`
  - `ExAws.ElasticLoadBalancingV2.get_resource_policy/1`
  - `ExAws.ElasticLoadBalancingV2.get_trust_store_ca_certificates_bundle/1`
  - `ExAws.ElasticLoadBalancingV2.add_trust_store_revocations/2`

v2.2.2

* Bug Fix: Typespec for target_description modified
* Enhancement: Modify doc tests to make resulting doc more readable

v2.2.1

* Bug Fix: CanonicalHostedZoneId support added to ExAws.ElasticLoadBalancingV2.Parsers
* Enhancement: Switch to main branch
* Enhancement: Use Github Workflows to test with multiple Elixir versions, credo, dialyzer
* Enhancement: Update dependencies

v2.1.1
  * Provide alternative param format for add_tags on v2 to align with classic add_tags

v2.1.0
  * Implement all the other classic load balancer functions

v2.0.2
  * Initial published version to hex.pm
