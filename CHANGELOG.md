v3.0.0 
* Add function add_trust_store_revocations to ElasticLoadBalancingV2
* Remove opts parameter for delete_listener, set_rule_priorities, modify_target_group_attributes, register_targets, remove_listener_certificates, remove_tags, set_ip_address_type, modify_load_balancer_attributes in ElasticLoadBalancingV2. Unneeded.
* add_trust_store_revocations in ElasticLoadBalancingV2 modified. The parameter `revocation_contents` is not required. The signature of the function was modified to allow passing just `trust_store_arn` as the sole parameter.

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
