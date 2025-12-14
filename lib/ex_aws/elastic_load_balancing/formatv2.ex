defmodule ExAws.ElasticLoadBalancing.FormatV2 do
  @moduledoc false

  import ExAws.Utils, only: [maybe_stringify: 1, format: 2, format: 1]

  def format_param({:actions, actions}) do
    actions |> format(prefix: "Actions.member")
  end

  def format_param({:attributes, attributes}) do
    attributes
    |> Enum.map(&normalize_tag_or_attribute/1)
    |> format(prefix: "Attributes.member")
  end

  def format_param({:alpn_policy, alpn_policies}) do
    alpn_policies |> format(prefix: "AlpnPolicy.member")
  end

  def format_param({:certificates, certificates}) do
    certificates |> format(prefix: "Certificates.member")
  end

  def format_param({:conditions, conditions}) do
    conditions |> format(prefix: "Conditions.member")
  end

  def format_param({:default_actions, actions}) do
    actions |> format(prefix: "DefaultActions.member")
  end

  def format_param({:listener_arns, listener_arns}) do
    listener_arns |> format(prefix: "ListenerArns.member")
  end

  def format_param({:load_balancer_arns, load_balancer_arns}) do
    load_balancer_arns |> format(prefix: "LoadBalancerArns.member")
  end

  def format_param({key, names}) when key in [:names, :ssl_policy_names] do
    names |> format(prefix: "Names.member")
  end

  def format_param({:trust_store_arns, trust_store_arns}) do
    trust_store_arns |> format(prefix: "TrustStoreArns.member")
  end

  def format_param({:resource_arns, resource_arns}) do
    resource_arns |> format(prefix: "ResourceArns.member")
  end

  def format_param({:rewrites, rewrites}) do
    rewrites |> format(prefix: "Rewrites.member")
  end

  def format_param({:rule_arns, rule_arns}) do
    rule_arns |> format(prefix: "RuleArns.member")
  end

  def format_param({:rule_priorities, rule_priorities}) do
    rule_priorities |> format(prefix: "RulePriorities.member")
  end

  def format_param({:security_groups, security_groups}) do
    security_groups |> format(prefix: "SecurityGroups.member")
  end

  def format_param({:subnets, subnets}) do
    subnets |> format(prefix: "Subnets.member")
  end

  def format_param({:subnet_mappings, subnet_mappings}) do
    subnet_mappings |> format(prefix: "SubnetMappings.member")
  end

  def format_param({:regex_values, regex_values}) do
    regex_values |> format(prefix: "RegexValues.member")
  end

  def format_param({:values, values}) do
    values |> format(prefix: "Values.member")
  end

  def format_param({:transforms, transforms}) do
    Enum.map(transforms, fn transform ->
      normalize_transform(transform)
    end)
    |> format(prefix: "Transforms.member")
  end

  def format_param({:tags, tags}) do
    tags
    |> Enum.map(&normalize_tag_or_attribute/1)
    |> format(prefix: "Tags.member")
  end

  def format_param({:tag_keys, tag_keys}) do
    tag_keys |> format(prefix: "TagKeys.member")
  end

  def format_param({:targets, targets}) do
    targets |> format(prefix: "Targets.member")
  end

  def format_param({:target_group_arns, target_group_arns}) do
    target_group_arns |> format(prefix: "TargetGroupArns.member")
  end

  def format_param({:revocation_contents, revocation_contents}) do
    revocation_contents |> format(prefix: "RevocationContents.member")
  end

  def format_param({:revocation_ids, revocation_ids}) do
    revocation_ids |> format(prefix: "RevocationIds.member")
  end

  def format_param({:trust_store_arn, trust_store_arn}) do
    %{"TrustStoreArn" => trust_store_arn}
  end

  def format_param({:ipam_pools, ipam_pools}) do
    ipam_pools |> format(prefix: "IpamPools.member")
  end

  def format_param({:remove_ipam_pools, remove_ipam_pools}) do
    remove_ipam_pools |> format(prefix: "RemoveIpamPools.member")
  end

  def format_param({:include, include}) do
    include |> format(prefix: "Include.member")
  end

  def format_param({key, parameters}) do
    format([{key, parameters}])
  end

  def normalize_tag_or_attribute(val) when is_tuple(val) do
    {key, value} = val
    %{key: maybe_stringify(key), value: value}
  end

  def normalize_tag_or_attribute(val), do: val

  def normalize_transform(%{url_rewrite_config: url_rewrite_config} = transform) do
    val = Enum.flat_map(url_rewrite_config, &format_param/1)
    Map.put(transform, :url_rewrite_config, val)
  end

  def normalize_transform(%{host_header_rewrite_config: host_header_rewrite_config} = transform) do
    val = Enum.flat_map(host_header_rewrite_config, &format_param/1)
    Map.put(transform, :host_header_rewrite_config, val)
  end

  def normalize_transform(transform), do: transform
end
