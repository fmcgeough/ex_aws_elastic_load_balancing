defmodule ExAws.ElasticLoadBalancing.FormatV2Test do
  use ExUnit.Case

  alias ExAws.ElasticLoadBalancing.FormatV2
  alias ExAws.Utils

  test "add_trust_store_revocations_opts" do
    revocation1 = %{revocation_type: "CRL", s3_bucket: "test_bucket"}
    revocation2 = %{revocation_type: "CRL", s3_bucket: "test_bucket2"}

    result = build_result(revocation_contents: [revocation1, revocation2])

    assert %{
             "RevocationContents.member.1.RevocationType" => "CRL",
             "RevocationContents.member.1.S3Bucket" => "test_bucket",
             "RevocationContents.member.2.RevocationType" => "CRL",
             "RevocationContents.member.2.S3Bucket" => "test_bucket2"
           } == result
  end

  test "create_listener_opts" do
    result =
      build_result(
        alpn_policy: ["HTTP1Only", "HTTP2Only"],
        certificates: [%{certificate_arn: "certificate_arn", is_default: true}],
        mutual_authentication: %{
          advertise_trust_store_ca_names: "on",
          ignore_client_certificate_expiry: true,
          mode: "verify",
          trust_store_arn: "trust_store_arn",
          trust_store_association_status: "active"
        },
        port: 65_535,
        protocol: "HTTP",
        ssl_policy: "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
        tags: [%{key: "key1", value: "value1"}, %{key: "key2", value: "value2"}]
      )

    assert %{
             "AlpnPolicy.member.1" => "HTTP1Only",
             "AlpnPolicy.member.2" => "HTTP2Only",
             "Certificates.member.1.CertificateArn" => "certificate_arn",
             "Certificates.member.1.IsDefault" => true,
             "MutualAuthentication.AdvertiseTrustStoreCaNames" => "on",
             "MutualAuthentication.IgnoreClientCertificateExpiry" => true,
             "MutualAuthentication.Mode" => "verify",
             "MutualAuthentication.TrustStoreArn" => "trust_store_arn",
             "MutualAuthentication.TrustStoreAssociationStatus" => "active",
             "Port" => 65_535,
             "Protocol" => "HTTP",
             "SslPolicy" => "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09",
             "Tags.member.1.Key" => "key1",
             "Tags.member.1.Value" => "value1",
             "Tags.member.2.Key" => "key2",
             "Tags.member.2.Value" => "value2"
           } == result
  end

  test "create_load_balancer_opts" do
    result =
      build_result(
        customer_owned_ipv4_pool: "ipv4pool-coip-12345678",
        enable_prefix_for_ipv6_source_nat: "on",
        ip_address_type: "dualstack",
        ipam_pools: [%{ipv4_ipam_pool_id: "ipam-pool-1"}, %{ipv4_ipam_pool_id: "ipam-pool-2"}],
        scheme: "internet-facing",
        security_groups: ["Secure123", "Secure456"],
        subnets: ["1.2.3.4", "5.6.7.8"],
        subnet_mappings: [%{subnet_id: "1.2.3.4", allocation_id: "i2234342"}],
        tags: [%{key: "key1", value: "value1"}, %{key: "key2", value: "value2"}],
        type: "application"
      )

    assert %{
             "CustomerOwnedIpv4Pool" => "ipv4pool-coip-12345678",
             "EnablePrefixForIpv6SourceNat" => "on",
             "IpAddressType" => "dualstack",
             "IpamPools.member.1.Ipv4IpamPoolId" => "ipam-pool-1",
             "IpamPools.member.2.Ipv4IpamPoolId" => "ipam-pool-2",
             "Scheme" => "internet-facing",
             "SecurityGroups.member.1" => "Secure123",
             "SecurityGroups.member.2" => "Secure456",
             "SubnetMappings.member.1.AllocationId" => "i2234342",
             "SubnetMappings.member.1.SubnetId" => "1.2.3.4",
             "Subnets.member.1" => "1.2.3.4",
             "Subnets.member.2" => "5.6.7.8",
             "Tags.member.1.Key" => "key1",
             "Tags.member.1.Value" => "value1",
             "Tags.member.2.Key" => "key2",
             "Tags.member.2.Value" => "value2",
             "Type" => "application"
           } == result
  end

  test "create_rule_opts" do
    result =
      build_result(
        transforms: [
          %{
            type: "url-rewrite",
            url_rewrite_config: [
              rewrites: [%{regex: "test1", replace: "replace1"}, %{regex: "test2", replace: "replace2"}]
            ]
          },
          %{
            type: "host-header-rewrite",
            host_header_rewrite_config: [
              rewrites: [%{regex: "test1", replace: "replace1"}, %{regex: "test2", replace: "replace2"}]
            ]
          }
        ]
      )

    assert %{
             "Transforms.member.1.Type" => "url-rewrite",
             "Transforms.member.1.UrlRewriteConfig.Rewrites.member.1.Regex" => "test1",
             "Transforms.member.1.UrlRewriteConfig.Rewrites.member.1.Replace" => "replace1",
             "Transforms.member.1.UrlRewriteConfig.Rewrites.member.2.Regex" => "test2",
             "Transforms.member.1.UrlRewriteConfig.Rewrites.member.2.Replace" => "replace2",
             "Transforms.member.2.HostHeaderRewriteConfig.Rewrites.member.1.Regex" => "test1",
             "Transforms.member.2.HostHeaderRewriteConfig.Rewrites.member.1.Replace" => "replace1",
             "Transforms.member.2.HostHeaderRewriteConfig.Rewrites.member.2.Regex" => "test2",
             "Transforms.member.2.HostHeaderRewriteConfig.Rewrites.member.2.Replace" => "replace2",
             "Transforms.member.2.Type" => "host-header-rewrite"
           } == result
  end

  test "create_target_group_opts" do
    result =
      build_result(
        health_check_enabled: true,
        health_check_path: "/healthcheck",
        health_check_port: "8080",
        health_check_protocol: "HTTP",
        health_check_timeout_seconds: 5,
        healthy_threshold_count: 3,
        matcher: %{http_code: "200-299"},
        port: 80,
        protocol: "HTTP",
        target_type: "instance",
        unhealthy_threshold_count: 2,
        vpc_id: "vpc-12345678"
      )

    assert %{
             "HealthCheckEnabled" => true,
             "HealthCheckPath" => "/healthcheck",
             "HealthCheckPort" => "8080",
             "HealthCheckProtocol" => "HTTP",
             "HealthCheckTimeoutSeconds" => 5,
             "HealthyThresholdCount" => 3,
             "Matcher.HttpCode" => "200-299",
             "Port" => 80,
             "Protocol" => "HTTP",
             "TargetType" => "instance",
             "UnhealthyThresholdCount" => 2,
             "VpcId" => "vpc-12345678"
           } == result
  end

  test "create_trust_store_opts" do
    result =
      build_result(
        ca_certificates_bundle_s3_object_version: "version1",
        tags: [%{key: "key1", value: "value1"}, %{key: "key2", value: "value2"}]
      )

    assert %{
             "CaCertificatesBundleS3ObjectVersion" => "version1",
             "Tags.member.1.Key" => "key1",
             "Tags.member.1.Value" => "value1",
             "Tags.member.2.Key" => "key2",
             "Tags.member.2.Value" => "value2"
           } == result
  end

  test "describe_account_limits_opts" do
    result = build_result(marker: "marker-abc", page_size: 25)
    assert %{"Marker" => "marker-abc", "PageSize" => 25} == result
  end

  test "describe_listener_certificates_opts" do
    result = build_result(marker: "marker-abc", page_size: 25)
    assert %{"Marker" => "marker-abc", "PageSize" => 25} == result
  end

  test "describe_listeners_opts" do
    result = build_result(listener_arns: ["arn1", "arn2"], load_balancer_arn: "load_balancer_arn")

    assert %{
             "ListenerArns.member.1" => "arn1",
             "ListenerArns.member.2" => "arn2",
             "LoadBalancerArn" => "load_balancer_arn"
           } == result
  end

  test "describe_load_balancers_opts" do
    result =
      build_result(
        load_balancer_arns: ["arn1", "arn2"],
        names: ["name1", "name2"],
        marker: "marker-123",
        page_size: 25
      )

    assert %{
             "LoadBalancerArns.member.1" => "arn1",
             "LoadBalancerArns.member.2" => "arn2",
             "Names.member.1" => "name1",
             "Names.member.2" => "name2",
             "Marker" => "marker-123",
             "PageSize" => 25
           } == result
  end

  test "describe_rules_opts" do
    result =
      build_result(
        listener_arn: "listener-arn-123",
        rule_arns: ["rule-arn-1", "rule-arn-2"],
        marker: "marker-abc",
        page_size: 10
      )

    assert %{
             "ListenerArn" => "listener-arn-123",
             "RuleArns.member.1" => "rule-arn-1",
             "RuleArns.member.2" => "rule-arn-2",
             "Marker" => "marker-abc",
             "PageSize" => 10
           } == result
  end

  defp build_result(opts) do
    opts
    |> Enum.flat_map(&FormatV2.format_param/1)
    |> Utils.filter_nil_params()
  end
end
