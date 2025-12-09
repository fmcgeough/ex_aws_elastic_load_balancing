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

  defp build_result(opts) do
    opts
    |> Enum.flat_map(&FormatV2.format_param/1)
    |> Utils.filter_nil_params()
  end
end
