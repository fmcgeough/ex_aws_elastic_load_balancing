if Code.ensure_loaded?(SweetXml) do
  defmodule ExAws.ElasticLoadBalancing.Parsers do
    use ExAws.Operation.Query.Parser

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancers) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancersResponse",
          load_balancers: load_balancers_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )
      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse(val, _), do: val

    defp load_balancers_xml_description do
      [
        ~x"./DescribeLoadBalancersResult/LoadBalancerDescriptions/member"l,
        load_balancer_name: ~x"./LoadBalancerName/text()"s,
        dns_name: ~x"./DNSName/text()"s,
        canonical_hosted_zone_name: ~x"./CanonicalHostedZoneName/text()"s,
        canonical_hosted_zone_name_id: ~x"./CanonicalHostedZoneNameID/text()"s,
        availability_zones: ~x"./AvailabilityZones/member/text()"ls,
        vpc_id: ~x"./VPCId/text()"s,
        instances: ~x"./Instances/member/InstanceId/text()"ls,
        security_groups: ~x"./SecurityGroups/member/text()"ls,
        created_time: ~x"./CreatedTime/text()"s,
        scheme: ~x"./Scheme/text()"s,
        policies: [
          ~x"./Policies",
          app_cookie_stickiness_policies: [
            ~x"./AppCookieStickinessPolicies/member"l,
            policy_name: ~x"./PolicyName/text()"s,
            cookie_name: ~x"./CookieName/text()"s
          ],
          lb_cookie_stickiness_policies: [
            ~x"./LBCookieStickinessPolicies/member"l,
            policy_name: ~x"./PolicyName/text()"s,
            cookie_expiration_period: ~x"./CookieExpirationPeriod/text()"i
          ],
          other_policies: ~x"./OtherPolicies/member/text()"ls,
        ],
        source_security_group: [
          ~x"./SourceSecurityGroup",
          owner_alias: ~x"./OwnerAlias/text()"s,
          group_name: ~x"./GroupName/text()"s
        ],
        listener_descriptions: [
          ~x"./ListenerDescriptions/member"l,
          listener: [
            ~x"./Listener",
            instance_port: ~x"./InstancePort/text()"i,
            instance_protocol: ~x"./InstanceProtocol/text()"s,
            protocol: ~x"./Protocol/text()"s,
            load_balancer_port: ~x"./LoadBalancerPort/text()"i
          ],
          policy_names: [
            ~x"./PolicyNames/member/text()"ls,
          ]
        ],
        health_check: [
          ~x"./HealthCheck",
          unhealthy_threshold: ~x"./UnhealthyThreshold/text()"i,
          interval: ~x"./Interval/text()"i,
          healthy_threshold: ~x"./HealthyThreshold/text()"i,
          timeout: ~x"./Timeout/text()"i,
          target: ~x"./Target/text()"s
        ],
        subnets: ~x"./Subnets/member/text()"ls
      ]
    end

  end
else
  defmodule ExAws.Cloudwatch.Parsers do
    def parse(val, _), do: val
  end
end