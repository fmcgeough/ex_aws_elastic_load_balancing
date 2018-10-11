if Code.ensure_loaded?(SweetXml) do
  defmodule ExAws.ElasticLoadBalancingV2.Parsers do
    use ExAws.Operation.Query.Parser

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancers) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancersResponse",
          load_balancers: load_balancers_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s,
          next_marker: ~x"./DescribeLoadBalancersResult/NextMarker/text()"S
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_tags) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeTagsResponse",
          tag_descriptions: load_balancer_tags_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_target_groups) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeTargetGroupsResponse",
          target_groups: target_groups_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s,
          next_marker: ~x"./DescribeTargetGroupsResult/NextMarker/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_target_health) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeTargetHealthResponse",
          target_health_descriptions: target_health_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_account_limits) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeAccountLimitsResponse",
          account_limits: account_limits_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancer_attributes) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancerAttributesResponse",
          attributes: describe_load_balancer_attribute_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :modify_load_balancer_attributes) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//ModifyLoadBalancerAttributesResponse",
          attributes: modify_load_balancer_attribute_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :register_targets) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//RegisterTargetsResponse",
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :deregister_targets) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DeregisterTargetsResponse",
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse(val, _), do: val

    defp load_balancers_xml_description do
      [
        ~x"./DescribeLoadBalancersResult/LoadBalancers/member"l,
        load_balancer_name: ~x"./LoadBalancerName/text()"s,
        dns_name: ~x"./DNSName/text()"s,
        canonical_hosted_zone_name: ~x"./CanonicalHostedZoneName/text()"s,
        canonical_hosted_zone_name_id: ~x"./CanonicalHostedZoneNameID/text()"s,
        availability_zones: [
          ~x"./AvailabilityZones/member"l,
          subnet_id: ~x"./SubnetId/text()"s,
          zone_name: ~x"./ZoneName/text()"s
        ],
        vpc_id: ~x"./VpcId/text()"s,
        instances: [
          ~x"./Instances/member"l,
          instance_id: ~x"./InstanceId/text()"s
        ],
        security_groups: ~x"./SecurityGroups/member/text()"ls,
        created_time: ~x"./CreatedTime/text()"s,
        scheme: ~x"./Scheme/text()"s,
        load_balancer_arn: ~x"./LoadBalancerArn/text()"s
      ]
    end

    defp load_balancer_tags_description do
      [
        ~x"./DescribeTagsResult/TagDescriptions/member"l,
        resource_arn: ~x"./ResourceArn/text()"s,
        tags: [
          ~x"./Tags/member"l,
          key: ~x"./Key/text()"s,
          value: ~x"./Value/text()"s
        ]
      ]
    end

    def target_groups_xml_description do
      [
        ~x"./DescribeTargetGroupsResult/TargetGroups/member"l,
        target_group_arn: ~x"./TargetGroupArn/text()"s,
        health_check_timeout_secs: ~x"./HealthCheckTimeoutSeconds/text()"s,
        health_check_port: ~x"./HealthCheckPort/text()"s,
        target_type: ~x"./TargetType/text()"s,
        http_code: ~x"./Matcher/HttpCode/text()"s,
        target_group_name: ~x"./TargetGroupName/text()"s,
        health_check_protocol: ~x"./HealthCheckProtocol/text()"s,
        health_check_path: ~x"./HealthCheckPath/text()"s,
        protocol: ~x"./Protocol/text()"s,
        port: ~x"./Port/text()"s,
        vpc_id: ~x"./VpcId/text()"s,
        healthy_threshold_count: ~x"./HealthyThresholdCount/text()"s,
        healthy_inteval_seconds: ~x"./HealthCheckIntervalSeconds/text()"s,
        load_balancer_arn: ~x"./LoadBalancerArns/member/text()"s,
        unhealthy_threshold_count: ~x"./UnhealthyThresholdCount/text()"s
      ]
    end

    defp target_health_xml_description do
      [
        ~x"./DescribeTargetHealthResult/TargetHealthDescriptions/member"l,
        health_check_port: ~x"./HealthCheckPort/text()"s,
        target_health: ~x"./TargetHealth/State/text()"s,
        targets: [
          ~x"./Target"l,
          port: ~x"./Port/text()"s,
          availability_zone: ~x"./AvailabilityZone/text()"s,
          id: ~x"./Id/text()"s
        ]
      ]
    end

    defp account_limits_xml_description do
      [
        ~x"./DescribeAccountLimitsResult/Limits/member"l,
        name: ~x"./Name/text()"s,
        max: ~x"./Max/text()"s
      ]
    end

    defp describe_load_balancer_attribute_xml_description do
      [
        ~x"./DescribeLoadBalancerAttributesResult/Attributes/member"l,
        key: ~x"./Key/text()"s,
        value: ~x"./Value/text()"s
      ]
    end

    defp modify_load_balancer_attribute_xml_description do
      [
        ~x"./ModifyLoadBalancerAttributesResult/Attributes/member"l,
        key: ~x"./Key/text()"s,
        value: ~x"./Value/text()"s
      ]
    end
  end
else
  defmodule ExAws.ElasticLoadBalancingV2.Parsers do
    def parse(val, _), do: val
  end
end
