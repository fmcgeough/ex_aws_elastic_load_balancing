if Code.ensure_loaded?(SweetXml) do
  defmodule ExAws.ElasticLoadBalancing.Parsers do
    use ExAws.Operation.Query.Parser

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancers) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancersResponse",
          load_balancers: load_balancers_xml_description(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s,
          next_marker: ~x"./DescribeLoadBalancersResult/NextMarker/text()"s
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

    def parse({:ok, %{body: xml} = resp}, :describe_account_limits) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeAccountLimitsResponse",
          limits: account_limits_xml(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_instance_health) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeInstanceHealthResponse",
          instance_states: instances_health_xml(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancer_attributes) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancerAttributesResponse",
          attributes: attributes_xml(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancer_policies) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancerPoliciesResponse",
          attributes: balancer_policies_xml(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse({:ok, %{body: xml} = resp}, :describe_load_balancer_policy_types) do
      parsed_body =
        xml
        |> SweetXml.xpath(
          ~x"//DescribeLoadBalancerPolicyTypesResponse",
          attributes: policy_types_xml(),
          request_id: ~x"./ResponseMetadata/RequestId/text()"s
        )

      {:ok, Map.put(resp, :body, parsed_body)}
    end

    def parse(val, _), do: val

    defp policy_types_xml do
      [
        ~x"./DescribeLoadBalancerPolicyTypesResult/PolicyTypeDescriptions/member"l,
        description: ~x"./Description/text()"s,
        policy_type_name: ~x"./PolicyTypeName/text()"s,
        policy_attribute_descriptions: [
          ~x"./PolicyAttributeTypeDescriptions/member"l,
          atttribute_name: ~x"./AttributeName/text()"s,
          attribute_type: ~x"./AttributeType/text()"s,
          cardinality: ~x"./Cardinality/text()"s
        ]
      ]
    end

    defp balancer_policies_xml do
      [
        ~x"./DescribeLoadBalancerPoliciesResult/PolicyDescriptions/member"l,
        policy_type_name: ~x"./PolicyTypeName/text()"s,
        attribute_descriptions: [
          ~x"./PolicyAttributeDescriptions/member"l,
          attribute_value: ~x"./AttributeValue/text()"s,
          attribute_name: ~x"./AttributeName/text()"s
        ]
      ]
    end

    defp attributes_xml do
      [
        ~x"./DescribeLoadBalancerAttributesResult/LoadBalancerAttributes"l,
        connection_settings_idle_timeout: ~x"./ConnectionSettings/IdleTimeout/text()"s,
        cross_zone_load_balancing_enabled: ~x"./CrossZoneLoadBalancing/Enabled/text()"s,
        connection_draining_enabled: ~x"./ConnectionDraining/Enabled/text()"s,
        connection_draining_timeout: ~x"./ConnectionDraining/Timeout/text()"i,
        access_log_emit_interval: ~x"./AccessLog/EmitInterval/text()"i,
        access_log_enabled: ~x"./AccessLog/Enabled/text()"s,
        access_log_s3_bucket_prefix: ~x"./AccessLog/S3BucketPrefix/text()"s,
        access_log_s3_bucket_name: ~x"./AccessLog/S3BucketName/text()"s
      ]
    end

    defp account_limits_xml do
      [
        ~x"./DescribeAccountLimitsResult/Limits/member"l,
        name: ~x"./Name/text()"s,
        max: ~x"./Max/text()"i
      ]
    end

    defp instances_health_xml do
      [
        ~x"./DescribeInstanceHealthResult/InstanceStates/member"l,
        description: ~x"./Description/text()"s,
        instance_id: ~x"./InstanceId/text()"s,
        state: ~x"./State/text()"s,
        reason_code: ~x"./ReasonCode/text()"s
      ]
    end

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
          other_policies: ~x"./OtherPolicies/member/text()"ls
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
            ~x"./PolicyNames/member/text()"ls
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

    defp load_balancer_tags_description() do
      [
        ~x"./DescribeTagsResult/TagDescriptions/member"l,
        load_balancer_name: ~x"./LoadBalancerName/text()"s,
        tags: [
          ~x"./Tags/member"l,
          key: ~x"./Key/text()"s,
          value: ~x"./Value/text()"s
        ]
      ]
    end
  end
else
  defmodule ExAws.ElasticLoadBalancing.Parsers do
    def parse(val, _), do: val
  end
end
