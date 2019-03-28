defmodule ExAws.ElasticLoadBalancingTest do
  use ExUnit.Case
  doctest ExAws.ElasticLoadBalancing

  test "modify_load_balancer_attributes Enable Cross-Zone Load Balancing" do
    op =
      ExAws.ElasticLoadBalancing.modify_load_balancer_attributes("mylb",
        cross_zone_load_balancing_enabled: true
      )

    assert op == %ExAws.Operation.Query{
             action: :modify_load_balancer_attributes,
             params: %{
               "Action" => "ModifyLoadBalancerAttributes",
               "LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled" => true,
               "LoadBalancerName" => "mylb",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "modify_load_balancer_attributes Enable Access Logs" do
    op =
      ExAws.ElasticLoadBalancing.modify_load_balancer_attributes("mylb",
        access_log_enabled: true,
        access_log_s3_bucket_name: "my-loadbalancer-logs",
        access_log_s3_bucket_prefix: "my-bucket-prefix/prod",
        access_log_emit_interval: 60
      )

    assert op == %ExAws.Operation.Query{
             action: :modify_load_balancer_attributes,
             params: %{
               "Action" => "ModifyLoadBalancerAttributes",
               "LoadBalancerAttributes.AccessLog.EmitInterval" => 60,
               "LoadBalancerAttributes.AccessLog.Enabled" => true,
               "LoadBalancerAttributes.AccessLog.S3BucketName" => "my-loadbalancer-logs",
               "LoadBalancerAttributes.AccessLog.S3BucketPrefix" => "my-bucket-prefix/prod",
               "LoadBalancerName" => "mylb",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "modify_load_balancer_attributes Enable Connection Draining" do
    op =
      ExAws.ElasticLoadBalancing.modify_load_balancer_attributes("mylb",
        connection_draining_enabled: true,
        connection_draining_timeout: 60
      )

    assert op == %ExAws.Operation.Query{
             action: :modify_load_balancer_attributes,
             params: %{
               "Action" => "ModifyLoadBalancerAttributes",
               "LoadBalancerAttributes.ConnectionDraining.Enabled" => true,
               "LoadBalancerAttributes.ConnectionDraining.Timeout" => 60,
               "LoadBalancerName" => "mylb",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "modify_load_balancer_attributes Configure Idle Timeout" do
    op =
      ExAws.ElasticLoadBalancing.modify_load_balancer_attributes("mylb",
        connection_settings_idle_timeout: 60
      )

    assert op == %ExAws.Operation.Query{
             action: :modify_load_balancer_attributes,
             params: %{
               "Action" => "ModifyLoadBalancerAttributes",
               "LoadBalancerAttributes.ConnectionSettings.IdleTimeout" => 60,
               "LoadBalancerName" => "mylb",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "Create a Load Balancer in EC2-Classic" do
    listener = %{
      instance_port: 80,
      instance_protocol: "http",
      load_balancer_port: 80,
      protocol: "http"
    }

    op =
      ExAws.ElasticLoadBalancing.create_load_balancer("mylb", [listener],
        availability_zones: ["us-east-1"]
      )

    assert op == %ExAws.Operation.Query{
             action: :create_load_balancer,
             params: %{
               "Action" => "CreateLoadBalancer",
               "AvailabilityZones.member.1" => "us-east-1",
               "Listeners.member.1.InstancePort" => 80,
               "Listeners.member.1.InstanceProtocol" => "http",
               "Listeners.member.1.LoadBalancerPort" => 80,
               "Listeners.member.1.Protocol" => "http",
               "LoadBalancerName" => "mylb",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "Create an HTTPS Load Balancer in EC2-Classic" do
    listener = %{
      instance_port: 443,
      instance_protocol: "https",
      load_balancer_port: 443,
      protocol: "https",
      ssl_certificate_id: "arn:aws:iam::123456789012"
    }

    op =
      ExAws.ElasticLoadBalancing.create_load_balancer("mylb", [listener],
        availability_zones: ["us-east-1c"]
      )

    assert op == %ExAws.Operation.Query{
             action: :create_load_balancer,
             params: %{
               "Action" => "CreateLoadBalancer",
               "AvailabilityZones.member.1" => "us-east-1c",
               "Listeners.member.1.InstancePort" => 443,
               "Listeners.member.1.InstanceProtocol" => "https",
               "Listeners.member.1.LoadBalancerPort" => 443,
               "Listeners.member.1.Protocol" => "https",
               "Listeners.member.1.SSLCertificateId" => "arn:aws:iam::123456789012",
               "LoadBalancerName" => "mylb",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "Create a Load Balancer in a VPC" do
    listener = %{
      instance_port: 80,
      instance_protocol: "http",
      load_balancer_port: 80,
      protocol: "http"
    }

    op =
      ExAws.ElasticLoadBalancing.create_load_balancer("mylb", [listener],
        subnets: ["subnet-6dec9f03"],
        security_groups: ["sg-6801da07"]
      )

    assert op == %ExAws.Operation.Query{
             action: :create_load_balancer,
             params: %{
               "Action" => "CreateLoadBalancer",
               "Listeners.member.1.InstancePort" => 80,
               "Listeners.member.1.InstanceProtocol" => "http",
               "Listeners.member.1.LoadBalancerPort" => 80,
               "Listeners.member.1.Protocol" => "http",
               "LoadBalancerName" => "mylb",
               "SecurityGroups.member.1" => "sg-6801da07",
               "Subnets.member.1" => "subnet-6dec9f03",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end

  test "Create an Internal Load Balancer" do
    listener = %{
      instance_port: 80,
      instance_protocol: "http",
      load_balancer_port: 80,
      protocol: "http"
    }

    op =
      ExAws.ElasticLoadBalancing.create_load_balancer("mylb", [listener],
        subnets: ["subnet-9edc97f0"],
        security_groups: ["sg-706cb61f"],
        scheme: "internal"
      )

    assert op == %ExAws.Operation.Query{
             action: :create_load_balancer,
             params: %{
               "Action" => "CreateLoadBalancer",
               "Listeners.member.1.InstancePort" => 80,
               "Listeners.member.1.InstanceProtocol" => "http",
               "Listeners.member.1.LoadBalancerPort" => 80,
               "Listeners.member.1.Protocol" => "http",
               "LoadBalancerName" => "mylb",
               "Scheme" => "internal",
               "SecurityGroups.member.1" => "sg-706cb61f",
               "Subnets.member.1" => "subnet-9edc97f0",
               "Version" => "2012-06-01"
             },
             parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
             path: "/",
             service: :elasticloadbalancing
           }
  end
end
