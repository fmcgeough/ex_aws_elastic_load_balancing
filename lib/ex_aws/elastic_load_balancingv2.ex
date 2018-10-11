defmodule ExAws.ElasticLoadBalancingV2 do
  @moduledoc """
  Operations on AWS ELB (Elastic Load Balancing) V2 API

  AWS Elastic Load Balancing supports three types of load balancers: Application
  Load Balancers (ALB), Network Load Balancers (NLB), and Classic Load Balancers. You can
  select a load balancer based on your application needs. This API covers the
  ALB and NLB. Classic Load Balancers are covered by the ElasticLoadBalancing module.

  More information:
  * [Elastic Load Balancing User Guide][User_Guide]
  * [Elastic Load Balancing API][API_Doc]
  * [Amazon Resource Names (ARNs)][ARN_Doc]

  [User_Guide]: http://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/
  [API_Doc]: http://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/
  [ARN_Doc]: http://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html
  """

  use ExAws.Utils,
    format_type: :xml,
    non_standard_keys: %{}

  # version of the AWS API
  @version "2015-12-01"

  @type tag :: {key :: atom, value :: binary}
  @type load_balancer_attribute :: {key :: atom, value :: binary}
  @type target_group_attribute :: {key :: atom, value :: binary}

  @type action :: [
          type: binary,
          target_group_arn: binary
        ]

  @type certificate :: [
          certificate_arn: binary,
          is_default: boolean
        ]

  @type target_description :: [
          id: binary,
          port: integer,
          availability_zone: binary
        ]

  @type rule_condition :: [
          field: binary,
          values: [binary, ...]
        ]

  @type subnet_mapping :: [
          subnet_id: binary,
          allocation_id: binary
        ]
  @doc """
  Adds the specified certificate to the specified secure listener.

  If the certificate was already added, the call is successful but the certificate
  is not added again.

  To list the certificates for your listener, use `describe_listener_certificates/1`.
  To remove certificates from your listener, use `remove_listener_certificates/1`.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.add_listener_certificates(
        ...> "listener_arn",
        ...>  [%{certificate_arn: "certificate1_arn", is_default: true},
        ...>   %{certificate_arn: "certificate2_arn"}])
        %ExAws.Operation.Query{action: :add_listener_certificates,
        params: %{"Action" => "AddListenerCertificates",
        "Certificates.member.1.CertificateArn" => "certificate1_arn",
        "Certificates.member.1.IsDefault" => true,
        "Certificates.member.2.CertificateArn" => "certificate2_arn",
        "ListenerArn" => "listener_arn", "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec add_listener_certificates(listener_arn :: binary, certificates :: [certificate, ...]) ::
          ExAws.Operation.Query.t()
  def add_listener_certificates(listener_arn, certificates, opts \\ []) do
    [{:listener_arn, listener_arn}, {:certificates, certificates} | opts]
    |> build_request(:add_listener_certificates)
  end

  @doc """
  Adds the specified tags to the specified Elastic Load Balancing resource.

  You can tag your Application Load Balancers, Network Load Balancers, and your target groups.

  Each tag consists of a key and an optional value. If a resource already has a tag with the same
  key, `add_tags/1` updates its value.

  To list the current tags for your resources, use `describe_tags/1`. To remove tags from
  your resources, use `remove_tags/1`.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.add_tags(["resource_arn1", "resource_arn2"], [hello: "test"])
        %ExAws.Operation.Query{action: :add_tags,
        params: %{"Action" => "AddTags",
        "ResourceArns.member.1" => "resource_arn1",
        "ResourceArns.member.2" => "resource_arn2",
        "Tags.member.1.Key" => "hello", "Tags.member.1.Value" => "test",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

        iex> ExAws.ElasticLoadBalancingV2.add_tags(["resource_arn1", "resource_arn2"], [{:hello, "test"}])
        %ExAws.Operation.Query{action: :add_tags,
        params: %{"Action" => "AddTags",
        "ResourceArns.member.1" => "resource_arn1",
        "ResourceArns.member.2" => "resource_arn2",
        "Tags.member.1.Key" => "hello", "Tags.member.1.Value" => "test",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec add_tags(resource_arns :: [binary, ...], tags :: [tag, ...]) :: ExAws.Operation.Query.t()
  def add_tags(resource_arns, tags, opts \\ []) do
    [{:resource_arns, resource_arns}, {:tags, tags} | opts]
    |> build_request(:add_tags)
  end

  @doc """
  Creates a listener for the specified Application Load Balancer
  or Network Load Balancer.

  You can create up to 10 listeners per load balancer.

  To update a listener, use `modify_listener/1`. When you are finished with a
  listener, you can delete it using `delete_listener/1`. If you are finished
  with both the listener and the load balancer, you can delete them both
  using `delete_load_balancer/1`.

  More information:
  * [Listeners for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html)
  in the *Application Load Balancers Guide*
  * [Listeners for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html)
  in the *Network Load Balancers Guide*

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.create_listener(
        ...> "load_balancer_arn",
        ...> "HTTP", 80, [%{type: "forward", target_group_arn: "target_arn"}])
        %ExAws.Operation.Query{action: :create_listener,
        params: %{"Action" => "CreateListener",
        "DefaultActions.member.1.TargetGroupArn" => "target_arn",
        "DefaultActions.member.1.Type" => "forward",
        "LoadBalancerArn" => "load_balancer_arn", "Port" => 80, "Protocol" => "HTTP",
        "Version" => "2015-12-01"}, parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/",
        service: :elasticloadbalancing}
  """
  @type create_listener_opts :: [
          ssl_policy: binary,
          certificates: [certificate, ...]
        ]
  @spec create_listener(
          load_balancer_arn :: binary,
          protocol :: binary,
          port :: integer,
          default_actions :: [action, ...]
        ) :: ExAws.Operation.Query.t()
  @spec create_listener(
          load_balancer_arn :: binary,
          protocol :: binary,
          port :: integer,
          default_actions :: [action, ...],
          opts :: create_listener_opts
        ) :: ExAws.Operation.Query.t()
  def create_listener(load_balancer_arn, protocol, port, default_actions, opts \\ []) do
    [
      {:load_balancer_arn, load_balancer_arn},
      {:protocol, protocol},
      {:port, port},
      {:default_actions, default_actions} | opts
    ]
    |> build_request(:create_listener)
  end

  @doc """
  Creates an Application Load Balancer or a Network Load Balancer.

  When you create a load balancer, you can specify security groups, subnets,
  IP address type, and tags. Otherwise, you could do so later using set_security_groups,
  set_subnets, set_ip_address_type, and add_tags.

  To create listeners for your load balancer, use `create_listener/1`. To describe your
  current load balancers, see `describe_load_balancer/1`. When you are finished with a
  load balancer, you can delete it using `delete_load_balancer/1`.

  You can create up to 20 load balancers per region per account. You can request an
  increase for the number of load balancers for your account.

  More information:
  * [Limits for Your Application Load Balancer](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
  in the *Application Load Balancers Guide*
  * [Limits for Your Network Load Balancer](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-limits.html)
  in the *Network Load Balancers Guide*

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.create_load_balancer("Loader")
        %ExAws.Operation.Query{action: :create_load_balancer,
        params: %{"Action" => "CreateLoadBalancer",
        "Name" => "Loader",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

        iex> ExAws.ElasticLoadBalancingV2.create_load_balancer("Loader",
        ...> [schema: "internet-facing",
        ...> subnet_mappings: [%{subnet_id: "1.2.3.4", allocation_id: "i2234342"}],
        ...> subnets: ["1.2.3.4", "5.6.7.8"],
        ...> security_groups: ["Secure123", "Secure456"],
        ...> type: "application", ip_address_type: "ipv4"])
        %ExAws.Operation.Query{action: :create_load_balancer,
        params: %{"Action" => "CreateLoadBalancer", "IpAddressType" => "ipv4",
        "Name" => "Loader", "Schema" => "internet-facing",
        "SecurityGroups.member.1" => "Secure123",
        "SecurityGroups.member.2" => "Secure456",
        "SubnetMappings.member.1.AllocationId" => "i2234342",
        "SubnetMappings.member.1.SubnetId" => "1.2.3.4",
        "Subnets.member.1" => "1.2.3.4", "Subnets.member.2" => "5.6.7.8",
        "Type" => "application", "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @type create_load_balancer_opts :: [
          subnets: [binary, ...],
          subnet_mappings: [subnet_mapping, ...],
          security_groups: [binary, ...],
          scheme: binary,
          tags: [tag, ...],
          type: binary,
          ip_address_type: binary
        ]
  @spec create_load_balancer(name :: binary) :: ExAws.Operation.Query.t()
  @spec create_load_balancer(name :: binary, opts :: create_load_balancer_opts) ::
          ExAws.Operation.Query.t()
  def create_load_balancer(name, opts \\ []) do
    [{:name, name} | opts]
    |> build_request(:create_load_balancer)
  end

  @doc """
  Creates a rule for the specified listener.

  The listener must be associated with an Application Load Balancer. Rules are
  evaluated in priority order, from the lowest value to the highest value. When
  the condition for a rule is met, the specified action is taken. If no conditions
  are met, the action for the default rule is taken.

  More information:
  * [Listener Rules](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#listener-rules)
  *Application Load Balancers Guide*

  To view your current rules, use `describe_rules/1`. To update a rule, use
  `modify_rule/1`. To set the priorities of your rules, use `set_rule_priorities/1`.
  To delete a rule, use `delete_rule/1`.
  """
  @spec create_rule(
          listener_arn :: binary,
          conditions :: [rule_condition, ...],
          priority :: integer,
          actions :: [action, ...]
        ) :: ExAws.Operation.Query.t()
  def create_rule(listener_arn, conditions, priority, actions, opts \\ []) do
    [
      {:listener_arn, listener_arn},
      {:conditions, conditions},
      {:priority, priority},
      {:actions, actions} | opts
    ]
    |> build_request(:create_rule)
  end

  @doc """
  Creates a target group.

  To register targets with the target group, use `register_targets/1`. To
  update the health check settings for the target group, use
  `modify_target_group/1`. To monitor the health of targets in the target group,
  use `describe_target_health/1`. To route traffic to the targets in a target group,
  specify the target group in an action using `create_listener/1` or `create_rule/1`.
  To delete a target group, use `delete_target_group/1`.

  More information:
  * [Target Groups for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-target-groups.html)
  in the *Application Load Balancers Guide*
  * [Target Groups for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html)
  in the *Network Load Balancers Guide*.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.create_target_group("target_group_name", "vpc_id")
      %ExAws.Operation.Query{action: :create_target_group,
      params: %{"Action" => "CreateTargetGroup", "Name" => "target_group_name",
        "Version" => "2015-12-01", "VpcId" => "vpc_id"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type create_target_group_opts :: [
          protocol: binary,
          port: integer,
          health_check_protocol: binary,
          health_check_port: binary,
          health_check_path: binary,
          # min 5, max 300
          health_check_interval_seconds: integer,
          # min 2, max 60
          health_check_timeout_seconds: integer,
          healthy_threshold_count: integer,
          # min 2, max 60
          unhealthy_threshold_count: integer,
          matcher: binary,
          target_type: binary
        ]
  @spec create_target_group(name :: binary, vpc_id :: binary) :: ExAws.Operation.Query.t()
  @spec create_target_group(name :: binary, vpc_id :: binary, opts :: create_target_group_opts) ::
          ExAws.Operation.Query.t()
  def create_target_group(name, vpc_id, opts \\ []) do
    [{:name, name}, {:vpc_id, vpc_id} | opts]
    |> build_request(:create_target_group)
  end

  @doc """
  Deletes the specified listener.

  Alternatively, your listener is deleted when you delete the load balancer
  it is attached to using `delete_load_balancer/1`.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_listener("listener_arn")
        %ExAws.Operation.Query{action: :delete_listener,
        params: %{"Action" => "DeleteListener",
        "ListenerArn" => "listener_arn",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec delete_listener(listener_arn :: binary) :: ExAws.Operation.Query.t()
  def delete_listener(listener_arn, opts \\ []) do
    [{:listener_arn, listener_arn} | opts]
    |> build_request(:delete_listener)
  end

  @doc """
  Deletes the specified Application Load Balancer or Network Load Balancer
  and its attached listeners.

  You can't delete a load balancer if deletion protection is enabled.
  If the load balancer does not exist or has already been deleted,
  the call succeeds.

  Deleting a load balancer does not affect its registered targets. For
  example, your EC2 instances continue to run and are still registered
  to their target groups. If you no longer need these EC2 instances,
  you can stop or terminate them.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_load_balancer("load_balancer_arn")
        %ExAws.Operation.Query{action: :delete_load_balancer,
        params: %{"Action" => "DeleteLoadBalancer",
        "LoadBalancerArn" => "load_balancer_arn",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec delete_load_balancer(load_balancer_arn :: binary) :: ExAws.Operation.Query.t()
  def delete_load_balancer(load_balancer_arn, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn} | opts]
    |> build_request(:delete_load_balancer)
  end

  @doc """
  Deletes the specified rule.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_rule("rule_arn")
        %ExAws.Operation.Query{action: :delete_rule,
        params: %{"Action" => "DeleteRule",
        "RuleArn" => "rule_arn",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec delete_rule(rule_arn :: binary) :: ExAws.Operation.Query.t()
  def delete_rule(rule_arn, opts \\ []) do
    [{:rule_arn, rule_arn} | opts]
    |> build_request(:delete_rule)
  end

  @doc """
  Deletes the specified target group.

  You can delete a target group if it is not referenced by any
  actions. Deleting a target group also deletes any associated
  health checks.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.delete_target_group("target_group_arn")
        %ExAws.Operation.Query{action: :delete_target_group,
        params: %{"Action" => "DeleteTargetGroup",
        "TargetGroupArn" => "target_group_arn",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec delete_target_group(target_group_arn :: binary) :: ExAws.Operation.Query.t()
  def delete_target_group(target_group_arn, opts \\ []) do
    [{:target_group_arn, target_group_arn} | opts]
    |> build_request(:delete_target_group)
  end

  @doc """
  Deregisters the specified targets from the specified target group.

  After the targets are deregistered, they no longer receive traffic
  from the load balancer.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.deregister_targets("target_group_arn",
        ...> [%{id: "test", port: 8080, availability_zone: "us-east-1"},
        ...>  %{id: "test2", port: 8088, availability_zone: "us-east-1"}])
        %ExAws.Operation.Query{action: :deregister_targets,
        params: %{"Action" => "DeregisterTargets",
        "TargetGroupArn" => "target_group_arn",
        "Targets.member.1.AvailabilityZone" => "us-east-1",
        "Targets.member.1.Id" => "test", "Targets.member.1.Port" => 8080,
        "Targets.member.2.AvailabilityZone" => "us-east-1",
        "Targets.member.2.Id" => "test2", "Targets.member.2.Port" => 8088,
        "Version" => "2015-12-01"}, parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/",
        service: :elasticloadbalancing}

        iex> ExAws.ElasticLoadBalancingV2.deregister_targets("target_group_arn", [%{id: "i-0f76fade435676abd"}])
        %ExAws.Operation.Query{action: :deregister_targets,
        params: %{"Action" => "DeregisterTargets",
          "TargetGroupArn" => "target_group_arn",
          "Targets.member.1.Id" => "i-0f76fade435676abd", "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @spec deregister_targets(target_group_arn :: binary, targets :: [target_description, ...]) ::
          ExAws.Operation.Query.t()
  def deregister_targets(target_group_arn, targets, opts \\ []) do
    [{:target_group_arn, target_group_arn}, {:targets, targets} | opts]
    |> build_request(:deregister_targets)
  end

  @doc """
  Describes the current Elastic Load Balancing resource limits
  for your AWS account.

  More information:
  * [Limits for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
  in the *Application Load Balancer Guide*
  * [Limits for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-limits.html)
  in the *Network Load Balancers Guide*.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_account_limits()
        %ExAws.Operation.Query{action: :describe_account_limits,
        params: %{"Action" => "DescribeAccountLimits", "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_account_limits_opts :: [
          marker: binary,
          # Minimum value of 1. Maximum value of 400
          page_size: integer
        ]
  @spec describe_account_limits() :: ExAws.Operation.Query.t()
  @spec describe_account_limits(opts :: describe_account_limits_opts) :: ExAws.Operation.Query.t()
  def describe_account_limits(opts \\ []) do
    opts |> build_request(:describe_account_limits)
  end

  @doc """
  Describes the certificates for the specified secure listener.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_listener_certificates("listener_arn");
        %ExAws.Operation.Query{action: :describe_listener_certificates,
        params: %{"Action" => "DescribeListenerCertificates",
        "ListenerArn" => "listener_arn",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_listener_certificates_opts :: [
          marker: binary,
          # Minimum value of 1. Maximum value of 400
          page_size: integer
        ]
  @spec describe_listener_certificates(listener_arn :: binary) :: ExAws.Operation.Query.t()
  @spec describe_listener_certificates(
          listener_arn :: binary,
          opts :: describe_listener_certificates_opts
        ) :: ExAws.Operation.Query.t()
  def describe_listener_certificates(listener_arn, opts \\ []) do
    [{:listener_arn, listener_arn} | opts]
    |> build_request(:describe_listener_certificates)
  end

  @doc """
  Describes the specified listeners or the listeners for the
  specified Application Load Balancer or Network Load Balancer.

  You must specify either a load balancer or one or more listeners.

  ## Example

      iex> ExAws.ElasticLoadBalancingV2.describe_listeners()
      %ExAws.Operation.Query{action: :describe_listeners,
      params: %{"Action" => "DescribeListeners", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_listeners_opts :: [
          listener_arns: [binary, ...],
          load_balancer_arn: binary,
          marker: binary,
          page_size: integer
        ]
  @spec describe_listeners() :: ExAws.Operation.Query.t()
  @spec describe_listeners(opts :: describe_listeners_opts) :: ExAws.Operation.Query.t()
  def describe_listeners(opts \\ []) do
    opts |> build_request(:describe_listeners)
  end

  @doc """
  Describes the attributes for the specified Application Load
  Balancer or Network Load Balancer.

  ## Examples:

        iex> ExAws.ElasticLoadBalancingV2.describe_load_balancer_attributes(
        ...> "load_balancer_arn")
        %ExAws.Operation.Query{action: :describe_load_balancer_attributes,
        params: %{"Action" => "DescribeLoadBalancerAttributes",
        "LoadBalancerArn" => "load_balancer_arn",
        "Version" => "2015-12-01"},
        parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec describe_load_balancer_attributes(load_balancer_arn :: binary) ::
          ExAws.Operation.Query.t()
  def describe_load_balancer_attributes(load_balancer_arn, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn} | opts]
    |> build_request(:describe_load_balancer_attributes)
  end

  @doc """
  Describes the specified load balancers or all of your
  load balancers.

  To describe the listeners for a load balancer, use `describe_listeners/1`.
  To describe the attributes for a load balancer, use `describe_load_balancer_attributes/1`.

  The options that can be passed into `describe_load_balancers/1` allow load_balancer_arns or names
  (there would not be a reason ordinarily to specify both). Elastic Load Balancing provides
  two versions of ARNS (one for Classic and one for Application Load Balancer). The syntax for
  each is below:

  Classic Load Balancer ARN Syntax:

      arn:aws:elasticloadbalancing:region:account-id:loadbalancer/name

  Application Load Balancer ARN Syntax:

      arn:aws:elasticloadbalancing:region:account-id:loadbalancer/app/load-balancer-name/load-balancer-id
      arn:aws:elasticloadbalancing:region:account-id:listener/app/load-balancer-name/load-balancer-id/listener-id
      arn:aws:elasticloadbalancing:region:account-id:listener-rule/app/load-balancer-name/load-balancer-id/listener-id/rule-id
      arn:aws:elasticloadbalancing:region:account-id:targetgroup/target-group-name/target-group-id

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_load_balancers
      %ExAws.Operation.Query{action: :describe_load_balancers,
      params: %{"Action" => "DescribeLoadBalancers", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_load_balancers_opts :: [
          load_balancer_arns: [binary, ...],
          names: [binary, ...],
          marker: binary,
          page_size: integer
        ]
  @spec describe_load_balancers() :: ExAws.Operation.Query.t()
  @spec describe_load_balancers(opts :: describe_load_balancers_opts) :: ExAws.Operation.Query.t()
  def describe_load_balancers(opts \\ []) do
    opts |> build_request(:describe_load_balancers)
  end

  @doc """
  Describes the specified rules or the rules for the specified listener.

  You must specify either a listener or one or more rules.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_rules()
      %ExAws.Operation.Query{action: :describe_rules,
      params: %{"Action" => "DescribeRules", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

      iex> ExAws.ElasticLoadBalancingV2.describe_rules([listener_arn: "listener_arn", rule_arns: ["rule_arns"]])
      %ExAws.Operation.Query{action: :describe_rules,
      params: %{"Action" => "DescribeRules", "ListenerArn" => "listener_arn",
      "RuleArns.member.1" => "rule_arns", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_rules_opts :: [
          listener_arn: binary,
          rule_arns: [binary, ...],
          marker: binary,
          page_size: integer
        ]
  @spec describe_rules() :: ExAws.Operation.Query.t()
  @spec describe_rules(opts :: describe_rules_opts) :: ExAws.Operation.Query.t()
  def describe_rules(opts \\ []) do
    opts |> build_request(:describe_rules)
  end

  @doc """
  Describes the specified policies or all policies used for SSL negotiation.

  More information:
  * [Security Policies](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies)
  in the *Application Load Balancers Guide*.

  ## Examples:

       iex> ExAws.ElasticLoadBalancingV2.describe_ssl_policies()
       %ExAws.Operation.Query{action: :describe_ssl_policies,
       params: %{"Action" => "DescribeSslPolicies", "Version" => "2015-12-01"},
       parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

       iex> ExAws.ElasticLoadBalancingV2.describe_ssl_policies([ssl_policy_names: ["policy1", "policy2"]])
       %ExAws.Operation.Query{action: :describe_ssl_policies,
       params: %{"Action" => "DescribeSslPolicies", "SslPolicyNames.1" => "policy1",
       "SslPolicyNames.2" => "policy2", "Version" => "2015-12-01"},
       parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_ssl_policies_opts :: [
          ssl_policy_names: [binary, ...],
          marker: binary,
          page_size: integer
        ]
  @spec describe_ssl_policies() :: ExAws.Operation.Query.t()
  @spec describe_ssl_policies(opts :: describe_ssl_policies_opts) :: ExAws.Operation.Query.t()
  def describe_ssl_policies(opts \\ []) do
    opts |> build_request(:describe_ssl_policies)
  end

  @doc """
  Describes the tags for the specified resources.

  You can describe the tags for one or more Application Load Balancers,
  Network Load Balancers, and target groups.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_tags(["resource_arn1", "resource_arn2"])
      %ExAws.Operation.Query{action: :describe_tags,
      params: %{"Action" => "DescribeTags", "ResourceArns.member.1" => "resource_arn1",
      "ResourceArns.member.2" => "resource_arn2", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec describe_tags(resource_arns :: [binary, ...]) :: ExAws.Operation.Query.t()
  def describe_tags(resource_arns, opts \\ []) do
    [{:resource_arns, resource_arns} | opts]
    |> build_request(:describe_tags)
  end

  @doc """
  Describes the attributes for the specified target group.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.describe_target_group_attributes(["target_group_arn1", "target_group_arn2"])
      %ExAws.Operation.Query{action: :describe_target_group_attributes,
      params: %{"Action" => "DescribeTargetGroupAttributes",
      "TargetGroupArn.1" => "target_group_arn1",
      "TargetGroupArn.2" => "target_group_arn2", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec describe_target_group_attributes(target_group_arn :: binary) :: ExAws.Operation.Query.t()
  def describe_target_group_attributes(target_group_arn, opts \\ []) do
    [{:target_group_arn, target_group_arn} | opts]
    |> build_request(:describe_target_group_attributes)
  end

  @doc """
   Describes the specified target groups or all of your target groups.

   By default, all target groups are described. Alternatively, you can
   specify one of the following to filter the results: the ARN of the
   load balancer, the names of one or more target groups, or the ARNs
   of one or more target groups. To describe the targets for a
   target group, use `describe_target_health/1`. To describe the attributes
   of a target group, use `describe_target_group_attributes/1`.

   ## Examples:

       iex> ExAws.ElasticLoadBalancingV2.describe_target_groups()
       %ExAws.Operation.Query{action: :describe_target_groups,
       params: %{"Action" => "DescribeTargetGroups", "Version" => "2015-12-01"},
       parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

       iex> ExAws.ElasticLoadBalancingV2.describe_target_groups([load_balancer_arn: "load_balancer_arn",
       ...> target_group_arns: ["target_group_arn1", "target_group_arn2"]])
       %ExAws.Operation.Query{action: :describe_target_groups,
       params: %{"Action" => "DescribeTargetGroups",
         "LoadBalancerArn" => "load_balancer_arn",
         "TargetGroupArns.member.1" => "target_group_arn1",
         "TargetGroupArns.member.2" => "target_group_arn2",
         "Version" => "2015-12-01"}, parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/",
       service: :elasticloadbalancing}
  """
  @type describe_target_groups_opts :: [
          load_balancer_arn: binary,
          target_group_arns: [binary, ...],
          names: [binary, ...],
          marker: binary,
          page_size: integer
        ]
  @spec describe_target_groups() :: ExAws.Operation.Query.t()
  @spec describe_target_groups(opts :: describe_target_groups_opts) :: ExAws.Operation.Query.t()
  def describe_target_groups(opts \\ []) do
    opts |> build_request(:describe_target_groups)
  end

  @doc """
  Describes the health of the specified targets or all of your targets.
  """
  @type describe_target_health_opts :: [
          targets: [target_description, ...]
        ]
  @spec describe_target_health(target_group_arn :: binary) :: ExAws.Operation.Query.t()
  @spec describe_target_health(target_group_arn :: binary, opts :: describe_target_health_opts) ::
          ExAws.Operation.Query.t()
  def describe_target_health(target_group_arn, opts \\ []) do
    [{:target_group_arn, target_group_arn} | opts]
    |> build_request(:describe_target_health)
  end

  @doc """
  Modifies the specified properties of the specified listener.

  Any properties that you do not specify retain their current values.
  However, changing the protocol from HTTPS to HTTP removes the security
  policy and SSL certificate properties. If you change the protocol from
  HTTP to HTTPS, you must add the security policy and server certificate.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.modify_listener("listener_arn")
      %ExAws.Operation.Query{action: :modify_listener,
      params: %{"Action" => "ModifyListener", "ListenerArn" => "listener_arn",
      "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

      iex> ExAws.ElasticLoadBalancingV2.modify_listener("listener_arn",
      ...> [port: 80, protocol: "HTTP", certificates: ["certificate1", "certificate2"]])
      %ExAws.Operation.Query{action: :modify_listener,
      params: %{"Action" => "ModifyListener",
        "Certificates.member.1" => "certificate1",
        "Certificates.member.2" => "certificate2", "ListenerArn" => "listener_arn",
        "Port" => 80, "Protocol" => "HTTP", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type modify_listener_opts :: [
          port: integer,
          protocol: binary,
          ssl_policy: binary,
          certificates: [binary, ...],
          default_actions: [action, ...]
        ]
  @spec modify_listener(listener_arn :: binary) :: ExAws.Operation.Query.t()
  @spec modify_listener(listener_arn :: binary, opts :: modify_listener_opts) ::
          ExAws.Operation.Query.t()
  def modify_listener(listener_arn, opts \\ []) do
    [{:listener_arn, listener_arn} | opts]
    |> build_request(:modify_listener)
  end

  @doc """
  Modifies the specified attributes of the specified Application Load Balancer
  or Network Load Balancer.

  If any of the specified attributes can't be modified as requested, the call
  fails. Any existing attributes that you do not modify retain their current
  values.
  """
  @spec modify_load_balancer_attributes(
          load_balancer_arn :: binary,
          attributes :: [load_balancer_attribute, ...]
        ) :: ExAws.Operation.Query.t()
  def modify_load_balancer_attributes(load_balancer_arn, attributes, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn}, {:attributes, attributes} | opts]
    |> build_request(:modify_load_balancer_attributes)
  end

  @doc """
  Modifies the specified rule.

  Any existing properties that you do not modify retain their current values.
  To modify the default action, use `modify_listener/1`.
  """
  @type modify_rule_opts :: [
          actions: [action, ...],
          conditions: [rule_condition, ...]
        ]
  @spec modify_rule(rule_arn :: binary) :: ExAws.Operation.Query.t()
  @spec modify_rule(rule_arn :: binary, opts :: modify_rule_opts) :: ExAws.Operation.Query.t()
  def modify_rule(rule_arn, opts \\ []) do
    [{:rule_arn, rule_arn} | opts] |> build_request(:modify_rule)
  end

  @doc """
  Modifies the health checks used when evaluating the health state of
  the targets in the specified target group.

  To monitor the health of the targets, use `describe_target_health/1`.

  Examples:

      iex> ExAws.ElasticLoadBalancingV2.modify_target_group("target_group_arn")
      %ExAws.Operation.Query{action: :modify_target_group,
      params: %{"Action" => "ModifyTargetGroup",
        "TargetGroupArn" => "target_group_arn", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

      iex> ExAws.ElasticLoadBalancingV2.modify_target_group("target_group_arn",
      ...> [heath_check_port: 8088, health_check_protocol: "HTTP", health_check_path: "/"])
      %ExAws.Operation.Query{action: :modify_target_group,
      params: %{"Action" => "ModifyTargetGroup", "HealthCheckPath" => "/",
      "HealthCheckProtocol" => "HTTP", "HeathCheckPort" => 8088,
      "TargetGroupArn" => "target_group_arn", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}

  """
  @type modify_target_group_opts :: [
          health_check_protocol: binary,
          health_check_port: binary,
          health_check_path: binary,
          # min 5, max 300
          health_check_interval_seconds: integer,
          # min 2, max 60
          health_check_timeout_seconds: integer,
          # min 2, max 60
          unhealthy_threshold_count: integer,
          matcher: binary
        ]
  @spec modify_target_group(target_group_arn :: binary) :: ExAws.Operation.Query.t()
  @spec modify_target_group(target_group_arn :: binary, opts :: modify_target_group_opts) ::
          ExAws.Operation.Query.t()
  def modify_target_group(target_group_arn, opts \\ []) do
    [{:target_group_arn, target_group_arn} | opts]
    |> build_request(:modify_target_group)
  end

  @doc """
  Modifies the specified attributes of the specified target group.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.modify_target_group_attributes("target_group_arn",
      ...> [{:hello, "test"}])
      %ExAws.Operation.Query{action: :modify_target_group_attributes,
      params: %{"Action" => "ModifyTargetGroupAttributes",
      "Attributes.member.1.Key" => "hello", "Attributes.member.1.Value" => "test",
      "TargetGroupArn" => "target_group_arn", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec modify_target_group_attributes(
          target_group_arn :: binary,
          attributes :: [target_group_attribute, ...]
        ) :: ExAws.Operation.Query.t()
  def modify_target_group_attributes(target_group_arn, attributes, opts \\ []) do
    [{:target_group_arn, target_group_arn}, {:attributes, attributes} | opts]
    |> build_request(:modify_target_group_attributes)
  end

  @doc """
  Registers the specified targets with the specified target group.

  You can register targets by instance ID or by IP address. If the
  target is an EC2 instance, it must be in the `running` state when you
  register it.

  By default, the load balancer routes requests to registered targets using
  the protocol and port for the target group. Alternatively, you can override
  the port for a target when you register it. You can register each EC2
  instance or IP address with the same target group multiple times using
  different ports.

  With a Network Load Balancer, you cannot register instances by instance ID
  if they have the following instance types: C1, CC1, CC2, CG1, CG2, CR1,
  CS1, G1, G2, HI1, HS1, M1, M2, M3, and T1. You can register instances of
  these types by IP address.

  To remove a target from a target group, use `deregister_targets/1`.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.register_targets("target_group_arn", ["target1", "target2"])
      %ExAws.Operation.Query{action: :register_targets,
      params: %{"Action" => "RegisterTargets",
        "TargetGroupArn" => "target_group_arn", "Targets.member.1" => "target1",
        "Targets.member.2" => "target2", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec register_targets(target_group_arn :: binary, targets :: [target_description, ...]) ::
          ExAws.Operation.Query.t()
  def register_targets(target_group_arn, targets, opts \\ []) do
    [{:target_group_arn, target_group_arn}, {:targets, targets} | opts]
    |> build_request(:register_targets)
  end

  @doc """
  Removes the specified certificate from the specified secure listener.

  You can't remove the default certificate for a listener. To replace
  the default certificate, call `modify_listener/1`. To list the certificates
  for your listener, use `describe_listener_certificates/1`.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.remove_listener_certificates("listener_arn",
      ...> [%{certificate_arn: "certificate1_arn", is_default: true}, %{certificate_arn: "certificate2_arn"}])
      %ExAws.Operation.Query{action: :remove_listener_certificates,
      params: %{"Action" => "RemoveListenerCertificates",
      "Certificates.member.1.CertificateArn" => "certificate1_arn",
      "Certificates.member.1.IsDefault" => true,
      "Certificates.member.2.CertificateArn" => "certificate2_arn",
      "ListenerArn" => "listener_arn", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec remove_listener_certificates(listener_arn :: binary, certificates :: [certificate, ...]) ::
          ExAws.Operation.Query.t()
  def remove_listener_certificates(listener_arn, certificates, opts \\ []) do
    [{:listener_arn, listener_arn}, {:certificates, certificates} | opts]
    |> build_request(:remove_listener_certificates)
  end

  @doc """
  Removes the specified tags from the specified Elastic Load Balancing
  resource.

  To list the current tags for your resources, use `describe_tags/1`.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.remove_tags(["resource_arn1", "resource_arn2"], ["tag1", "tag2"])
      %ExAws.Operation.Query{action: :remove_tags,
      params: %{"Action" => "RemoveTags",
      "ResourceArns.member.1" => "resource_arn1", "ResourceArns.member.2" => "resource_arn2",
      "TagsKeys.1" => "tag1", "TagsKeys.2" => "tag2", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec remove_tags(resource_arns :: [binary, ...], tag_keys :: [binary, ...]) ::
          ExAws.Operation.Query.t()
  def remove_tags(resource_arns, tag_keys, opts \\ []) do
    [{:resource_arns, resource_arns}, {:tags_keys, tag_keys} | opts]
    |> build_request(:remove_tags)
  end

  @doc """
  Sets the type of IP addresses used by the subnets of the specified
  Application Load Balancer or Network Load Balancer.

  *Note: Network Load Balancers must use `ipv4`*.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.set_ip_address_type("load_balancer_arn", "ipv4")
      %ExAws.Operation.Query{action: :set_ip_address_type,
      params: %{"Action" => "SetIpAddressType", "IpAddressType" => "ipv4",
      "LoadBalancerArn" => "load_balancer_arn", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec set_ip_address_type(load_balancer_arn :: binary, ip_address_type :: binary) ::
          ExAws.Operation.Query.t()
  def set_ip_address_type(load_balancer_arn, ip_address_type, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn}, {:ip_address_type, ip_address_type} | opts]
    |> build_request(:set_ip_address_type)
  end

  @doc """
  Sets the priorities of the specified rules.

  You can reorder the rules as long as there are no priority conflicts
  in the new order. Any existing rules that you do not specify retain
  their current priority.

  ## Examples:

      iex> ExAws.ElasticLoadBalancingV2.set_rule_priorities([1,2,3])
      %ExAws.Operation.Query{action: :set_rule_priorities,
      params: %{"Action" => "SetRulePriorities", "RulePriorities.member.1" => 1,
      "RulePriorities.member.2" => 2, "RulePriorities.member.3" => 3,
      "Version" => "2015-12-01"}, parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/",
      service: :elasticloadbalancing}
  """
  @spec set_rule_priorities(rule_priorities :: [integer, ...]) :: ExAws.Operation.Query.t()
  def set_rule_priorities(rule_priorities, opts \\ []) do
    [{:rule_priorities, rule_priorities} | opts]
    |> build_request(:set_rule_priorities)
  end

  @doc """
  Associates the specified security groups with the specified Application
  Load Balancer.

  The specified security groups override the previously associated security
  groups.

  *Note: You can't specify a security group for a Network Load Balancer*.

  ## Examples:

      iex>  ExAws.ElasticLoadBalancingV2.set_security_groups("load_balancer_arn", ["security_group1", "security_group2"])
      %ExAws.Operation.Query{action: :set_security_groups,
      params: %{"Action" => "SetSecurityGroups",
        "LoadBalancerArn" => "load_balancer_arn",
        "SecurityGroups.member.1" => "security_group1",
        "SecurityGroups.member.2" => "security_group2", "Version" => "2015-12-01"},
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @spec set_security_groups(load_balancer_arn :: binary, security_groups :: [binary, ...]) ::
          ExAws.Operation.Query.t()
  def set_security_groups(load_balancer_arn, security_groups, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn}, {:security_groups, security_groups} | opts]
    |> build_request(:set_security_groups)
  end

  @doc """
  Enables the Availability Zone for the specified subnets for the specified
  Application Load Balancer.

  The specified subnets replace the previously enabled subnets.

  *Note: You can't change the subnets for a Network Load Balancer*.

  ## Examples:

      iex>  ExAws.ElasticLoadBalancingV2.set_subnets("load_balancer_arn", ["subnet1", "subnet2"])
      %ExAws.Operation.Query{action: :set_subnets,
      params: %{"Action" => "SetSubnets", "LoadBalancerArn" => "load_balancer_arn",
        "Subnets.member.1" => "subnet1", "Subnets.member.2" => "subnet2",
        "Version" => "2015-12-01"}, parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2, path: "/",
      service: :elasticloadbalancing}
  """
  @type set_subnets_opts :: [
          subnet_mappings: [subnet_mapping, ...]
        ]
  @spec set_subnets(load_balancer_arn :: binary, subnets :: [binary, ...]) ::
          ExAws.Operation.Query.t()
  @spec set_subnets(
          load_balancer_arn :: binary,
          subnets :: [binary, ...],
          opts :: set_subnets_opts
        ) :: ExAws.Operation.Query.t()
  def set_subnets(load_balancer_arn, subnets, opts \\ []) do
    [{:load_balancer_arn, load_balancer_arn}, {:subnets, subnets} | opts]
    |> build_request(:set_subnets)
  end

  ####################
  # Helper Functions #
  ####################

  defp build_request(opts, action) do
    opts
    |> Enum.flat_map(&format_param/1)
    |> request(action)
  end

  defp request(params, action) do
    action_string = action |> Atom.to_string() |> Macro.camelize()

    %ExAws.Operation.Query{
      path: "/",
      params:
        params
        |> filter_nil_params
        |> Map.put("Action", action_string)
        |> Map.put("Version", @version),
      service: :elasticloadbalancing,
      action: action,
      parser: &ExAws.ElasticLoadBalancingV2.Parsers.parse/2
    }
  end

  defp format_param({:actions, actions}) do
    actions |> format(prefix: "Actions.member")
  end

  defp format_param({:attributes, attributes}) do
    attributes
    |> Enum.map(fn {key, value} -> [key: maybe_stringify(key), value: value] end)
    |> format(prefix: "Attributes.member")
  end

  defp format_param({:certificates, certificates}) do
    certificates |> format(prefix: "Certificates.member")
  end

  defp format_param({:conditions, conditions}) do
    conditions |> format(prefix: "Conditions.member")
  end

  defp format_param({:default_actions, actions}) do
    actions |> format(prefix: "DefaultActions.member")
  end

  defp format_param({:listener_arns, listener_arns}) do
    listener_arns |> format(prefix: "ListenerArns.member")
  end

  defp format_param({:load_balancer_arns, load_balancer_arns}) do
    load_balancer_arns |> format(prefix: "LoadBalancerArns.member")
  end

  defp format_param({:names, names}) do
    names |> format(prefix: "Names.member")
  end

  defp format_param({:resource_arns, resource_arns}) do
    resource_arns |> format(prefix: "ResourceArns.member")
  end

  defp format_param({:rule_arns, rule_arns}) do
    rule_arns |> format(prefix: "RuleArns.member")
  end

  defp format_param({:rule_priorities, rule_priorities}) do
    rule_priorities |> format(prefix: "RulePriorities.member")
  end

  defp format_param({:security_groups, security_groups}) do
    security_groups |> format(prefix: "SecurityGroups.member")
  end

  defp format_param({:subnets, subnets}) do
    subnets |> format(prefix: "Subnets.member")
  end

  defp format_param({:subnet_mappings, subnet_mappings}) do
    subnet_mappings |> format(prefix: "SubnetMappings.member")
  end

  defp format_param({:tags, tags}) do
    tags
    |> Enum.map(fn {key, value} -> [key: maybe_stringify(key), value: value] end)
    |> format(prefix: "Tags.member")
  end

  defp format_param({:tag_keys, tag_keys}) do
    tag_keys |> format(prefix: "TagKeys.member")
  end

  defp format_param({:targets, targets}) do
    targets |> format(prefix: "Targets.member")
  end

  defp format_param({:target_group_arns, target_group_arns}) do
    target_group_arns |> format(prefix: "TargetGroupArns.member")
  end

  defp format_param({key, parameters}) do
    format([{key, parameters}])
  end
end
