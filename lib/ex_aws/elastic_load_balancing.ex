defmodule ExAws.ElasticLoadBalancing do
  @moduledoc """
  Operations on AWS ElasticLoadBalancing

  AWS ElasticLoadBalancing provides a reliable, scalable, and flexible monitoring solution
  for your AWS resources. This module provides functionality for only classic load balancers.
  See `ExAws.ElasticLoadBalancingV2` for the API for application and network load balancers.

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
    non_standard_keys: %{ssl_certificate_id: "SSLCertificateId"}

  # version of the AWS API
  @version "2012-06-01"

  @type tag :: %{key: binary, value: binary}
  @type tag_key_only :: %{key: binary}

  @type describe_account_limits_opts :: [
          marker: binary,
          # Minimum value of 1. Maximum value of 400
          page_size: integer
        ]
  @type instance :: %{instance_id: binary}
  @type describe_instance_health_opts :: [
          instances: [instance, ...]
        ]
  @type describe_load_balancers_opts :: [
          load_balancer_names: [binary, ...],
          starting_token: binary,
          max_items: integer,
          page_size: integer
        ]

  @type describe_load_balancer_policies_opts :: [
          load_balancer_name: binary,
          policy_names: [binary, ...]
        ]

  @type describe_load_balancer_policy_types_opts :: [
          policy_type_names: [binary, ...]
        ]

  @type load_balancer_attribute :: [
          connection_settings_idle_timeout: binary,
          cross_zone_load_balancing_enabled: binary,
          connection_draining_enabled: boolean,
          connection_draining_timeout: integer,
          access_log_emit_interval: integer,
          access_log_enabled: boolean,
          access_log_s3_bucket_prefix: binary,
          access_log_s3_bucket_name: binary
        ]

  @type health_check :: %{
          healthy_threshold: integer,
          interval: integer,
          target: binary,
          timeout: integer,
          unhealthy_threshold: integer
        }

  @type listener :: %{
          instance_port: integer,
          instance_protocol: binary,
          load_balancer_port: integer,
          protocol: binary,
          ssl_certificate_id: binary
        }

  @type policy_attribute :: %{
          attribute_name: binary,
          attribute_value: binary
        }

  @type create_load_balancer_policy_opts :: [
          policy_attributes: [policy_attribute, ...]
        ]

  @type create_load_balancer_opts :: [
          availability_zones: [binary, ...],
          scheme: binary,
          security_groups: [binary, ...],
          subnets: [binary, ...],
          tags: [tag, ...]
        ]

  @doc """
  Adds the specified tags to the specified load balancer. Each load balancer can have a
  maximum of 10 tags

  Each tag consists of a key and an optional value. If a tag with the same key is already
  associated with the load balancer, `add_tags/2` updates its value.

  For more information, see [Tag Your Classic Load Balancer in the Classic Load Balancers
  Guide](https://amzn.to/2Ou2dCS).

  ## Parameters:

    * load_balancer_names (`List` of `String`) - The name of the load balancer. You can specify
    one load balancer only

    * tags (`List` of `t:tag/0`) - the tags to apply to the specified balancer

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.add_tags(["classic1"], [%{key: "Hello", value: "test"}])
      %ExAws.Operation.Query{
        action: :add_tags,
        params: %{
          "Action" => "AddTags",
          "LoadBalancerNames.member.1" => "classic1",
          "Tags.member.1.Key" => "Hello",
          "Tags.member.1.Value" => "test",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec add_tags(load_balancer_names :: [binary, ...], tags :: [tag, ...]) ::
          ExAws.Operation.Query.t()
  def add_tags(load_balancer_names, tags) do
    [{:load_balancer_names, load_balancer_names}, {:tags, tags}]
    |> build_request(:add_tags)
  end

  @doc """
  Associates one or more security groups with your load balancer in a virtual private cloud (VPC)

  The specified security groups override the previously associated security groups.
  For more information, see [Security Groups for Load Balancers in a VPC](https://amzn.to/2JDqK9A)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * security_groups (`List` of `String`) - The IDs of the security groups to associate with the
    load balancer. Note that you cannot specify the name of the security group

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.apply_security_groups_to_load_balancer("mylb", ["sg1", "sg2"])
      %ExAws.Operation.Query{
        action: :apply_security_groups_to_load_balancer,
        params: %{
          "Action" => "ApplySecurityGroupsToLoadBalancer",
          "LoadBalancerName" => "mylb",
          "SecurityGroups.member.1" => "sg1",
          "SecurityGroups.member.2" => "sg2",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec apply_security_groups_to_load_balancer(
          load_balancer_name :: binary,
          security_groups :: [binary, ...]
        ) :: ExAws.Operation.Query.t()
  def apply_security_groups_to_load_balancer(load_balancer_name, security_groups) do
    [{:load_balancer_name, load_balancer_name}, {:security_groups, security_groups}]
    |> build_request(:apply_security_groups_to_load_balancer)
  end

  @doc """
  Adds one or more subnets to the set of configured subnets for the specified
  load balancer

  The load balancer evenly distributes requests across all registered subnets. For
  more information, see [Add or Remove Subnets for Your Load Balancer in a
  VPC](https://amzn.to/2YqKJvD) in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * subnets (`List` of `String`) - the IDs of the subnets to add. You can add only
    one subnet per Availability Zone.

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.attach_load_balancer_to_subnets("mylb", ["subnet-3561b05e"])
      %ExAws.Operation.Query{
        action: :attach_load_balancer_to_subnets,
        params: %{
          "Action" => "AttachLoadBalancerToSubnets",
          "LoadBalancerName" => "mylb",
          "Subnets.member.1" => "subnet-3561b05e",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  def attach_load_balancer_to_subnets(load_balancer_name, subnets) do
    [{:load_balancer_name, load_balancer_name}, {:subnets, subnets}]
    |> build_request(:attach_load_balancer_to_subnets)
  end

  @doc """
  Specifies the health check settings to use when evaluating the health state of your EC2 instances

  For more information, see [Configure Health Checks for Your Load Balancer](https://amzn.to/2HWBv4z)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * health_check (`t:health_check/0`) - configuration information

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.configure_health_check("mylb",
      ...> %{healthy_threshold: 2,
      ...> unhealthy_threshold: 2,
      ...> target: "HTTP:80/ping",
      ...> interval: 30,
      ...> timeout: 3})
      %ExAws.Operation.Query{
        action: :configure_health_check,
        params: %{
          "Action" => "ConfigureHealthCheck",
          "LoadBalancerName" => "mylb",
          "HealthCheck.HealthyThreshold" => 2,
          "HealthCheck.UnhealthyThreshold" => 2,
          "HealthCheck.Target" => "HTTP:80/ping",
          "HealthCheck.Interval" => 30,
          "HealthCheck.Timeout" => 3,
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec configure_health_check(load_balancer_name :: binary, health_check :: health_check) ::
          ExAws.Operation.Query.t()
  def configure_health_check(load_balancer_name, health_check) do
    [{:load_balancer_name, load_balancer_name}, {:health_check, health_check}]
    |> build_request(:configure_health_check)
  end

  @doc """
  Generates a stickiness policy with sticky session lifetimes that follow
  that of an application-generated cookie

  This policy can be associated only with HTTP/HTTPS listeners.

  This policy is similar to the policy created by `create_lb_cookie_stickiness_policy/3`, except
  that the lifetime of the special Elastic Load Balancing cookie, AWSELB, follows the lifetime
  of the application-generated cookie specified in the policy configuration. The load balancer
  only inserts a new stickiness cookie when the application response includes a new application
  cookie.

  If the application cookie is explicitly removed or expires, the session stops being sticky
  until a new application cookie is issued.

  For more information, see [Application-Controlled Session Stickiness](https://amzn.to/2HFsyNz)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * policy_name (`String`) - The name of the policy being created. Policy names must consist
    of alphanumeric characters and dashes (-). This name must be unique within the set of policies
    for this load balancer

    * cookie_name (`String`) - The name of the application cookie used for stickiness

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.create_app_cookie_stickiness_policy("mylb", "my-app-sticky-policy", "my-cookie")
      %ExAws.Operation.Query{
        action: :create_app_cookie_stickiness_policy,
        params: %{
          "Action" => "CreateAppCookieStickinessPolicy",
          "LoadBalancerName" => "mylb",
          "PolicyName" => "my-app-sticky-policy",
          "CookieName" => "my-cookie",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec create_app_cookie_stickiness_policy(
          load_balancer_name :: binary,
          policy_name :: binary,
          cookie_name :: binary
        ) :: ExAws.Operation.Query.t()
  def create_app_cookie_stickiness_policy(load_balancer_name, policy_name, cookie_name) do
    [
      {:load_balancer_name, load_balancer_name},
      {:policy_name, policy_name},
      {:cookie_name, cookie_name}
    ]
    |> build_request(:create_app_cookie_stickiness_policy)
  end

  @doc """
  Generates a stickiness policy with sticky session lifetimes controlled
  by the lifetime of the browser (user-agent) or a specified expiration period

  This policy can be associated only with HTTP/HTTPS listeners.

  When a load balancer implements this policy, the load balancer uses a special
  cookie to track the instance for each request. When the load balancer receives
  a request, it first checks to see if this cookie is present in the request. If
  so, the load balancer sends the request to the application server specified in
  the cookie. If not, the load balancer sends the request to a server that is
  chosen based on the existing load-balancing algorithm.

  A cookie is inserted into the response for binding subsequent requests from the
  same user to that server. The validity of the cookie is based on the cookie
  expiration time, which is specified in the policy configuration.

  For more information, see [Duration-Based Session Stickiness](https://amzn.to/2CzNbX9)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * policy_name (`String`) - The name of the policy being created. Policy names must consist
    of alphanumeric characters and dashes (-). This name must be unique within the set of policies
    for this load balancer

    * cookie_expiration_period (`Integer`) - The time period, in seconds, after which the cookie
    should be considered stale. If you do not specify this parameter, the default value is 0,
    which indicates that the sticky session should last for the duration of the browser session

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.create_lb_cookie_stickiness_policy("mylb", "my-app-sticky-policy", 60)
      %ExAws.Operation.Query{
        action: :create_lb_cookie_stickiness_policy,
        params: %{
          "Action" => "CreateLBCookieStickinessPolicy",
          "LoadBalancerName" => "mylb",
          "PolicyName" => "my-app-sticky-policy",
          "CookieExpirationPeriod" => 60,
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec create_lb_cookie_stickiness_policy(
          load_balancer_name :: binary,
          policy_name :: binary,
          cookie_expiration_period :: integer
        ) :: ExAws.Operation.Query.t()
  def create_lb_cookie_stickiness_policy(
        load_balancer_name,
        policy_name,
        cookie_expiration_period
      ) do
    [
      {:load_balancer_name, load_balancer_name},
      {:policy_name, policy_name},
      {:cookie_expiration_period, cookie_expiration_period}
    ]
    |> build_request(:create_lb_cookie_stickiness_policy)
  end

  @doc """
  Creates a Classic Load Balancer.

  You can add listeners, security groups, subnets, and tags when you create your
  load balancer, or you can add them later using `create_load_balancer_listeners/2`,
  `apply_security_groups_to_load_balancer/2`, `attach_load_balancer_to_subnets/2`, and
  `add_tags/2`.

  To describe your current load balancers, see `describe_load_balancers/1`. When you
  are finished with a load balancer, you can delete it using `delete_load_balancer/1`.

  You can create up to 20 load balancers per region per account. You can request an
  increase for the number of load balancers for your account. For more information,
  see [Limits for Your Classic Load Balancer](https://amzn.to/2uxqzSW) in the
  Classic Load Balancers Guide.
  """
  @spec create_load_balancer(load_balancer_name :: binary, listeners :: [listener, ...]) ::
          ExAws.Operation.Query.t()
  @spec create_load_balancer(
          load_balancer_name :: binary,
          listeners :: [listener, ...],
          opts :: create_load_balancer_opts
        ) :: ExAws.Operation.Query.t()
  def create_load_balancer(load_balancer_name, listeners, opts \\ []) do
    [
      {:load_balancer_name, load_balancer_name},
      {:listeners, listeners} | opts
    ]
    |> build_request(:create_load_balancer)
  end

  @doc """
  Creates one or more listeners for the specified load balancer

  If a listener with the specified port does not already exist, it is
  created; otherwise, the properties of the new listener must match the
  properties of the existing listener.

  For more information, see [Listeners for Your Classic Load Balancer](https://amzn.to/2CIUMCS)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the load balancer name

    * listeners (`List` of `t:listener/0`) - the listeners

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.create_load_balancer_listeners("mylb",
      ...> [%{protocol: "https", load_balancer_port: 443, instance_port: 443, instance_protocol: "https",
      ...> ssl_certificate_id: "arn:aws:iam::123456789012"}])
      %ExAws.Operation.Query{
        action: :create_load_balancer_listeners,
        params: %{
          "Action" => "CreateLoadBalancerListeners",
          "LoadBalancerName" => "mylb",
          "Listeners.member.1.Protocol" => "https",
          "Listeners.member.1.LoadBalancerPort" => 443,
          "Listeners.member.1.InstancePort" => 443,
          "Listeners.member.1.InstanceProtocol" => "https",
          "Listeners.member.1.SSLCertificateId" => "arn:aws:iam::123456789012",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec create_load_balancer_listeners(load_balancer_name :: binary, listeners :: [listener, ...]) ::
          ExAws.Operation.Query.t()
  def create_load_balancer_listeners(load_balancer_name, listeners) do
    [
      {:load_balancer_name, load_balancer_name},
      {:listeners, listeners}
    ]
    |> build_request(:create_load_balancer_listeners)
  end

  @doc """
  Creates a policy with the specified attributes for the specified load balancer

  Policies are settings that are saved for your load balancer and that can be applied
  to the listener or the application server, depending on the policy type.

  ## Parameters:

    * load_balancer_name (`String`) - the load balancer name

    * policy_name (`String`) - the name of the load balancer policy to be created. This
    name must be unique within the set of policies for this load balancer

    * policy_type_name (`String`) - the name of the base policy type. To get the list of
    policy types, use `describe_load_balancer_policy_types/1`

    * opts (`t:create_load_balancer_policy_opts/0`) - optional policy attributes

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.create_load_balancer_policy("mylb",
      ...> "EnableProxyProtocol", "ProxyProtocolPolicyType", policy_attributes: [%{attribute_name: "ProxyProtocol", attribute_value: true}])
      %ExAws.Operation.Query{
        action: :create_load_balancer_policy,
        params: %{
          "Action" => "CreateLoadBalancerPolicy",
          "LoadBalancerName" => "mylb",
          "PolicyAttributes.member.1.AttributeName" => "ProxyProtocol",
          "PolicyAttributes.member.1.AttributeValue" => true,
          "PolicyName" => "EnableProxyProtocol",
          "PolicyTypeName" => "ProxyProtocolPolicyType",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec create_load_balancer_policy(
          load_balancer_name :: binary,
          policy_name :: binary,
          policy_type_name :: binary
        ) :: ExAws.Operation.Query.t()
  @spec create_load_balancer_policy(
          load_balancer_name :: binary,
          policy_name :: binary,
          policy_type_name :: binary,
          opts :: create_load_balancer_policy_opts
        ) :: ExAws.Operation.Query.t()
  def create_load_balancer_policy(load_balancer_name, policy_name, policy_type_name, opts \\ []) do
    [
      {:load_balancer_name, load_balancer_name},
      {:policy_name, policy_name},
      {:policy_type_name, policy_type_name} | opts
    ]
    |> build_request(:create_load_balancer_policy)
  end

  @doc """
  Deletes the specified load balancer

  If you are attempting to recreate a load balancer, you must reconfigure all
  settings. The DNS name associated with a deleted load balancer are no longer
  usable. The name and associated DNS record of the deleted load balancer no longer
  exist and traffic sent to any of its IP addresses is no longer delivered to your
  instances.

  If the load balancer does not exist or has already been deleted, the call to
  `delete_load_balancer/1` still succeeds.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.delete_load_balancer("mylb")
      %ExAws.Operation.Query{
        action: :delete_load_balancer,
        params: %{
          "Action" => "DeleteLoadBalancer",
          "LoadBalancerName" => "mylb",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec delete_load_balancer(load_balancer_name :: binary) :: ExAws.Operation.Query.t()
  def delete_load_balancer(load_balancer_name) do
    [{:load_balancer_name, load_balancer_name}]
    |> build_request(:delete_load_balancer)
  end

  @doc """
  Deletes the specified listeners from the specified load balancer

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * ports (`List` of `Integer`) - The client port numbers of the listeners

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.delete_load_balancer_listeners("mylb", [8001, 8002])
      %ExAws.Operation.Query{
        action: :delete_load_balancer_listeners,
        params: %{
          "Action" => "DeleteLoadBalancerListeners",
          "LoadBalancerName" => "mylb",
          "LoadBalancerPorts.member.1" => 8001,
          "LoadBalancerPorts.member.2" => 8002,
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec delete_load_balancer_listeners(load_balancer_name :: binary, ports :: [integer, ...]) ::
          ExAws.Operation.Query.t()
  def delete_load_balancer_listeners(load_balancer_name, ports) do
    [{:load_balancer_name, load_balancer_name}, {:load_balancer_ports, ports}]
    |> build_request(:delete_load_balancer_listeners)
  end

  @doc """
  Deletes the specified policy from the specified load balancer

  This policy must not be enabled for any listeners.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * policy_name (`String`) - The name of the policy

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.delete_load_balancer_policy("mylb", "my-policy")
      %ExAws.Operation.Query{
        action: :delete_load_balancer_policy,
        params: %{
          "Action" => "DeleteLoadBalancerPolicy",
          "LoadBalancerName" => "mylb",
          "PolicyName" => "my-policy",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  def delete_load_balancer_policy(load_balancer_name, policy_name) do
    [{:load_balancer_name, load_balancer_name}, {:policy_name, policy_name}]
    |> build_request(:delete_load_balancer_policy)
  end

  @doc """
  Deregisters the specified instances from the specified load balancer

  After the instance is deregistered, it no longer receives traffic from the load balancer.

  You can use `describe_load_balancers/1` to verify that the instance is deregistered
  from the load balancer.

  For more information, see [Register or De-Register EC2 Instances](https://amzn.to/2urqjVB)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * instances (`List` of `String`) - the  IDs of the instances

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.deregister_instances_from_load_balancer("mylb", [%{instance_id: "i-12345678"}])
      %ExAws.Operation.Query{
        action: :deregister_instances_from_load_balancer,
        params: %{
          "Action" => "DeregisterInstancesFromLoadBalancer",
          "LoadBalancerName" => "mylb",
          "Instances.member.1.InstanceId" => "i-12345678",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  def deregister_instances_from_load_balancer(load_balancer_name, instances) do
    [{:load_balancer_name, load_balancer_name}, {:instances, instances}]
    |> build_request(:deregister_instances_from_load_balancer)
  end

  @doc """
  Describes the current Elastic Load Balancing resource limits for your AWS account

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.describe_account_limits()
      %ExAws.Operation.Query{
        action: :describe_account_limits,
        params: %{
          "Action" => "DescribeAccountLimits",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec describe_account_limits() :: ExAws.Operation.Query.t()
  @spec describe_account_limits(opts :: describe_account_limits_opts) :: ExAws.Operation.Query.t()
  def describe_account_limits(opts \\ []) do
    opts |> build_request(:describe_account_limits)
  end

  @doc """
  Describes the state of the specified instances with respect to the specified load balancer

  If no instances are specified, the call describes the state of all instances that are currently
  registered with the load balancer. If instances are specified, their state is returned even if
  they are no longer registered with the load balancer. The state of terminated instances is not
  returned.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * opts (`t:describe_instance_health_opts/0`) - optionally provide a list of instance ids

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.describe_instance_health("mylb")
      %ExAws.Operation.Query{
        action: :describe_instance_health,
        params: %{
          "Action" => "DescribeInstanceHealth",
          "Version" => "2012-06-01",
          "LoadBalancerName" => "mylb"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }

      iex> ExAws.ElasticLoadBalancing.describe_instance_health("mylb", [instances: [%{instance_id: "i-12345678"}]])
      %ExAws.Operation.Query{
        action: :describe_instance_health,
        params: %{
          "Action" => "DescribeInstanceHealth",
          "Version" => "2012-06-01",
          "LoadBalancerName" => "mylb",
          "Instances.member.1.InstanceId" => "i-12345678",
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec describe_instance_health(load_balancer_name :: binary) :: ExAws.Operation.Query.t()
  @spec describe_instance_health(
          load_balancer_name :: binary,
          opts :: describe_instance_health_opts
        ) :: ExAws.Operation.Query.t()
  def describe_instance_health(load_balancer_name, opts \\ []) do
    [
      {:load_balancer_name, load_balancer_name} | opts
    ]
    |> build_request(:describe_instance_health)
  end

  @doc """
  Describes the attributes for the specified load balancer

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

  ## Examples:

      iex> ExAws.ElasticLoadBalancing.describe_load_balancer_attributes("mylb")
      %ExAws.Operation.Query{
        action: :describe_load_balancer_attributes,
        params: %{
          "Action" => "DescribeLoadBalancerAttributes",
          "Version" => "2012-06-01",
          "LoadBalancerName" => "mylb"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }

  """
  @spec describe_load_balancer_attributes(load_balancer_name :: binary) ::
          ExAws.Operation.Query.t()
  def describe_load_balancer_attributes(load_balancer_name) do
    [{:load_balancer_name, load_balancer_name}]
    |> build_request(:describe_load_balancer_attributes)
  end

  @doc """
  Describes the specified policies

  If you specify a load balancer name, the action returns the descriptions of all
  policies created for the load balancer. If you specify a policy name associated
  with your load balancer, the action returns the description of that policy. If you
  don't specify a load balancer name, the action returns descriptions of the specified
  sample policies, or descriptions of all sample policies. The names of the sample
  policies have the ELBSample- prefix.
  """
  @spec describe_load_balancer_policies() :: ExAws.Operation.Query.t()
  @spec describe_load_balancer_policies(opts :: describe_load_balancer_policies_opts) ::
          ExAws.Operation.Query.t()
  def describe_load_balancer_policies(opts \\ []) do
    opts
    |> build_request(:describe_load_balancer_policies)
  end

  @doc """
  Describes the specified load balancer policy types or all load balancer policy types.

  The description of each type indicates how it can be used. For example, some policies
  can be used only with layer 7 listeners, some policies can be used only with layer 4
  listeners, and some policies can be used only with your EC2 instances.

  You can use `create_load_balancer_policy/4` to create a policy configuration for any of these
  policy types. Then, depending on the policy type, use either
  `set_load_balancer_policies_of_listener/3` or
  `set_load_balancer_policies_for_backend_server/3` to set the policy.
  """
  @spec describe_load_balancer_policy_types() :: ExAws.Operation.Query.t()
  @spec describe_load_balancer_policy_types(opts :: describe_load_balancer_policy_types_opts) ::
          ExAws.Operation.Query.t()
  def describe_load_balancer_policy_types(opts \\ []) do
    opts
    |> build_request(:describe_load_balancer_policy_types)
  end

  @doc """
  Describes the specified the load balancers

  If no load balancers are specified, the call describes all of your load balancers.

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

      iex> ExAws.ElasticLoadBalancing.describe_load_balancers()
      %ExAws.Operation.Query{
        action: :describe_load_balancers,
        params: %{"Action" => "DescribeLoadBalancers", "Version" => "2012-06-01"},
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec describe_load_balancers() :: ExAws.Operation.Query.t()
  @spec describe_load_balancers(opts :: describe_load_balancers_opts) :: ExAws.Operation.Query.t()
  def describe_load_balancers(opts \\ []) do
    opts |> build_request(:describe_load_balancers)
  end

  @doc """
  Describes the tags associated with the specified load balancers

  ## Parameters:

    * load_balancer_names (`List` of `String`) - the names of the load balancers. Minimum number of 1 item.
    Maximum number of 20 items

  ## Examples:

      iex(1)> ExAws.ElasticLoadBalancing.describe_tags(["load_balancer_name1", "load_balancer_name2"])
      %ExAws.Operation.Query{
        action: :describe_tags,
        params: %{
          "Action" => "DescribeTags",
          "LoadBalancerNames.member.1" => "load_balancer_name1",
          "LoadBalancerNames.member.2" => "load_balancer_name2",
          "Version" => "2012-06-01"
        },
        parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
        path: "/",
        service: :elasticloadbalancing
      }
  """
  @spec describe_tags(load_balancer_names :: [binary, ...]) :: ExAws.Operation.Query.t()
  def describe_tags(load_balancer_names) do
    [{:load_balancer_names, load_balancer_names}]
    |> build_request(:describe_tags)
  end

  @doc """
  Removes the specified subnets from the set of configured subnets for the load balancer.

  After a subnet is removed, all EC2 instances registered with the load balancer in the
  removed subnet go into the OutOfService state. Then, the load balancer balances the
  traffic among the remaining routable subnets.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * subnets (`List` of `String`) - the IDs of the subnets

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.detach_load_balancer_from_subnets("mylb", ["subnet1"])
        %ExAws.Operation.Query{
          action: :detach_load_balancer_from_subnets,
          params: %{
            "Action" => "DetachLoadBalancerFromSubnets",
            "LoadBalancerName" => "mylb",
            "Subnets.member.1" => "subnet1",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec detach_load_balancer_from_subnets(load_balancer_name :: binary, subnets :: [binary, ...]) ::
          ExAws.Operation.Query.t()
  def detach_load_balancer_from_subnets(load_balancer_name, subnets) do
    [{:load_balancer_name, load_balancer_name}, {:subnets, subnets}]
    |> build_request(:detach_load_balancer_from_subnets)
  end

  @doc """
  Removes the specified Availability Zones from the set of Availability Zones
  for the specified load balancer in EC2-Classic or a default VPC.

  For load balancers in a non-default VPC, use `detach_load_balancer_from_subnets/2`.

  There must be at least one Availability Zone registered with a load balancer at
  all times. After an Availability Zone is removed, all instances registered with
  the load balancer that are in the removed Availability Zone go into the OutOfService
  state. Then, the load balancer attempts to equally balance the traffic among its
  remaining Availability Zones.

  For more information, see [Add or Remove Availability Zones](https://amzn.to/2WtKE8q)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * availability_zones (`List` of `String`) - The Availability Zones. These must be in
    the same region as the load balancer.

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.disable_availability_zones_for_load_balancer("mylb", ["us-east-1c"])
        %ExAws.Operation.Query{
          action: :disable_availability_zones_for_load_balancer,
          params: %{
            "Action" => "DisableAvailabilityZonesForLoadBalancer",
            "LoadBalancerName" => "mylb",
            "AvailabilityZones.member.1" => "us-east-1c",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec disable_availability_zones_for_load_balancer(
          load_balancer_name :: binary,
          availability_zones :: [binary, ...]
        ) :: ExAws.Operation.Query.t()
  def disable_availability_zones_for_load_balancer(load_balancer_name, availability_zones) do
    [{:load_balancer_name, load_balancer_name}, {:availability_zones, availability_zones}]
    |> build_request(:disable_availability_zones_for_load_balancer)
  end

  @doc """
  Adds the specified Availability Zones to the set of Availability Zones for the specified
  load balancer in EC2-Classic or a default VPC.

  For load balancers in a non-default VPC, use `attach_load_balancer_to_subnets/2`.

  The load balancer evenly distributes requests across all its registered Availability Zones
  that contain instances. For more information, see [Add or Remove Availability Zones]((https://amzn.to/2WtKE8q))
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * availability_zones (`List` of `String`) - The Availability Zones. These must be in
    the same region as the load balancer.

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.enable_availability_zones_for_load_balancer("mylb", ["us-east-1c"])
        %ExAws.Operation.Query{
          action: :enable_availability_zones_for_load_balancer,
          params: %{
            "Action" => "EnableAvailabilityZonesForLoadBalancer",
            "LoadBalancerName" => "mylb",
            "AvailabilityZones.member.1" => "us-east-1c",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec enable_availability_zones_for_load_balancer(
          load_balancer_name :: binary,
          availability_zones :: [binary, ...]
        ) :: ExAws.Operation.Query.t()
  def enable_availability_zones_for_load_balancer(load_balancer_name, availability_zones) do
    [{:load_balancer_name, load_balancer_name}, {:availability_zones, availability_zones}]
    |> build_request(:enable_availability_zones_for_load_balancer)
  end

  @doc """
  Modifies the attributes of the specified load balancer.

  You can modify the load balancer attributes, such as AccessLogs, ConnectionDraining,
  and CrossZoneLoadBalancing by either enabling or disabling them. Or, you can modify
  the load balancer attribute ConnectionSettings by specifying an idle connection
  timeout value for your load balancer.

  For more information, see the following in the Classic Load Balancers Guide:

  * [Cross-Zone Load Balancing](https://amzn.to/2XhXnwe)
  * [Connection Draining](https://amzn.to/2JLr9af)
  * [Access Logs](https://amzn.to/2RhLiD9)
  * [Idle Connection Timeout](https://amzn.to/2U0jGZu)
  """
  @spec modify_load_balancer_attributes(
          load_balancer_name :: binary,
          load_balancer_attributes :: [load_balancer_attribute, ...]
        ) :: ExAws.Operation.Query.t()
  def modify_load_balancer_attributes(load_balancer_name, load_balancer_attributes) do
    [{:load_balancer_name, load_balancer_name} | load_balancer_attributes]
    |> build_request(:modify_load_balancer_attributes)
  end

  @doc """
  Adds the specified instances to the specified load balancer.

  The instance must be a running instance in the same network as the load balancer
  (EC2-Classic or the same VPC). If you have EC2-Classic instances and a load balancer
  in a VPC with ClassicLink enabled, you can link the EC2-Classic instances to that
  VPC and then register the linked EC2-Classic instances with the load balancer in the VPC.

  Note that `register_instances_with_load_balancer/2` completes when the request has been registered.
  Instance registration takes a little time to complete. To check the state of the registered
  instances, use `describe_load_balancers/1` or `describe_instance_health/2`.

  After the instance is registered, it starts receiving traffic and requests from the load
  balancer. Any instance that is not in one of the Availability Zones registered for the load
  balancer is moved to the OutOfService state. If an Availability Zone is added to the load
  balancer later, any instances registered with the load balancer move to the InService state.

  To deregister instances from a load balancer, use `deregister_instances_from_load_balancer/2`.

  For more information, see [Register or De-Register EC2 Instances](https://amzn.to/2urqjVB)
  in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * instances (`List` of `String`) - the IDs of the instances.

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.register_instances_with_load_balancer("mylb", [%{instance_id: "i-12345678"}])
        %ExAws.Operation.Query{
          action: :register_instances_with_load_balancer,
          params: %{
            "Action" => "RegisterInstancesWithLoadBalancer",
            "LoadBalancerName" => "mylb",
            "Instances.member.1.InstanceId" => "i-12345678",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec register_instances_with_load_balancer(
          load_balancer_name :: binary,
          instances :: [instance, ...]
        ) :: ExAws.Operation.Query.t()
  def register_instances_with_load_balancer(load_balancer_name, instances) do
    [{:load_balancer_name, load_balancer_name}, {:instances, instances}]
    |> build_request(:register_instances_with_load_balancer)
  end

  @doc """
  Removes one or more tags from the specified load balancer.

  ## Parameters:

    * load_balancer_names (`List` of `String`) - the name of the load balancer. You can
    specify a maximum of one load balancer name

    * tag_keys (`List` of `t:tag_key_only/0`) - the keys for the tags to remove

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.remove_tags(["mylb"], [%{key: "department"}, %{key: "project"}])
        %ExAws.Operation.Query{
          action: :remove_tags,
          params: %{
            "Action" => "RemoveTags",
            "LoadBalancerNames.member.1" => "mylb",
            "Tags.member.1.Key" => "department",
            "Tags.member.2.Key" => "project",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec remove_tags(load_balancer_names :: [binary, ...], tag_keys :: [tag_key_only, ...]) ::
          ExAws.Operation.Query.t()
  def remove_tags(load_balancer_name, tag_keys) do
    [{:load_balancer_names, load_balancer_name}, {:tags, tag_keys}]
    |> build_request(:remove_tags)
  end

  @doc """
  Sets the certificate that terminates the specified listener's SSL connections

  The specified certificate replaces any prior certificate that was used on the
  same load balancer and port.

  For more information about updating your SSL certificate, see [Replace the SSL
  Certificate for Your Load Balancer](https://amzn.to/2HHSs3p) in the Classic
  Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * ssl_certificate_id (`String`) - the Amazon Resource Name (ARN) of the SSL certificate

    * load_balancer_port (`Integer`) - the port that uses the specified SSL certificate

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.set_load_balancer_listener_ssl_certificate("mylb", "arn:aws:iam::123456789012", 443)
        %ExAws.Operation.Query{
          action: :set_load_balancer_listener_ssl_certificate,
          params: %{
            "Action" => "SetLoadBalancerListenerSSLCertificate",
            "LoadBalancerName" => "mylb",
            "LoadBalancerPort" => 443,
            "SSLCertificateId" => "arn:aws:iam::123456789012",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec set_load_balancer_listener_ssl_certificate(
          load_balancer_name :: binary,
          ssl_certificate_id :: binary,
          load_balancer_port :: integer
        ) :: ExAws.Operation.Query.t()
  def set_load_balancer_listener_ssl_certificate(
        load_balancer_name,
        ssl_certificate_id,
        load_balancer_port
      ) do
    [
      {:load_balancer_name, load_balancer_name},
      {:ssl_certificate_id, ssl_certificate_id},
      {:load_balancer_port, load_balancer_port}
    ]
    |> build_request(:set_load_balancer_listener_ssl_certificate)
  end

  @doc """
  Replaces the set of policies associated with the specified port on which the
  EC2 instance is listening with a new set of policies

  At this time, only the back-end server authentication policy type can be applied
  to the instance ports; this policy type is composed of multiple public key policies.

  Each time you use `set_load_balancer_policies_for_backend_server/3` to enable the policies, use
  the PolicyNames parameter to list the policies that you want to enable.

  You can use `describe_load_balancers/1` or `describe_load_balancer_policies/1` to verify that the
  policy is associated with the EC2 instance.

  For more information about enabling back-end instance authentication, see
  [Configure Back-end Instance Authentication](https://amzn.to/2TDGppd) in the Classic
  Load Balancers Guide. For more information about Proxy Protocol, see [Configure Proxy
  Protocol Support](https://amzn.to/2HHelQd) in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * policy_names (`List` of `String`) - the names of the policies. If the list is empty,
    then all current polices are removed from the EC2 instance

    * instance_port (`Integer`) - the port number associated with the EC2 instance

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.set_load_balancer_policies_for_backend_server("mylb", ["EnableProxyProtocol", "my-policy2"], 80)
        %ExAws.Operation.Query{
          action: :set_load_balancer_policies_for_backend_server,
          params: %{
            "Action" => "SetLoadBalancerPoliciesForBackendServer",
            "InstancePort" => 80,
            "LoadBalancerName" => "mylb",
            "PolicyNames.member.1" => "EnableProxyProtocol",
            "PolicyNames.member.2" => "my-policy2",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec set_load_balancer_policies_for_backend_server(
          load_balancer_name :: binary,
          policy_names :: [binary, ...],
          instance_port :: integer
        ) :: ExAws.Operation.Query.t()
  def set_load_balancer_policies_for_backend_server(
        load_balancer_name,
        policy_names,
        instance_port
      ) do
    [
      {:load_balancer_name, load_balancer_name},
      {:policy_names, policy_names},
      {:instance_port, instance_port}
    ]
    |> build_request(:set_load_balancer_policies_for_backend_server)
  end

  @doc """
  Replaces the current set of policies for the specified load balancer port with the specified set of policies.

  To enable back-end server authentication, use `set_load_balancer_policies_for_backend_server/3`.

  For more information about setting policies, see [Update the SSL Negotiation Configuration](https://amzn.to/2WuPGlj),
  [Duration-Based Session Stickiness](https://amzn.to/2CzNbX9), and [Application-Controlled Session
  Stickiness](https://amzn.to/2HFsyNz) in the Classic Load Balancers Guide.

  ## Parameters:

    * load_balancer_name (`String`) - the name of the load balancer

    * policy_names (`List` of `String`) - the names of the policies. If the list is empty,
    then all current polices are removed from the EC2 instance

    * load_balancer_port (`Integer`) - the external port of the load balancer

  ## Examples:

        iex> ExAws.ElasticLoadBalancing.set_load_balancer_policies_of_listener("mylb", ["my-SSLNegotiation-policy"], 443)
        %ExAws.Operation.Query{
          action: :set_load_balancer_policies_of_listener,
          params: %{
            "Action" => "SetLoadBalancerPoliciesOfListener",
            "LoadBalancerPort" => 443,
            "LoadBalancerName" => "mylb",
            "PolicyNames.member.1" => "my-SSLNegotiation-policy",
            "Version" => "2012-06-01"
          },
          parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2,
          path: "/",
          service: :elasticloadbalancing
        }
  """
  @spec set_load_balancer_policies_of_listener(
          load_balancer_name :: binary,
          policy_names :: [binary, ...],
          load_balancer_port :: integer
        ) :: ExAws.Operation.Query.t()
  def set_load_balancer_policies_of_listener(load_balancer_name, policy_names, load_balancer_port) do
    [
      {:load_balancer_name, load_balancer_name},
      {:policy_names, policy_names},
      {:load_balancer_port, load_balancer_port}
    ]
    |> build_request(:set_load_balancer_policies_of_listener)
  end

  defp build_request(opts, action) do
    opts
    |> Enum.flat_map(&format_param/1)
    |> request(action)
  end

  defp request(params, action) do
    action_string = action |> camelize_action()

    %ExAws.Operation.Query{
      path: "/",
      params:
        params
        |> filter_nil_params
        |> Map.put("Action", action_string)
        |> Map.put("Version", @version),
      service: :elasticloadbalancing,
      action: action,
      parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2
    }
  end

  defp camelize_action(:create_lb_cookie_stickiness_policy) do
    "CreateLBCookieStickinessPolicy"
  end

  defp camelize_action(:set_load_balancer_listener_ssl_certificate) do
    "SetLoadBalancerListenerSSLCertificate"
  end

  defp camelize_action(action) do
    action |> Atom.to_string() |> Macro.camelize()
  end

  defp format_param({:tags, tags}) do
    tags |> format(prefix: "Tags.member")
  end

  defp format_param({:ssl_certificate_id, ssl_certificate_id}) do
    ssl_certificate_id |> format(prefix: "SSLCertificateId")
  end

  defp format_param({:security_groups, security_groups}) do
    security_groups |> format(prefix: "SecurityGroups.member")
  end

  defp format_param({:subnets, subnets}) do
    subnets |> format(prefix: "Subnets.member")
  end

  defp format_param({:listeners, listeners}) do
    listeners |> format(prefix: "Listeners.member")
  end

  defp format_param({:availability_zones, availability_zones}) do
    availability_zones |> format(prefix: "AvailabilityZones.member")
  end

  defp format_param({:load_balancer_ports, ports}) do
    ports |> format(prefix: "LoadBalancerPorts.member")
  end

  defp format_param({:instances, instances}) do
    instances |> format(prefix: "Instances.member")
  end

  defp format_param({:load_balancer_names, load_balancer_names}) do
    load_balancer_names |> format(prefix: "LoadBalancerNames.member")
  end

  defp format_param({:policy_type_names, policy_type_names}) do
    policy_type_names |> format(prefix: "PolicyTypeNames.member")
  end

  defp format_param({:policy_names, policy_names}) do
    policy_names |> format(prefix: "PolicyNames.member")
  end

  defp format_param({:policy_attributes, policy_attributes}) do
    policy_attributes |> format(prefix: "PolicyAttributes.member")
  end

  defp format_param({:max_items, max_items}) do
    max_items |> format(prefix: "MaxItems")
  end

  defp format_param({:page_size, page_size}) do
    page_size |> format(prefix: "PageSize")
  end

  defp format_param({:starting_token, starting_token}) do
    starting_token |> format(prefix: "StartingToken")
  end

  defp format_param({:connection_settings_idle_timeout, timeout}) do
    timeout |> format(prefix: "LoadBalancerAttributes.ConnectionSettings.IdleTimeout")
  end

  defp format_param({:cross_zone_load_balancing_enabled, enabled}) do
    enabled |> format(prefix: "LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled")
  end

  defp format_param({:connection_draining_enabled, connection_draining_enabled}) do
    connection_draining_enabled
    |> format(prefix: "LoadBalancerAttributes.ConnectionDraining.Enabled")
  end

  defp format_param({:connection_draining_timeout, connection_draining_timeout}) do
    connection_draining_timeout
    |> format(prefix: "LoadBalancerAttributes.ConnectionDraining.Timeout")
  end

  defp format_param({:access_log_emit_interval, access_log_emit_interval}) do
    access_log_emit_interval |> format(prefix: "LoadBalancerAttributes.AccessLog.EmitInterval")
  end

  defp format_param({:access_log_enabled, access_log_enabled}) do
    access_log_enabled |> format(prefix: "LoadBalancerAttributes.AccessLog.Enabled")
  end

  defp format_param({:access_log_s3_bucket_prefix, access_log_s3_bucket_prefix}) do
    access_log_s3_bucket_prefix
    |> format(prefix: "LoadBalancerAttributes.AccessLog.S3BucketPrefix")
  end

  defp format_param({:access_log_s3_bucket_name, access_log_s3_bucket_name}) do
    access_log_s3_bucket_name |> format(prefix: "LoadBalancerAttributes.AccessLog.S3BucketName")
  end

  defp format_param({:health_check, health_check}) do
    health_check |> format(prefix: "HealthCheck")
  end

  defp format_param({key, parameters}) do
    format([{key, parameters}])
  end
end
