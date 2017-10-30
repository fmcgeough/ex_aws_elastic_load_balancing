defmodule ExAws.ElasticLoadBalancing do
  @moduledoc """
  Operations on AWS ELB (Elastic Load Balancing)

  AWS Elastic Load Balancing supports three types of load balancers: Application 
  Load Balancers, Network Load Balancers, and Classic Load Balancers. You can 
  select a load balancer based on your application needs. For more information, 
  see the [Elastic Load Balancing User Guide][User_Guide].

  Examples of how to use this:
  ```
  elixir
  alias ExAws.ElasticLoadBalancing
  ElasticLoadBalancing.describe_load_balancers()
  ```

  [User_Guide]: http://docs.aws.amazon.com/elasticloadbalancing/latest/userguide/
  """

  use ExAws.Utils,
    format_type: :xml,
    non_standard_keys: %{}

  # version of the AWS API
  @version "2015-12-01"

  @type tag :: {key :: atom, value :: binary}
  
  @type load_balancer_address :: [
    ip_address: binary,
    allocation_id: binary
  ]

  @type action :: [
    action_type_enum: binary,
    target_group_arn: binary
  ]

  @type availability_zone :: [
    zone_name: boolean,
    subnet_id: binary,
    load_balancer_addresses: [load_balancer_address, ...]
  ]
  
  @type certificate :: [
    certificate_arn: binary,
    is_default: boolean
  ]

  @type add_listener_certificates_input :: [
    listener_arn: binary,
    certificates: [certificate, ...]
  ]

  @type port_spec :: [
    max: integer,
    min: integer
  ]

  @type target_group :: [
    target_group_arn: binary,
    target_group_name: binary,
    protocol: binary,
    port: port_spec,
  ]

  @type remove_listener_certificates_input :: [
    listener_arn: binary,
    certificates: [certificate, ...]
  ]

  @type rule_condition :: [
    field: binary,
    values: [binary, ...]
  ]

  @type rule :: [
    rule_arn: binary,
    priority: binary,
    conditions: [rule_condition, ...],
    actions: [action, ...],
    is_default: boolean
  ]
  
  @doc """
  Adds the specified certificate to the specified secure listener.

  If the certificate was already added, the call is successful but the certificate 
  is not added again.

  To list the certificates for your listener, use `describe_listener_certificates/1`.
  To remove certificates from your listener, use `remove_listener_certificates/1`.
  """
  def add_listener_certificates(opts \\ []) do
    opts |> build_request(:add_listener_certificates)
  end

  @doc """
  Adds the specified tags to the specified Elastic Load Balancing resource. 

  You can tag your Application Load Balancers, Network Load Balancers, and your target groups.

  Each tag consists of a key and an optional value. If a resource already has a tag with the same 
  key, `add_tags/1` updates its value.

  To list the current tags for your resources, use `describe_tags/1`. To remove tags from 
  your resources, use `remove_tags/1`.
  """
  @spec add_tags(load_balancer_names :: [binary, ...], tags :: [tag, ...]) :: ExAws.Operation.Query.t
  def add_tags(load_balancer_names, tags, opts \\ []) do
    [ {:load_balancer_names, load_balancer_names},
    {:tags, tags} | opts ]
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
  """
  def create_listener(opts \\ []) do
    opts |> build_request(:create_listener)
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
  """
  def create_load_balancer(opts \\ []) do
    opts |> build_request(:create_load_balancer)
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
  def create_rule(opts \\ []) do
    opts |> build_request(:create_rule)
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
  """
  def create_target_group(opts \\ []) do
    opts |> build_request(:create_target_group)
  end

  @doc """
  Deletes the specified listener.

  Alternatively, your listener is deleted when you delete the load balancer 
  it is attached to using `delete_load_balancer/1`.
  """
  def delete_listener(opts \\ []) do
    opts |> build_request(:delete_listener)
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
  """
  def delete_load_balancer(opts \\ []) do
    opts |> build_request(:delete_load_balancer)
  end

  @doc """
  Deletes the specified rule.
  """
  def delete_rule(opts \\ []) do
    opts |> build_request(:delete_rule)
  end

  @doc """
  Deletes the specified target group.

  You can delete a target group if it is not referenced by any 
  actions. Deleting a target group also deletes any associated 
  health checks.
  """
  def delete_target_group(opts \\ []) do
    opts |> build_request(:delete_target_group)
  end

  @doc """
  Deregisters the specified targets from the specified target group. 

  After the targets are deregistered, they no longer receive traffic 
  from the load balancer.
  """
  def deregister_targets(opts \\ []) do
    opts |> build_request(:deregister_targets)
  end

  @doc """
  Describes the current Elastic Load Balancing resource limits 
  for your AWS account.

  More information:
  * [Limits for Your Application Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html)
  in the *Application Load Balancer Guide*
  * [Limits for Your Network Load Balancers](http://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-limits.html)
  in the *Network Load Balancers Guide*.
  """
  def describe_account_limits(opts \\ []) do
    opts |> build_request(:describe_account_limits)
  end

  @doc """
  Describes the certificates for the specified secure listener.
  """
  def describe_listener_certificates(opts \\ []) do
    opts |> build_request(:describe_listener_certificates)
  end

  @doc """
  Describes the specified listeners or the listeners for the 
  specified Application Load Balancer or Network Load Balancer. 

  You must specify either a load balancer or one or more listeners.
  """
  def describe_listeners(opts \\ []) do
    opts |> build_request(:describe_listeners)
  end

  @doc """
  Describes the attributes for the specified Application Load 
  Balancer or Network Load Balancer.
  """
  def describe_load_balancer_attributes(opts \\ []) do
    opts |> build_request(:describe_load_balancer_attributes)
  end

  @doc """
  Describes the specified load balancers or all of your 
  load balancers.

  To describe the listeners for a load balancer, use `describe_listeners/1`.
  To describe the attributes for a load balancer, use `describe_load_balancer_attributes/1`.
  """
  def describe_load_balancers(opts \\ []) do
    opts |> build_request(:describe_load_balancers)
  end

  @doc """
  Describes the specified rules or the rules for the specified listener. 

  You must specify either a listener or one or more rules.
  """
  def describe_rules(opts \\ []) do
    opts |> build_request(:describe_rules)
  end

  @doc """
  Describes the specified policies or all policies used for SSL negotiation.

  More information:
  * [Security Policies](http://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html#describe-ssl-policies)
  in the *Application Load Balancers Guide*.
  """
  def describe_ssl_policies(opts \\ []) do
    opts |> build_request(:describe_ssl_policies)
  end

  @doc """
  Describes the tags for the specified resources. 

  You can describe the tags for one or more Application Load Balancers, 
  Network Load Balancers, and target groups.
  """
  def describe_tags(opts \\ []) do
    opts |> build_request(:describe_tags)
  end

  @doc """
  Describes the attributes for the specified target group.
  """
  def describe_target_group_attributes(opts \\ []) do
    opts |> build_request(:describe_target_group_attributes)
  end

  @doc """
  Describes the specified target groups or all of your target groups. 

  By default, all target groups are described. Alternatively, you can 
  specify one of the following to filter the results: the ARN of the 
  load balancer, the names of one or more target groups, or the ARNs 
  of one or more target groups. To describe the targets for a 
  target group, use `describe_target_health/1`. To describe the attributes 
  of a target group, use `describe_target_group_attributes/1`.
  """
  def describe_target_groups(opts \\ []) do
    opts |> build_request(:describe_target_groups)
  end

  @doc """
  Describes the health of the specified targets or all of your targets.
  """
  def describe_target_health(opts \\ []) do
    opts |> build_request(:describe_target_health)
  end

  @doc """
  Modifies the specified properties of the specified listener.

  Any properties that you do not specify retain their current values. 
  However, changing the protocol from HTTPS to HTTP removes the security 
  policy and SSL certificate properties. If you change the protocol from 
  HTTP to HTTPS, you must add the security policy and server certificate.
  """
  def modify_listener(opts \\ []) do
    opts |> build_request(:modify_listener)
  end

  @doc """
  Modifies the specified attributes of the specified Application Load Balancer 
  or Network Load Balancer.

  If any of the specified attributes can't be modified as requested, the call 
  fails. Any existing attributes that you do not modify retain their current 
  values.
  """
  def modify_load_balancer_attributes(opts \\ []) do
    opts |> build_request(:modify_load_balancer_attributes)
  end

  @doc """
  Modifies the specified rule.
  
  Any existing properties that you do not modify retain their current values.

  To modify the default action, use `modify_listener/1`.
  """
  def modify_rule(opts \\ []) do
    opts |> build_request(:modify_rule)
  end

  @doc """
  Modifies the health checks used when evaluating the health state of 
  the targets in the specified target group.

  To monitor the health of the targets, use `describe_target_health/1`.
  """
  def modify_target_group(opts \\ []) do
    opts |> build_request(:modify_target_group)
  end

  @doc """
  Modifies the specified attributes of the specified target group.
  """
  def modify_target_group_attributes(opts \\ []) do
    opts |> build_request(:modify_target_group_attributes)
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
  """
  def register_targets(opts \\ []) do
    opts |> build_request(:register_targets)
  end

  @doc """
  Removes the specified certificate from the specified secure listener.

  You can't remove the default certificate for a listener. To replace 
  the default certificate, call `modify_listener/1`. To list the certificates 
  for your listener, use `describe_listener_certificates/1`.
  """
  def remove_listener_certificates(opts \\ []) do
    opts |> build_request(:remove_listener_certificates)
  end

  @doc """
  Removes the specified tags from the specified Elastic Load Balancing 
  resource.

  To list the current tags for your resources, use `describe_tags/1`.
  """
  def remove_tags(opts \\ []) do
    opts |> build_request(:remove_tags)
  end

  @doc """
  Sets the type of IP addresses used by the subnets of the specified 
  Application Load Balancer or Network Load Balancer.

  *Note: Network Load Balancers must use `ipv4`*.
  """
  def set_ip_address_type(opts \\ []) do
    opts |> build_request(:set_ip_address_type)
  end

  @doc """
  Sets the priorities of the specified rules.

  You can reorder the rules as long as there are no priority conflicts 
  in the new order. Any existing rules that you do not specify retain 
  their current priority.
  """
  def set_rule_priorities(opts \\ []) do
    opts |> build_request(:set_rule_priorities)
  end

  @doc """
  Associates the specified security groups with the specified Application 
  Load Balancer. 

  The specified security groups override the previously associated security 
  groups. 
  
  *Note: You can't specify a security group for a Network Load Balancer*.
  """
  def set_security_groups(opts \\ []) do
    opts |> build_request(:set_security_groups)
  end

  @doc """
  Enables the Availability Zone for the specified subnets for the specified 
  Application Load Balancer. 

  The specified subnets replace the previously enabled subnets. 
  
  *Note: You can't change the subnets for a Network Load Balancer*.
  """
  def set_subnets(opts \\ []) do
    opts |> build_request(:set_subnets)
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
      params: params
              |> filter_nil_params
              |> Map.put("Action", action_string)
              |> Map.put("Version", @version),
      service: :elastic_load_balancing,
      action: action
    }
  end

  defp format_param({key, parameters}) do
    format([{key, parameters}])
  end
end

