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
    non_standard_keys: %{}

  # version of the AWS API
  @version "2012-06-01"

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

      iex> ExAws.ElasticLoadBalancing.describe_load_balancers
      %ExAws.Operation.Query{action: :describe_load_balancers,
      params: %{"Action" => "DescribeLoadBalancers", "Version" => "2012-06-01"},
      parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2, path: "/", service: :elasticloadbalancing}
  """
  @type describe_load_balancers_opts :: [
          load_balancer_names: [binary, ...],
          starting_token: binary,
          max_items: integer,
          page_size: integer
        ]
  @spec describe_load_balancers() :: ExAws.Operation.Query.t()
  @spec describe_load_balancers(opts :: describe_load_balancers_opts) :: ExAws.Operation.Query.t()
  def describe_load_balancers(opts \\ []) do
    opts |> build_request(:describe_load_balancers)
  end

  @doc """
  DescribeTags API operation for Elastic Load Balancing.

  Describes the tags associated with the specified load balancers.

  A list of load balancer names is a required parameter

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
      parser: &ExAws.ElasticLoadBalancing.Parsers.parse/2
    }
  end

  defp format_param({:load_balancer_names, load_balancer_names}) do
    load_balancer_names |> format(prefix: "LoadBalancerNames.member")
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

  defp format_param({key, parameters}) do
    format([{key, parameters}])
  end
end
