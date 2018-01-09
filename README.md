# ExAws.ElasticLoadBalancing

Service module for https://github.com/ex-aws/ex_aws

## Installation

The package can be installed by adding ex_aws_elastic_load_balancing to your
list of dependencies in mix.exs along with :ex_aws and your
preferred JSON codec / http client

```elixir
def deps do
  [
    {:ex_aws, "~> 2.0"},
    {:ex_aws_elastic_load_balancing, "~> 2.0"},
    {:poison, "~> 3.0"},
    {:hackney, "~> 1.9"},
  ]
end
```
Elastic Load Balancing protocol: "query". So every function in the API
returns a `%ExAws.Operation.Query{}` struct.

All the unit tests are implemented using [DocTest](https://hexdocs.pm/ex_unit/ExUnit.DocTest.html).

AWS Elastic Load Balancing consists of two different API's that are grouped under the general
heading of "Elastic Load Balancing". Both are included in this library. ExAws.ElasticLoadBalancing
is used for dealing with what Amazon calls "Classic" Load Balancers. ExAws.ElasticLoadBalancingV2
is used for dealing with Application or Network Load Balancers.

Simple usage:

```elixir
iex(1)> alias ExAws.ElasticLoadBalancing
ExAws.ElasticLoadBalancing
iex(2)>  keys = [secret_access_key: "my_secret_keys",  access_key_id: "my_access_id", region: "us-east-1"]
[secret_access_key: "my_secret_keys",
 access_key_id: "my_access_id", region: "us-east-1"]
iex(3)>  ElasticLoadBalancing.describe_load_balancers() |> ExAws.request(keys)
```