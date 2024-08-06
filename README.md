# AWS Elastic Load Balancing API

AWS Elastic Load Balancing Service module for [ex_aws](https://github.com/ex-aws/ex_aws).
AWS Elastic Load Balancing consists of two different API's that are grouped under the general
heading of "Elastic Load Balancing". Both are included in this library. `ExAws.ElasticLoadBalancing`
is used for what Amazon calls "Classic" Load Balancers. `ExAws.ElasticLoadBalancingV2`
is used for Application or Network Load Balancers (alb/nlb).

## Installation

The package can be installed by adding ex_aws_elastic_load_balancing to your
list of dependencies in mix.exs along with :ex_aws and your
preferred JSON codec / http client. Example:

```elixir
def deps do
  [
    {:ex_aws, "~> 2.0"},
    {:ex_aws_elastic_load_balancing, "~> 2.2"},
    {:poison, "~> 3.0"},
    {:hackney, "~> 1.9"},
  ]
end
```

Simple usage from command line:

```elixir
iex(1)> alias ExAws.ElasticLoadBalancing
ExAws.ElasticLoadBalancing
iex(2)>  keys = [secret_access_key: "my_secret_keys",  access_key_id: "my_access_id", region: "us-east-1"]
[secret_access_key: "my_secret_keys",
 access_key_id: "my_access_id", region: "us-east-1"]
iex(3)>  ElasticLoadBalancing.describe_load_balancers() |> ExAws.request(keys)
```

## Other Notes

Both AWS Elastic Load Balancing APIs use the "query" protocol. So every function in the API
returns a `%ExAws.Operation.Query{}` struct.

Most of the unit tests are implemented using [DocTest](https://hexdocs.pm/ex_unit/ExUnit.DocTest.html).

## License

[License](LICENSE)
