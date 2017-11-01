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

This is just the initial project structure. Lots of work to do to make this
viable.