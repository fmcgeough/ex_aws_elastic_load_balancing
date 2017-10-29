defmodule ExAws.ElasticLoadBalancingTest do
  use ExUnit.Case
  doctest ExAws.ElasticLoadBalancing

  test "greets the world" do
    assert ExAws.ElasticLoadBalancing.hello() == :world
  end
end
