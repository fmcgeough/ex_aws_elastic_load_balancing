defmodule ExAws.ElasticLoadBalancingV2.ParsersTest do
  use ExUnit.Case
  doctest ExAws.ElasticLoadBalancingV2.Parsers

  describe "describe_target_health parsers" do
    test "parses DescribeTargetHealthResponse" do
      xml = """
      <DescribeTargetHealthResponse xmlns="http://elasticloadbalancing.amazonaws.com/doc/2015-12-01/">
        <DescribeTargetHealthResult>
          <TargetHealthDescriptions>
            <member>
              <HealthCheckPort>80</HealthCheckPort>
              <TargetHealth>
                <State>healthy</State>
              </TargetHealth>
              <Target>
                <Port>80</Port>
                <Id>i-0376fadf</Id>
              </Target>
            </member>
            <member>
              <HealthCheckPort>80</HealthCheckPort>
              <TargetHealth>
                <State>healthy</State>
              </TargetHealth>
              <Target>
                <AvailabilityZone>all</AvailabilityZone>
                <Port>80</Port>
                <Id>i-0376fade</Id>
              </Target>
            </member>
          </TargetHealthDescriptions>
        </DescribeTargetHealthResult>
        <ResponseMetadata>
          <RequestId>c534f810-f389-11e5-9192-3fff33344cfa</RequestId>
        </ResponseMetadata>
      </DescribeTargetHealthResponse>
      """

      expected = %{
        request_id: "c534f810-f389-11e5-9192-3fff33344cfa",
        target_health_descriptions: [
          %{
            health_check_port: "80",
            target_health: "healthy",
            targets: [%{availability_zone: "", id: "i-0376fadf", port: "80"}]
          },
          %{
            health_check_port: "80",
            target_health: "healthy",
            targets: [%{availability_zone: "all", id: "i-0376fade", port: "80"}]
          }
        ]
      }

      {:ok, %{body: body}} =
        ExAws.ElasticLoadBalancingV2.Parsers.parse(
          {:ok, %{body: xml}},
          :describe_target_health
        )

      assert expected == body
    end
  end
end
