defmodule ExAws.ElasticLoadBalancing.FormatV2Test do
  use ExUnit.Case

  alias ExAws.ElasticLoadBalancing.FormatV2

  describe "add_trust_store_revocations_opts" do
    setup do
      expected = [
        {"TrustStoreRevocations.RevocationContents.1.RevocationType", "CRL"},
        {"TrustStoreRevocations.RevocationContents.1.S3Bucket", "test_bucket"},
        {"TrustStoreRevocations.RevocationContents.2.RevocationType", "CRL"},
        {"TrustStoreRevocations.RevocationContents.2.S3Bucket", "test_bucket2"}
      ]

      revocation1 = %{revocation_type: "CRL", s3_bucket: "test_bucket"}
      revocation2 = %{revocation_type: "CRL", s3_bucket: "test_bucket2"}

      {:ok, expected: expected, revocation_contents: [revocation1, revocation2]}
    end

    test "as key list", context do
      opts = [{:revocation_contents, context.revocation_contents}]
      assert context.expected == FormatV2.format_param({:trust_store_revocations, opts})
    end

    test "as map", context do
      opts = %{revocation_contents: context.revocation_contents}
      assert context.expected == FormatV2.format_param({:trust_store_revocations, opts})
    end
  end
end
