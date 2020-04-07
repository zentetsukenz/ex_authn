defmodule ExAuthn.WebAuthn.PublicKeyCredentialCreationTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.PublicKeyCredentialCreation

  describe "parse/1" do
    setup do
      {:ok,
       params: %{
         "id" =>
           "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
         "raw_id" =>
           "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
         "response" => %{
           "attestation_object" =>
             "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOXTBMnA6EihBVqknuxdbzLkn5V39V3NJOsohI-ZHnzfAiEAvxraExcTuAYCwExCkjj40WGt_Q6n7HC0QGEPXbdgwEloYXV0aERhdGFY3UmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV6KFUStzgACNbzGCmSLCyXx8FUDAFkBK44LylgloN-M9D0TKOhCRyoT-GS8pIZVwp-XUHHV9AGHnsQqI7winuLFp5x6__kziqW4zIsoLdt-XnvZYLwUDdpGFqSEZZDJ-pbr2RJ_X7P4eIi9-xA0KaUBAgMmIAEhWCCYhcobY1UkOAz6X7QKb9txhgMhz4Ve0_kCGy7fwnPHQSJYIPwg9xjeHRR_sULkhkSICtcyT36wBIyV4FGqEfprySTc",
           "client_data_json" =>
             "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
         },
         "type" => "public-key"
       }}
    end

    test "returns error if credential is nil" do
      {:error, msg} = PublicKeyCredentialCreation.parse(nil)

      assert msg == "credential creation payload must be present"
    end

    test "returns public key creation", context do
      {:ok, public_key} = PublicKeyCredentialCreation.parse(context.params)

      assert public_key.id ==
               "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk"

      assert public_key.type == :public_key

      assert public_key.raw_id ==
               "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk"

      assert public_key.extensions == nil
      assert public_key.response != nil
    end
  end
end
