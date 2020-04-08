defmodule ExAuthn.WebAuthn.AuthenticatorAttestationTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.AuthenticatorAttestation

  describe "parse/1" do
    setup do
      raw_attestation = %{
        "attestation_object" =>
          "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOXTBMnA6EihBVqknuxdbzLkn5V39V3NJOsohI-ZHnzfAiEAvxraExcTuAYCwExCkjj40WGt_Q6n7HC0QGEPXbdgwEloYXV0aERhdGFY3UmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV6KFUStzgACNbzGCmSLCyXx8FUDAFkBK44LylgloN-M9D0TKOhCRyoT-GS8pIZVwp-XUHHV9AGHnsQqI7winuLFp5x6__kziqW4zIsoLdt-XnvZYLwUDdpGFqSEZZDJ-pbr2RJ_X7P4eIi9-xA0KaUBAgMmIAEhWCCYhcobY1UkOAz6X7QKb9txhgMhz4Ve0_kCGy7fwnPHQSJYIPwg9xjeHRR_sULkhkSICtcyT36wBIyV4FGqEfprySTc",
        "client_data_json" =>
          "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
      }

      {:ok, raw_attestation: raw_attestation}
    end

    test "returns authenticator attestation", context do
      {:ok, authenticator_attestation} = AuthenticatorAttestation.parse(context.raw_attestation)

      assert authenticator_attestation.client_data != nil
      assert authenticator_attestation.attestation_object != nil
    end

    test "returns error if no attestation" do
      {:error, msg} = AuthenticatorAttestation.parse(nil)

      assert msg == "authenticator attestation is missing"
    end

    test "returns error if client data is missing" do
      {:error, msg} = AuthenticatorAttestation.parse(%{"attestation_object" => "test"})

      assert msg == "client data or attestation object is missing"
    end

    test "returns error if attestation object is missing" do
      {:error, msg} = AuthenticatorAttestation.parse(%{"client_data_json" => "test"})

      assert msg == "client data or attestation object is missing"
    end
  end
end
