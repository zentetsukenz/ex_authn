defmodule ExAuthn.ConfigTest do
  use ExUnit.Case, async: true
  doctest ExAuthn.Config

  alias ExAuthn.Config

  describe "load/0" do
    test "returns config" do
      config = Config.load()

      assert config == %Config{
               rp: %{
                 id: "localhost",
                 name: "Ex Authn",
                 origin: "http://localhost:4000"
               },
               timeout: 60000,
               attestation: :direct,
               authenticator_selection: %{
                 user_verification: :preferred
               },
               pub_key_cred_params: [
                 %{type: :public_key, alg: -7},
                 %{type: :public_key, alg: -8},
                 %{type: :public_key, alg: -35},
                 %{type: :public_key, alg: -36},
                 %{type: :public_key, alg: -37},
                 %{type: :public_key, alg: -38},
                 %{type: :public_key, alg: -39}
               ]
             }
    end
  end
end
