defmodule ExAuthn.ConfigTest do
  use ExUnit.Case, async: true
  doctest ExAuthn.Config

  alias ExAuthn.Config

  describe "load/0" do
    test "returns config" do
      config = Config.load()

      assert config == %Config{
               relying_party: %{
                 id: "localhost",
                 name: "Ex Authn",
                 origin: "http://localhost:4000"
               },
               timeout: 60000,
               attestation: :direct,
               user_verification: :preferred
             }
    end
  end
end
