defmodule ExAuthn.ConfigTest do
  use ExUnit.Case, async: true
  doctest ExAuthn.Config

  alias ExAuthn.Config

  describe "load/0" do
    test "returns config" do
      assert Config.load() == %Config{
               rp: %{
                 id: "localhost",
                 name: "ExAuthnTest",
                 origin: "http://localhost:4000",
                 icon: nil
               },
               timeout: 60000,
               attestation_preference: :direct,
               authenticator_selection: %{
                 user_verification: :preferred
               }
             }
    end
  end
end
