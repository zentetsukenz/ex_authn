defmodule ExAuthn.WebAuthn.ClientDataTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.ClientData

  describe "parse/1" do
    test "returns client data" do
      raw_client_data =
        "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"

      {:ok, client_data} = ClientData.parse(raw_client_data)

      assert client_data.type == :create
      assert client_data.challenge == "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo"
      assert client_data.origin == "http://localhost:4000"
    end
  end

  describe "verify/5" do
    setup do
      {:ok,
       client_data: %ClientData{
         type: :create,
         challenge: "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo",
         origin: "http://localhost:4000"
       },
       session_challenge: "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo",
       config_rp_origin: "http://localhost:4000"}
    end

    test "returns error if ceremony type is create but client data ceremony type is not create",
         context do
      {:error, msg} =
        ClientData.verify(
          %ClientData{type: :assert},
          context.session_challenge,
          :create,
          "",
          context.config_rp_origin
        )

      assert msg == "expect ceremony type to be create"
    end

    test "returns error if challenge mismatch", context do
      {:error, msg} =
        ClientData.verify(
          %ClientData{type: :create, challenge: "1234"},
          context.session_challenge,
          :create,
          "",
          context.config_rp_origin
        )

      assert msg == "challenge mismatch"
    end

    test "returns error if origin mismatch", context do
      {:error, msg} =
        ClientData.verify(
          %ClientData{type: :create, challenge: context.session_challenge, origin: "fake origin"},
          context.session_challenge,
          :create,
          "",
          context.config_rp_origin
        )

      assert msg == "origin mismatch"
    end

    test "returns client data", context do
      {:ok, client_data} =
        ClientData.verify(
          context.client_data,
          context.session_challenge,
          :create,
          "",
          context.config_rp_origin
        )

      assert client_data.type == :create
      assert client_data.challenge == "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo"
      assert client_data.origin == "http://localhost:4000"
    end
  end
end
