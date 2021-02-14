defmodule ExAuthn.WebAuthn.CollectedClientDataTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.CollectedClientData

  describe "parse/1" do
    test "returns client data" do
      raw_client_data =
        "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"

      {:ok, client_data} = CollectedClientData.parse(raw_client_data)

      assert client_data.type == :create
      assert client_data.challenge == "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo"
      assert client_data.origin == "http://localhost:4000"
    end
  end
end
