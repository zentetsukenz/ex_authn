defmodule ExAuthn.WebAuthn.ChallengeTest do
  use ExUnit.Case, async: true
  doctest ExAuthn.WebAuthn.Challenge

  alias ExAuthn.WebAuthn.Challenge

  describe "generate/1" do
    test "returns ok with random generated base64 challenge from specified challenge size" do
      assert {:ok, challenge} = Challenge.generate(32)
      assert 32 = challenge |> Base.url_decode64!() |> byte_size()
    end
  end
end
