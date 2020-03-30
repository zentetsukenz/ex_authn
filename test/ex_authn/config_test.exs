defmodule ExAuthn.ConfigTest do
  use ExUnit.Case, async: true
  doctest ExAuthn.Config

  alias ExAuthn.Config

  test "relying_party" do
    expected = %{
      id: "localhost",
      display_name: "Wiwatta Mongkhonchit",
      icon: ""
    }

    assert Config.relying_party() == expected
  end
end
