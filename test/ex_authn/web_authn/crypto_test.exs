defmodule ExAuthn.WebAuthn.CryptoTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.Crypto

  describe "hash/1" do
    test "returns check sum" do
      sum = Crypto.hash(<<1, 2, 3, 4>>)

      assert sum ==
               "\x9Fd\xA7G\xE1\xB9\d\x13\x1F\xAB\xB6\xB4G)l\x9Bo\x02\x01石\xC55nlw\xE8\x9Bj\x80j"
    end
  end
end
