defmodule ExAuthn.Protocol.AttestedCredentialDataTest do
  use ExUnit.Case, async: true

  alias ExAuthn.Protocol.AttestedCredentialData

  describe "parse/1" do
    setup do
      raw_attested_credential_data =
        <<173, 206, 0, 2, 53, 188, 198, 10, 100, 139, 11, 37, 241, 240, 85, 3, 0, 89, 1, 43, 142,
          11, 202, 88, 37, 160, 223, 140, 244, 61, 19, 40, 232, 66, 71, 42, 19, 248, 100, 188,
          164, 134, 85, 194, 159, 151, 80, 113, 213, 244, 1, 135, 158, 196, 42, 35, 188, 34, 158,
          226, 197, 167, 156, 122, 255, 249, 51, 138, 165, 184, 204, 139, 40, 45, 219, 126, 94,
          123, 217, 96, 188, 20, 13, 218, 70, 22, 164, 132, 101, 144, 201, 250, 150, 235, 217, 18,
          127, 95, 179, 248, 120, 136, 189, 251, 16, 52, 41, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32,
          152, 133, 202, 27, 99, 85, 36, 56, 12, 250, 95, 180, 10, 111, 219, 113, 134, 3, 33, 207,
          133, 94, 211, 249, 2, 27, 46, 223, 194, 115, 199, 65, 34, 88, 32, 252, 32, 247, 24, 222,
          29, 20, 127, 177, 66, 228, 134, 68, 136, 10, 215, 50, 79, 126, 176, 4, 140, 149, 224,
          81, 170, 17, 250, 107, 201, 36, 220>>

      {:ok, raw_attested_credential_data: raw_attested_credential_data}
    end

    test "returns attested credential data", context do
      {:ok, attested_credential_data, remain} =
        AttestedCredentialData.parse(context.raw_attested_credential_data)

      assert attested_credential_data.aaguid == "\xAD\xCE\0\x025\xBC\xC6\nd\x8B\v%\xF1\xF0U\x03"
      assert attested_credential_data.credential_id_length == 89

      assert attested_credential_data.credential_id ==
               <<1, 43, 142, 11, 202, 88, 37, 160, 223, 140, 244, 61, 19, 40, 232, 66, 71, 42, 19,
                 248, 100, 188, 164, 134, 85, 194, 159, 151, 80, 113, 213, 244, 1, 135, 158, 196,
                 42, 35, 188, 34, 158, 226, 197, 167, 156, 122, 255, 249, 51, 138, 165, 184, 204,
                 139, 40, 45, 219, 126, 94, 123, 217, 96, 188, 20, 13, 218, 70, 22, 164, 132, 101,
                 144, 201, 250, 150, 235, 217, 18, 127, 95, 179, 248, 120, 136, 189, 251, 16, 52,
                 41>>

      assert attested_credential_data.credential_public_key == %{
               -3 => %CBOR.Tag{
                 tag: :bytes,
                 value:
                   <<252, 32, 247, 24, 222, 29, 20, 127, 177, 66, 228, 134, 68, 136, 10, 215, 50,
                     79, 126, 176, 4, 140, 149, 224, 81, 170, 17, 250, 107, 201, 36, 220>>
               },
               -2 => %CBOR.Tag{
                 tag: :bytes,
                 value:
                   <<152, 133, 202, 27, 99, 85, 36, 56, 12, 250, 95, 180, 10, 111, 219, 113, 134,
                     3, 33, 207, 133, 94, 211, 249, 2, 27, 46, 223, 194, 115, 199, 65>>
               },
               -1 => 1,
               1 => 2,
               3 => -7
             }

      assert remain == ""
    end

    test "returns error if raw data is too short" do
      {:error, msg} = AttestedCredentialData.parse(<<1>>)

      assert msg == "attested credential data too short"
    end
  end
end
