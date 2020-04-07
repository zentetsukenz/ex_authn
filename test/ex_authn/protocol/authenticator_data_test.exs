defmodule ExAuthn.WebAuthn.AuthenticatorDataTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.AuthenticatorData

  describe "parse/1" do
    setup do
      raw_auth_data =
        <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143, 228, 174,
          185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99, 69, 94, 138, 21, 68, 173,
          206, 0, 2, 53, 188, 198, 10, 100, 139, 11, 37, 241, 240, 85, 3, 0, 89, 1, 43, 142, 11,
          202, 88, 37, 160, 223, 140, 244, 61, 19, 40, 232, 66, 71, 42, 19, 248, 100, 188, 164,
          134, 85, 194, 159, 151, 80, 113, 213, 244, 1, 135, 158, 196, 42, 35, 188, 34, 158, 226,
          197, 167, 156, 122, 255, 249, 51, 138, 165, 184, 204, 139, 40, 45, 219, 126, 94, 123,
          217, 96, 188, 20, 13, 218, 70, 22, 164, 132, 101, 144, 201, 250, 150, 235, 217, 18, 127,
          95, 179, 248, 120, 136, 189, 251, 16, 52, 41, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 152,
          133, 202, 27, 99, 85, 36, 56, 12, 250, 95, 180, 10, 111, 219, 113, 134, 3, 33, 207, 133,
          94, 211, 249, 2, 27, 46, 223, 194, 115, 199, 65, 34, 88, 32, 252, 32, 247, 24, 222, 29,
          20, 127, 177, 66, 228, 134, 68, 136, 10, 215, 50, 79, 126, 176, 4, 140, 149, 224, 81,
          170, 17, 250, 107, 201, 36, 220>>

      {:ok, raw_auth_data: raw_auth_data}
    end

    test "returns authenticator data", context do
      {:ok, auth_data} = AuthenticatorData.parse(context.raw_auth_data)

      assert auth_data.rp_id_hash ==
               "I\x96\r\xE5\x88\x0E\x8Cht4\x17\x0Fdv`[\x8F䮹\xA2\x862Ǚ\\\xF3\xBA\x83\x1D\x97c"

      assert auth_data.flags == %{
               user_present: true,
               user_verified: true,
               attested_credential_data: true,
               has_extensions: false
             }

      assert auth_data.sign_count == 1_586_107_716
      assert auth_data.attested_credential_data != nil
      assert auth_data.extensions == nil
    end
  end

  describe "verify/3" do
    test "returns error if require user verification but user not verify" do
      {:error, msg} =
        AuthenticatorData.verify(
          %AuthenticatorData{
            rp_id_hash: <<1, 2, 3, 4>>,
            flags: %{user_verified: false}
          },
          <<1, 2, 3, 4>>,
          :required
        )

      assert msg == "user verification required"
    end

    test "returns error if user not present" do
      {:error, msg} =
        AuthenticatorData.verify(
          %AuthenticatorData{
            rp_id_hash: <<1, 2, 3, 4>>,
            flags: %{user_present: false}
          },
          <<1, 2, 3, 4>>,
          :required
        )

      assert msg == "user not present"
    end

    test "returns error if rp_id mismatch" do
      {:error, msg} =
        AuthenticatorData.verify(
          %AuthenticatorData{
            rp_id_hash: <<1, 2, 3, 4>>,
            flags: %{user_present: true, user_verified: true}
          },
          <<1, 2, 3, 5>>,
          :required
        )

      assert msg == "relying party id mismatch"
    end

    test "returns authenticator data" do
      {:ok, auth_data} =
        AuthenticatorData.verify(
          %AuthenticatorData{
            rp_id_hash: <<1, 2, 3, 4>>,
            flags: %{
              user_present: true,
              user_verified: true,
              attested_credential_data: false,
              has_extensions: false
            },
            sign_count: 1234
          },
          <<1, 2, 3, 4>>,
          :required
        )

      assert auth_data.rp_id_hash == <<1, 2, 3, 4>>

      assert auth_data.flags == %{
               user_present: true,
               user_verified: true,
               attested_credential_data: false,
               has_extensions: false
             }

      assert auth_data.sign_count == 1234
      assert auth_data.attested_credential_data == nil
      assert auth_data.extensions == nil
    end
  end
end
