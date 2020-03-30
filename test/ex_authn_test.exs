defmodule ExAuthnTest do
  use ExUnit.Case, async: true
  doctest ExAuthn

  alias ExAuthn.{
    User,
    Session
  }

  describe "begin_registration\0" do
    test "returns public key credential creation options with default options" do
      user = %User{id: <<1, 2>>, name: "iZen", display_name: "ZentetsuKen", icon: ""}
      {:ok, %{public_key: pkey_creation_options}, session} = ExAuthn.begin_registration(user)

      assert %{
               attestation: :direct,
               authenticator_selection: %{
                 require_resident_key: false,
                 user_verification: :preferred
               },
               challenge: pkey_challenge,
               parameters: [
                 %{algorithm: -8, type: :public_key},
                 %{algorithm: -7, type: :public_key},
                 %{algorithm: -35, type: :public_key},
                 %{algorithm: -36, type: :public_key},
                 %{algorithm: -37, type: :public_key},
                 %{algorithm: -38, type: :public_key},
                 %{algorithm: -39, type: :public_key},
                 %{algorithm: -65535, type: :public_key},
                 %{algorithm: -257, type: :public_key},
                 %{algorithm: -258, type: :public_key},
                 %{algorithm: -259, type: :public_key}
               ],
               relying_party: %{
                 credential: %{icon: "", name: "Wiwatta Mongkhonchit"},
                 id: "localhost"
               },
               timeout: 60000,
               user: %{
                 credential: %{icon: "", name: "iZen"},
                 display_name: "ZentetsuKen",
                 id: <<1, 2>>
               }
             } = pkey_creation_options

      assert %Session{
               allowed_credential_ids: nil,
               challenge: session_challenge,
               user_id: <<1, 2>>,
               user_verification: nil
             } = session

      assert pkey_challenge == session_challenge
    end
  end
end
