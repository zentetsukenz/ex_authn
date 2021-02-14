defmodule ExAuthnTest do
  use ExUnit.Case, async: true

  import ExAuthn.Factory

  describe "begin_registration/2" do
    test "returns public key creation option" do
      %{id: user_id, display_name: user_display_name} = user = build(:user)
      %{rp: %{id: rp_id, name: rp_name}} = option = build(:option)

      assert {:ok,
              %ExAuthn.WebAuthn.PublicKeyCredentialCreationOptions{
                attestation: :none,
                authenticator_selection: %ExAuthn.WebAuthn.AuthenticatorSelectionCriteria{
                  authenticator_attachment: :platform,
                  resident_key: :preferred,
                  user_verification: :preferred
                },
                challenge: challenge,
                exclude_credentials: [],
                extensions: nil,
                pub_key_cred_params: [
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -7, type: :public_key},
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -8, type: :public_key},
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -35, type: :public_key},
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -36, type: :public_key},
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -37, type: :public_key},
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -38, type: :public_key},
                  %ExAuthn.WebAuthn.PublicKeyCredentialParameter{alg: -39, type: :public_key}
                ],
                rp: %ExAuthn.WebAuthn.PublicKeyCredentialRpEntity{
                  id: ^rp_id,
                  name: ^rp_name
                },
                timeout: 60_000,
                user: %ExAuthn.WebAuthn.PublicKeyCredentialUserEntity{
                  id: ^user_id,
                  display_name: ^user_display_name
                }
              }} = ExAuthn.create_public_key_credential_creation_options(user, option)

      assert 16 == byte_size(Base.url_decode64!(challenge))
    end
  end
end
