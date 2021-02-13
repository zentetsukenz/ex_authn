defmodule ExAuthn.RegistrationCeremonyTest do
  use ExUnit.Case, async: true

  alias ExAuthn.{
    RegistrationCeremony,
    Option,
    User
  }

  alias ExAuthn.WebAuthn.{
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameter,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity
  }

  describe "begin/1" do
    test "retutns create ceremony" do
      user = %User{
        id: "user_1234",
        name: "user",
        display_name: "User Test"
      }

      option = %Option{
        rp: %{
          id: "localhost",
          name: "ExAuthn",
          origin: "http://localhost",
          icon: ""
        },
        attestation_preference: :none
      }

      assert {:ok,
              %RegistrationCeremony{
                option: %Option{
                  rp: %{
                    id: "localhost",
                    name: "ExAuthn",
                    origin: "http://localhost",
                    icon: ""
                  },
                  attestation_preference: :none,
                  authenticator_selection: %AuthenticatorSelectionCriteria{
                    authenticator_attachment: nil,
                    resident_key: nil,
                    user_verification: :preferred
                  }
                },
                user: %User{
                  id: "user_1234",
                  name: "user",
                  display_name: "User Test"
                },
                public_key_credential_creation_options: %PublicKeyCredentialCreationOptions{
                  attestation: :none,
                  authenticator_selection: %AuthenticatorSelectionCriteria{
                    authenticator_attachment: nil,
                    resident_key: nil,
                    user_verification: :preferred
                  },
                  challenge: _,
                  exclude_credentials: [],
                  extensions: nil,
                  pub_key_cred_params: [
                    %PublicKeyCredentialParameter{alg: -7, type: :public_key},
                    %PublicKeyCredentialParameter{alg: -8, type: :public_key},
                    %PublicKeyCredentialParameter{alg: -35, type: :public_key},
                    %PublicKeyCredentialParameter{alg: -36, type: :public_key},
                    %PublicKeyCredentialParameter{alg: -37, type: :public_key},
                    %PublicKeyCredentialParameter{alg: -38, type: :public_key},
                    %PublicKeyCredentialParameter{alg: -39, type: :public_key}
                  ],
                  rp: %PublicKeyCredentialRpEntity{
                    id: "localhost",
                    name: "ExAuthn"
                  },
                  timeout: nil,
                  user: %PublicKeyCredentialUserEntity{
                    display_name: "User Test",
                    id: "user_1234"
                  }
                }
              }} = RegistrationCeremony.begin(user, option)
    end
  end
end
