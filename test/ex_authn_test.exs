defmodule ExAuthnTest do
  use ExUnit.Case, async: true
  import ExAuthn.Factory
  doctest ExAuthn

  @default_parameters [
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
  ]

  @default_authenticator_selection %{
    require_resident_key: false,
    user_verification: :preferred
  }

  @default_relying_party %{
    credential: %{icon: "", name: "Ex Authn"},
    id: "localhost"
  }

  @default_attestation :direct
  @default_timeout 60000

  describe "begin registration with valid user without options" do
    setup do
      user = user_args_factory()
      {:ok, pkey_creation_options, session} = ExAuthn.begin_registration(user)

      {:ok,
       %{
         user_args: user,
         public_key_creation_options: pkey_creation_options,
         session: session
       }}
    end

    test "returns public key credential creation options with default values", context do
      %{public_key_creation_options: pkey_creation_options} = context

      assert %{
               public_key: %{
                 attestation: @default_attestation,
                 authenticator_selection: @default_authenticator_selection,
                 challenge: _pkey_challenge,
                 parameters: @default_parameters,
                 relying_party: @default_relying_party,
                 timeout: @default_timeout,
                 user: _credential_user
               }
             } = pkey_creation_options
    end

    test "returns same challenge in credential options and session", context do
      %{public_key: %{challenge: pkey_challenge}} = context.public_key_creation_options
      %{challenge: session_challenge} = context.session

      assert pkey_challenge == session_challenge
    end

    test "return same user_id in credential options and session", context do
      %{public_key: %{user: pkey_user}} = context.public_key_creation_options
      %{user_id: session_user_id} = context.session

      assert pkey_user.id == context.user_args.id
      assert session_user_id == context.user_args.id
    end

    test "returns same user information", context do
      %{public_key: %{user: user}} = context.public_key_creation_options
      user_args = context.user_args

      assert user == %{
               credential: %{icon: "", name: user_args.name},
               display_name: user_args.display_name,
               id: user_args.id
             }
    end
  end

  describe "begin registration with valid user and options" do
    setup do
      user = user_args_factory()
      {:ok, user: user}
    end

    test "returns override authenticator selection options", %{user: user} do
      options = %{
        authenticator_selection: %{
          user_verification: :discouraged
        }
      }

      {:ok, %{public_key: pkey_creation_options}, session} =
        ExAuthn.begin_registration(user, options)

      assert %{
               attestation: @default_attestation,
               authenticator_selection: %{
                 user_verification: :discouraged
               },
               challenge: pkey_challenge,
               parameters: @default_parameters,
               relying_party: @default_relying_party,
               timeout: @default_timeout,
               user: pkey_user
             } = pkey_creation_options

      assert pkey_user == %{
               credential: %{icon: "", name: user.name},
               display_name: user.display_name,
               id: user.id
             }

      assert %ExAuthn.Session{
               allowed_credential_ids: nil,
               challenge: session_challenge,
               user_id: session_user_id,
               user_verification: nil
             } = session

      assert session_challenge == pkey_challenge
      assert session_user_id == user.id
    end

    test "returns override credential exclusion list", %{user: user} do
      options = %{
        excluded_credentials: [
          %{
            type: :public_key,
            id: <<1, 2>>,
            transports: [:usb]
          }
        ]
      }

      {:ok, %{public_key: pkey_creation_options}, session} =
        ExAuthn.begin_registration(user, options)

      assert %{
               attestation: @default_attestation,
               authenticator_selection: @default_authenticator_selection,
               challenge: pkey_challenge,
               parameters: @default_parameters,
               relying_party: @default_relying_party,
               timeout: @default_timeout,
               user: pkey_user,
               excluded_credentials: [
                 %{
                   type: :public_key,
                   id: <<1, 2>>,
                   transports: [:usb]
                 }
               ]
             } = pkey_creation_options

      assert pkey_user == %{
               credential: %{icon: "", name: user.name},
               display_name: user.display_name,
               id: user.id
             }

      assert %ExAuthn.Session{
               allowed_credential_ids: nil,
               challenge: session_challenge,
               user_id: session_user_id,
               user_verification: nil
             } = session

      assert session_challenge == pkey_challenge
      assert session_user_id == user.id
    end

    test "returns override attestation", %{user: user} do
      options = %{
        attestation: :none
      }

      {:ok, %{public_key: pkey_creation_options}, session} =
        ExAuthn.begin_registration(user, options)

      assert %{
               attestation: :none,
               authenticator_selection: @default_authenticator_selection,
               challenge: pkey_challenge,
               parameters: @default_parameters,
               relying_party: @default_relying_party,
               timeout: @default_timeout,
               user: pkey_user
             } = pkey_creation_options

      assert pkey_user == %{
               credential: %{icon: "", name: user.name},
               display_name: user.display_name,
               id: user.id
             }

      assert %ExAuthn.Session{
               allowed_credential_ids: nil,
               challenge: session_challenge,
               user_id: session_user_id,
               user_verification: nil
             } = session

      assert session_challenge == pkey_challenge
      assert session_user_id == user.id
    end

    test "returns override extensions", %{user: user} do
      options = %{
        extensions: %{extension: "ext"}
      }

      {:ok, %{public_key: pkey_creation_options}, session} =
        ExAuthn.begin_registration(user, options)

      assert %{
               attestation: @default_attestation,
               authenticator_selection: @default_authenticator_selection,
               challenge: pkey_challenge,
               parameters: @default_parameters,
               relying_party: @default_relying_party,
               timeout: @default_timeout,
               user: pkey_user,
               extensions: %{extension: "ext"}
             } = pkey_creation_options

      assert pkey_user == %{
               credential: %{icon: "", name: user.name},
               display_name: user.display_name,
               id: user.id
             }

      assert %ExAuthn.Session{
               allowed_credential_ids: nil,
               challenge: session_challenge,
               user_id: session_user_id,
               user_verification: nil
             } = session

      assert session_challenge == pkey_challenge
      assert session_user_id == user.id
    end
  end

  describe "finish_registration/3" do
    setup do
      params = %{
        "id" =>
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        "raw_id" =>
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        "response" => %{
          "attestation_object" =>
            "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOXTBMnA6EihBVqknuxdbzLkn5V39V3NJOsohI-ZHnzfAiEAvxraExcTuAYCwExCkjj40WGt_Q6n7HC0QGEPXbdgwEloYXV0aERhdGFY3UmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV6KFUStzgACNbzGCmSLCyXx8FUDAFkBK44LylgloN-M9D0TKOhCRyoT-GS8pIZVwp-XUHHV9AGHnsQqI7winuLFp5x6__kziqW4zIsoLdt-XnvZYLwUDdpGFqSEZZDJ-pbr2RJ_X7P4eIi9-xA0KaUBAgMmIAEhWCCYhcobY1UkOAz6X7QKb9txhgMhz4Ve0_kCGy7fwnPHQSJYIPwg9xjeHRR_sULkhkSICtcyT36wBIyV4FGqEfprySTc",
          "client_data_json" =>
            "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
        },
        "type" => "public-key"
      }

      c = "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo"

      {:ok, params: params, challenge: c}
    end

    test "returns error if user id mismatch" do
      {:error, msg} = ExAuthn.finish_registration(%{id: 1}, %{user_id: 2}, nil)

      assert msg == "user and session id mismatch"
    end

    test "returns credential", context do
      {:ok, credential} =
        ExAuthn.finish_registration(%{}, %{challenge: context.challenge}, context.params)

      assert credential.id ==
               <<1, 43, 142, 11, 202, 88, 37, 160, 223, 140, 244, 61, 19, 40, 232, 66, 71, 42, 19,
                 248, 100, 188, 164, 134, 85, 194, 159, 151, 80, 113, 213, 244, 1, 135, 158, 196,
                 42, 35, 188, 34, 158, 226, 197, 167, 156, 122, 255, 249, 51, 138, 165, 184, 204,
                 139, 40, 45, 219, 126, 94, 123, 217, 96, 188, 20, 13, 218, 70, 22, 164, 132, 101,
                 144, 201, 250, 150, 235, 217, 18, 127, 95, 179, 248, 120, 136, 189, 251, 16, 52,
                 41>>

      assert credential.public_key == %{
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

      assert credential.attestation_type == "packed"

      assert credential.authenticator == %ExAuthn.Authenticator{
               aaguid: <<173, 206, 0, 2, 53, 188, 198, 10, 100, 139, 11, 37, 241, 240, 85, 3>>,
               clone_warning: false,
               sign_count: 1_586_107_716
             }
    end
  end
end
