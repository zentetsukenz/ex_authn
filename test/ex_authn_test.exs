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
    credential: %{icon: "", name: "Wiwatta Mongkhonchit"},
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
end
