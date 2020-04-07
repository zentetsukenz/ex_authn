defmodule ExAuthn.WebAuthn.Options do
  @moduledoc """
  Option types for ExAuthn functions.
  """

  alias ExAuthn.WebAuthn.{
    AuthenticatorData,
    Challenge,
    Entity,
    WebAuthnCose
  }

  @type credential_creation :: %{
          public_key: public_key_credential_creation_options()
        }

  @type credential_assertion :: %{
          public_key: public_key_credential_request_options()
        }

  @type public_key_credential_creation_options :: %{
          optional(:excluded_credentials) => list(credential_descriptor),
          optional(:extensions) => map(),
          optional(:timeout) => pos_integer(),
          optional(:authenticator_selection) => authenticator_selection(),
          optional(:attestation) => conveyance_preference(),
          challenge: Challenge.t(),
          relying_party: Entity.relying_party(),
          user: Entity.user(),
          parameters: list(credential_parameter())
        }

  @type public_key_credential_request_options :: %{
          challenge: Challenge.t(),
          timeout: pos_integer(),
          relying_party_id: String.t(),
          allowed_credentials: list(credential_descriptor()),
          user_verification: AuthenticatorData.user_verification_requirement(),
          extensions: map()
        }

  @type credential_parameter :: %{
          type: credential_type(),
          algorithm: WebAuthnCose.cose_algorithm_identifier()
        }
  @type credential_type :: :public_key

  @type authenticator_selection :: %{
          optional(:authenticator_attachment) => AuthenticatorData.authenticator_attachment(),
          optional(:resident_key) => AuthenticatorData.resident_key(),
          optional(:require_resident_key) => boolean(),
          optional(:user_verification) => AuthenticatorData.user_verification_requirement()
        }

  @type credential_descriptor :: %{
          type: credential_type(),
          id: binary(),
          transports: list(AuthenticatorData.authenticator_transport())
        }

  @type conveyance_preference :: :none | :indirect | :direct

  @doc """
  Create authenticator selection.

  ## Examples

      iex> ExAuthn.WebAuthn.Options.create_authenticator_selection(%{authenticator_attachment: :platform, resident_key: :required, require_resident_key: true, user_verification: :required})
      {:ok, %{authenticator_attachment: :platform, resident_key: :required, require_resident_key: true, user_verification: :required}}

      iex> ExAuthn.WebAuthn.Options.create_authenticator_selection(%{resident_key: :required, require_resident_key: true, user_verification: :required})
      {:ok, %{resident_key: :required, require_resident_key: true, user_verification: :required}}

      iex> ExAuthn.WebAuthn.Options.create_authenticator_selection(%{require_resident_key: true, user_verification: :required})
      {:ok, %{require_resident_key: true, user_verification: :required}}
  """
  @spec create_authenticator_selection(%{
          optional(:authenticator_attachment) => AuthenticatorData.authenticator_attachment(),
          optional(:resident_key) => AuthenticatorData.resident_key() | nil,
          optional(:require_resident_key) => boolean(),
          optional(:user_verification) => AuthenticatorData.user_verification_requirement()
        }) :: {:ok, authenticator_selection()}
  def create_authenticator_selection(args) do
    {:ok, args}
  end

  @doc """
  Create credential creation options.

  ## Examples

      iex> ExAuthn.WebAuthn.Options.create_public_key_credential_creation_options(%{
      ...>   challenge: "hrkmOd1y_vL-qvdIHYif0A==",
      ...>   relying_party: %{id: "localhost", credential: %{name: "test", icon: ""}},
      ...>   user: %{id: <<1, 2, 3, 4>>, display_name: "ZentetsuKen", credential: %{name: "aaa", icon: "bbb"}},
      ...>   parameters: [%{type: :public_key, algorithm: -7}],
      ...>   authenticator_selection: %{require_resident_key: false, user_verification: :preferred},
      ...>   timeout: 60000,
      ...>   attestation: :direct,
      ...>   excluded_credentials: [%{id: <<1, 2, 3, 4>>, type: :public_key, transports: ["internal"]}],
      ...>   extensions: %{}
      ...> })
      {:ok, %{
        challenge: "hrkmOd1y_vL-qvdIHYif0A==",
        relying_party: %{id: "localhost", credential: %{name: "test", icon: ""}},
        user: %{id: <<1, 2, 3, 4>>, display_name: "ZentetsuKen", credential: %{name: "aaa", icon: "bbb"}},
        parameters: [%{type: :public_key, algorithm: -7}],
        authenticator_selection: %{require_resident_key: false, user_verification: :preferred},
        timeout: 60000,
        attestation: :direct,
        excluded_credentials: [%{id: <<1, 2, 3, 4>>, type: :public_key, transports: ["internal"]}],
        extensions: %{}
      }}

      iex> ExAuthn.WebAuthn.Options.create_public_key_credential_creation_options(%{
      ...>   challenge: "hrkmOd1y_vL-qvdIHYif0A==",
      ...>   relying_party: %{id: "localhost", credential: %{name: "test", icon: ""}},
      ...>   user: %{id: <<1, 2, 3, 4>>, display_name: "ZentetsuKen", credential: %{name: "aaa", icon: "bbb"}}
      ...> })
      {:ok, %{
        challenge: "hrkmOd1y_vL-qvdIHYif0A==",
        relying_party: %{id: "localhost", credential: %{name: "test", icon: ""}},
        user: %{id: <<1, 2, 3, 4>>, display_name: "ZentetsuKen", credential: %{name: "aaa", icon: "bbb"}},
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
        ]
      }}
  """
  @spec create_public_key_credential_creation_options(%{
          optional(:excluded_credentials) => list(credential_descriptor),
          optional(:extensions) => map(),
          optional(:timeout) => pos_integer(),
          optional(:authenticator_selection) => authenticator_selection(),
          optional(:attestation) => conveyance_preference(),
          optional(:parameters) => list(credential_parameter()),
          challenge: Challenge.t(),
          relying_party: Entity.relying_party(),
          user: Entity.user()
        }) :: {:ok, public_key_credential_creation_options()}
  def create_public_key_credential_creation_options(%{parameters: _} = args) do
    {:ok, args}
  end

  def create_public_key_credential_creation_options(args) do
    args
    |> Map.put(:parameters, default_credential_parameters())
    |> create_public_key_credential_creation_options()
  end

  @doc """
  Create credential creation.

  ## Examples

      iex> ExAuthn.WebAuthn.Options.create_credential_creation(%{
      ...>   challenge: "hrkmOd1y_vL-qvdIHYif0A==",
      ...>   relying_party: %{id: "localhost", credential: %{name: "test", icon: ""}},
      ...>   user: %{id: <<1, 2, 3, 4>>, display_name: "ZentetsuKen", credential: %{name: "aaa", icon: "bbb"}},
      ...>   parameters: [%{type: :public_key, algorithm: -7}],
      ...>   authenticator_selection: %{require_resident_key: false, user_verification: :preferred},
      ...>   timeout: 60000,
      ...>   attestation: :direct,
      ...>   excluded_credentials: [%{id: <<1, 2, 3, 4>>, type: :public_key, transports: ["internal"]}],
      ...>   extensions: %{}
      ...> })
      {:ok, %{
        public_key: %{
          challenge: "hrkmOd1y_vL-qvdIHYif0A==",
          relying_party: %{id: "localhost", credential: %{name: "test", icon: ""}},
          user: %{id: <<1, 2, 3, 4>>, display_name: "ZentetsuKen", credential: %{name: "aaa", icon: "bbb"}},
          parameters: [%{type: :public_key, algorithm: -7}],
          authenticator_selection: %{require_resident_key: false, user_verification: :preferred},
          timeout: 60000,
          attestation: :direct,
          excluded_credentials: [%{id: <<1, 2, 3, 4>>, type: :public_key, transports: ["internal"]}],
          extensions: %{}
        }
      }}
  """
  @spec create_credential_creation(public_key_credential_creation_options()) ::
          {:ok, credential_creation()}
  def create_credential_creation(creation_options) do
    {:ok, %{public_key: creation_options}}
  end

  @doc """
  Return list of default credential parameters.

  ## Examples

  iex> ExAuthn.WebAuthn.Options.default_credential_parameters()
  ...> [
  ...>   %{algorithm: -8, type: :public_key},
  ...>   %{algorithm: -7, type: :public_key},
  ...>   %{algorithm: -35, type: :public_key},
  ...>   %{algorithm: -36, type: :public_key},
  ...>   %{algorithm: -37, type: :public_key},
  ...>   %{algorithm: -38, type: :public_key},
  ...>   %{algorithm: -39, type: :public_key},
  ...>   %{algorithm: -65535, type: :public_key},
  ...>   %{algorithm: -257, type: :public_key},
  ...>   %{algorithm: -258, type: :public_key},
  ...>   %{algorithm: -259, type: :public_key}
  ...> ]
  """
  @spec default_credential_parameters() :: list(credential_parameter())
  def default_credential_parameters do
    WebAuthnCose.all_cose_identifiers()
    |> Enum.map(fn i -> Map.new(type: :public_key, algorithm: i) end)
  end
end
