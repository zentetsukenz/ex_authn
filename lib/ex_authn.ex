defmodule ExAuthn do
  @moduledoc """
  ExAuthn module implements Web Authentication API for registration and authentication.

  The credentials belong to user and are managed by WebAuthn Authenticator, which the
  relying party interacts through web application.

  You can read more info about Web Authentication API [here](https://w3c.github.io/webauthn/#sctn-api)
  """
  @moduledoc since: "1.0.0"

  alias ExAuthn.{
    Authenticator,
    Config,
    Session,
    Credential
  }

  alias ExAuthn.Protocol

  @type error :: {:error, reason()}
  @type reason :: String.t()

  @type user :: %{
          id: binary(),
          name: String.t(),
          display_name: String.t(),
          icon: String.t()
        }

  @type ok_begin_registration :: {:ok, Protocol.credential_creation(), Session.t()}
  @type ok_finish_registration :: {:ok, Credential.t()}

  @doc """
  Begin registration.

  Generate public key options and session data to be used in registration process.
  """
  @spec begin_registration(user(), %{}) :: ok_begin_registration() | error()
  @spec begin_registration(user(), Protocol.public_key_credential_creation_options()) ::
          ok_begin_registration() | error()
  def begin_registration(user, opts \\ %{})

  def begin_registration(user, opts) do
    config = Config.load()

    with {:ok, challenge} <- Protocol.create_challenge(32),
         {:ok, web_authn_user} <- Protocol.create_user(user),
         {:ok, relying_party} <- Protocol.create_relying_party(config.relying_party),
         {:ok, authenticator_selection} <-
           Protocol.create_authenticator_selection(%{
             require_resident_key: false,
             user_verification: :preferred
           }),
         {:ok, creation_options} <-
           %{
             challenge: challenge,
             user: web_authn_user,
             relying_party: relying_party,
             authenticator_selection: authenticator_selection,
             timeout: config.timeout,
             attestation: config.attestation_preference
           }
           |> Map.merge(opts)
           |> Protocol.create_creation_options(),
         {:ok, credential_creation} <- Protocol.create_credential_creation(creation_options),
         session <- %Session{user_id: web_authn_user.id, challenge: challenge} do
      {:ok, credential_creation, session}
    else
      {:error, msg} -> {:error, msg}
    end
  end

  @spec finish_registration(user(), Session.t(), Protocol.client_credential_creation()) ::
          ok_finish_registration() | error()
  def finish_registration(%{id: id}, %{user_id: user_id}, _) when id != user_id do
    {:error, "user and session id mismatch"}
  end

  def finish_registration(_user, session, client_credential_creation) do
    config = Config.load()

    with {:ok, credential_creation} <-
           Protocol.parse_client_credential_creation(client_credential_creation),
         {:ok, _} <-
           Protocol.validate_credential_creation(
             credential_creation,
             client_credential_creation,
             session.challenge,
             config.user_verification_requirement,
             config.relying_party.id,
             config.relying_party.origin
           ) do
      {:ok,
       %Credential{
         id:
           credential_creation.response.attestation_object.authenticator_data.attested_credential_data.credential_id,
         public_key:
           credential_creation.response.attestation_object.authenticator_data.attested_credential_data.credential_public_key,
         attestation_type: credential_creation.response.attestation_object.format,
         authenticator: %Authenticator{
           aaguid:
             credential_creation.response.attestation_object.authenticator_data.attested_credential_data.aaguid,
           sign_count:
             credential_creation.response.attestation_object.authenticator_data.sign_count
         }
       }}
    else
      {:error, msg} -> {:error, msg}
    end
  end
end
