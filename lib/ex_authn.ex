defmodule ExAuthn do
  @moduledoc """
  Documentation for `ExAuthn`.
  """

  alias ExAuthn.{
    Config,
    Session
  }

  alias ExAuthn.Protocol

  @type user_args :: %{
          id: binary(),
          name: String.t(),
          display_name: String.t(),
          icon: String.t()
        }

  @doc """
  Begin registration.

  Generate public key options and session data to be used in registration process.
  """
  @spec begin_registration(user_args(), %{}) ::
          {:ok, Protocol.credential_creation(), Session.t()}
          | {:error, String.t()}
  @spec begin_registration(user_args(), Protocol.public_key_credential_creation_options()) ::
          {:ok, Protocol.credential_creation(), Session.t()}
          | {:error, String.t()}
  def begin_registration(user, opts \\ %{})

  def begin_registration(user, opts) do
    with {:ok, challenge} <- Protocol.create_challenge(32),
         {:ok, web_authn_user} <- Protocol.create_user(user),
         {:ok, relying_party} <- Protocol.create_relying_party(Config.relying_party()),
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
             timeout: Config.timeout(),
             attestation: Config.attestation_preference()
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
end
