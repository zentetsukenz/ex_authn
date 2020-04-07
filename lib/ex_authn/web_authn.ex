defmodule ExAuthn.WebAuthn do
  @moduledoc """
  Web Authentication specification implementation module.

  Provides functions and Web Authentication type specifications according to
  [Web Authentication W3C specification](https://w3c.github.io/webauthn/).
  """

  alias ExAuthn.WebAuthn.{
    PublicKeyCredentialCreation,
    AuthenticatorData,
    Challenge,
    Options,
    Entity,
    ClientData,
    Attestation,
    Crypto
  }

  # Type delegetion

  @type public_key_credential_creation_options :: Options.public_key_credential_creation_options()
  @type credential_creation :: Options.credential_creation()
  @type user_verification_requirement :: AuthenticatorData.user_verification_requirement()
  @type conveyance_preference :: Options.conveyance_preference()
  @type authenticator_selection :: Options.authenticator_selection()
  @type client_credential_creation ::
          PublicKeyCredentialCreation.raw_public_key_credential_creation()

  defdelegate create_challenge(length_in_byte), to: Challenge, as: :generate
  defdelegate create_user(args), to: Entity
  defdelegate create_relying_party(args), to: Entity
  defdelegate create_authenticator_selection(args), to: Options

  defdelegate create_creation_options(args),
    to: Options,
    as: :create_public_key_credential_creation_options

  defdelegate create_credential_creation(args), to: Options

  @spec parse_client_credential_creation(
          PublicKeyCredentialCreation.raw_public_key_credential_creation()
        ) :: {:ok, PublicKeyCredentialCreation.t()} | {:error, String.t()}
  def parse_client_credential_creation(client_credential_creation) do
    PublicKeyCredentialCreation.parse(client_credential_creation)
  end

  @spec validate_credential_creation(
          PublicKeyCredentialCreation.t(),
          PublicKeyCredentialCreation.raw_public_key_credential_creation(),
          Challenge.t(),
          user_verification_requirement(),
          config_rp_id :: String.t(),
          config_rp_origin :: String.t()
        ) :: {:ok, PublicKeyCredentialCreation.t()} | {:error, String.t()}
  def validate_credential_creation(
        pkey_creation,
        raw_pkey_creation,
        challenge,
        user_verification,
        rp_id,
        rp_origin
      ) do
    %{response: %{client_data: client_data}} = pkey_creation

    with {:ok, _} <- ClientData.verify(client_data, challenge, :create, rp_id, rp_origin),
         {:ok, raw_response} <- fetch(raw_pkey_creation, "response"),
         {:ok, raw_client_data} <- fetch(raw_response, "client_data_json"),
         client_data_hash <- Crypto.hash(raw_client_data),
         {:ok, _} <-
           Attestation.verify(
             pkey_creation.response.attestation_object,
             rp_id,
             client_data_hash,
             user_verification
           ) do
      {:ok, pkey_creation}
    else
      {:error, msg} -> {:error, msg}
    end
  end

  defp fetch(h, field) do
    case Map.fetch(h, field) do
      :error -> {:error, "#{h} does not contain #{field}"}
      {:ok, value} -> {:ok, value}
    end
  end
end
