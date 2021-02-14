defmodule ExAuthn do
  @moduledoc """
  `ExAuthn` module implements Web Authentication API for registration and
  authentication.

  The concept of Web Authentication is that, credentials belong to user and are
  managed by WebAuthn Authenticator, which the relying party can interact
  through the web application.

  You can read more info about Web Authentication API
  [here](https://w3c.github.io/webauthn/#sctn-api)
  """
  @moduledoc since: "1.0.0"

  alias ExAuthn.{
    Option,
    User
  }

  alias ExAuthn.WebAuthn.{
    Challenge,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameter
  }

  @doc """
  Create a public key credential creation options.

  Generate public key credential creation options to be used to begin
  registration ceremony.

  Accepts User and Option struct.

  User is the registering user in the WebAuthn context. User must contain user
  handle (id) and display name.

  A user handle is an opaque byte sequence with a maximum size of 64 bytes, and
  is not meant to be displayed to the user.

  Option is the relying party specific values to be used as an option for
  authenticator to challenge user to create a public key.
  """
  @spec create_public_key_credential_creation_options(User.t(), Option.t()) ::
          {:error, String.t()} | {:ok, PublicKeyCredentialCreationOptions.t()}
  def create_public_key_credential_creation_options(
        %User{id: user_id, display_name: user_display_name},
        %Option{
          rp: rp,
          attestation_preference: attestation_preference,
          authenticator_selection: authenticator_selection,
          timeout: timeout
        }
      ) do
    with {:ok, pk_user} <-
           PublicKeyCredentialUserEntity.cast_and_validate(%{
             id: user_id,
             display_name: user_display_name
           }),
         {:ok, challenge} <- Challenge.generate(),
         {:ok, pk_rp} <- PublicKeyCredentialRpEntity.cast_and_validate(rp) do
      {:ok,
       %PublicKeyCredentialCreationOptions{
         attestation: attestation_preference,
         authenticator_selection: authenticator_selection,
         challenge: challenge,
         pub_key_cred_params: PublicKeyCredentialParameter.all(),
         rp: pk_rp,
         timeout: timeout,
         user: pk_user
       }}
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
