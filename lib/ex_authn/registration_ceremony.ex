defmodule ExAuthn.RegistrationCeremony do
  @moduledoc """
  RegistrationCeremony performs a ceremony to create a public key credential for
  a user's relying party account.

  The registration ceremony contains two steps, begin and finish. The begin
  function takes user and option as a parameter to begin registration ceremony.
  It returns a public key credential creation option. Basically controls how
  user can create a credential.
  """

  alias ExAuthn.{
    RegistrationCeremony,
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

  @type t :: %__MODULE__{
          option: Option.t(),
          public_key_credential_creation_options: PublicKeyCredentialCreationOptions.t(),
          user: User.t()
        }

  defstruct option: nil,
            public_key_credential_creation_options: nil,
            user: nil

  @doc """
  Begins Web Authentication Registration Ceremony.

  Take user as a parameter and relying party options to begin a registration
  ceremony.

  Returns a Ceremony struct with necessary information for relying party
  javascript application to be used to begin user attestation.
  """
  @spec begin(User.t(), Option.t()) :: {:ok, t()} | {:error, String.t()}
  def begin(
        user,
        %Option{
          rp: rp,
          attestation_preference: attestation_preference,
          authenticator_selection: authenticator_selection,
          timeout: timeout
        } = option
      ) do
    with {:ok, pk_user} <-
           PublicKeyCredentialUserEntity.cast_and_validate(%{
             id: user.id,
             display_name: user.display_name
           }),
         {:ok, challenge} <- Challenge.generate(),
         {:ok, pk_rp} <- PublicKeyCredentialRpEntity.cast_and_validate(rp),
         pk <- %PublicKeyCredentialCreationOptions{
           attestation: attestation_preference,
           authenticator_selection: authenticator_selection,
           challenge: challenge,
           pub_key_cred_params: PublicKeyCredentialParameter.all(),
           rp: pk_rp,
           timeout: timeout,
           user: pk_user
         } do
      {:ok,
       %RegistrationCeremony{
         option: option,
         public_key_credential_creation_options: pk,
         user: user
       }}
    else
      {:error, reason} -> {:error, reason}
    end
  end
end
