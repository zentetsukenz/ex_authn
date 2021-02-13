defmodule ExAuthn.WebAuthn.PublicKeyCredentialCreationOptions do
  alias ExAuthn.WebAuthn.{
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    Challenge,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameter,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity
  }

  @type t :: %__MODULE__{
          attestation: AttestationConveyancePreference.t(),
          authenticator_selection: AuthenticatorSelectionCriteria.t() | nil,
          challenge: Challenge.t(),
          exclude_credentials: list(PublicKeyCredentialDescriptor.t()),
          extensions: map() | nil,
          pub_key_cred_params: list(PublicKeyCredentialParameter.t()),
          rp: PublicKeyCredentialRpEntity.t(),
          timeout: pos_integer() | nil,
          user: PublicKeyCredentialUserEntity.t()
        }

  defstruct attestation: AttestationConveyancePreference.default(),
            authenticator_selection: nil,
            challenge: nil,
            exclude_credentials: [],
            extensions: nil,
            pub_key_cred_params: nil,
            rp: nil,
            timeout: nil,
            user: nil
end
