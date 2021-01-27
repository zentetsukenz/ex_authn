defmodule ExAuthn.Option do
  @moduledoc """
  An Option for ExAuthn operations.
  """

  alias ExAuthn.WebAuthn.{
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference
  }

  @type t :: %__MODULE__{
          rp: relying_party(),
          attestation_preference: AttestationConveyancePreference.t(),
          authenticator_selection: AuthenticatorSelectionCriteria.t(),
          timeout: pos_integer()
        }

  @type relying_party :: %{
          id: String.t(),
          name: String.t(),
          origin: String.t(),
          icon: String.t()
        }

  defstruct rp: nil,
            attestation_preference: AttestationConveyancePreference.default(),
            authenticator_selection: %AuthenticatorSelectionCriteria{},
            timeout: nil
end
