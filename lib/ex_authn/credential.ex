defmodule ExAuthn.Credential do
  alias ExAuthn.Authenticator

  @type t :: %__MODULE__{
          id: binary(),
          public_key: binary(),
          attestation_type: String.t(),
          authenticator: Authenticator.t()
        }

  defstruct id: nil, public_key: nil, attestation_type: nil, authenticator: nil
end
