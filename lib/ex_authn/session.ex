defmodule ExAuthn.Session do
  alias ExAuthn.WebAuthn

  @type t :: %__MODULE__{
          challenge: String.t(),
          user_id: binary(),
          allowed_credential_ids: list(binary()),
          user_verification: WebAuthn.user_verification_requirement()
        }

  defstruct challenge: nil, user_id: nil, allowed_credential_ids: nil, user_verification: nil
end
