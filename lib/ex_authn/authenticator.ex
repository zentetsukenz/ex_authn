defmodule ExAuthn.Authenticator do
  @type t :: %__MODULE__{
          aaguid: binary(),
          sign_count: pos_integer(),
          clone_warning: boolean()
        }

  defstruct aaguid: nil, sign_count: nil, clone_warning: false
end
