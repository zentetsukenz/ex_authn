defmodule ExAuthn.User do
  alias ExAuthn.Credential

  @type t :: %__MODULE__{
          id: binary(),
          name: String.t(),
          display_name: String.t(),
          icon: String.t(),
          credentials: list(Credential.t())
        }

  defstruct id: nil, name: nil, display_name: nil, icon: nil, credentials: []
end
