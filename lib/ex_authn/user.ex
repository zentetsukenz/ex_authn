defmodule ExAuthn.User do
  @moduledoc """
  `User` module defines a user struct for creadential creation.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          id: binary(),
          name: String.t(),
          display_name: String.t()
        }

  defstruct id: nil, name: nil, display_name: nil
end
