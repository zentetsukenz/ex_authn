defmodule ExAuthn.Config do
  @moduledoc """
  TODO: Document me.
  """

  alias ExAuthn.Protocol

  @type relying_party :: %{
          id: String.t(),
          display_name: String.t(),
          icon: String.t()
        }

  @spec relying_party() :: relying_party()
  def relying_party do
    %{
      id: "localhost",
      display_name: "Wiwatta Mongkhonchit",
      icon: ""
    }
  end

  @spec timeout :: pos_integer()
  def timeout do
    60000
  end

  @spec attestation_preference() :: Protocol.conveyance_preference()
  def attestation_preference do
    :direct
  end
end
