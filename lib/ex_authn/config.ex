defmodule ExAuthn.Config do
  @moduledoc """
  TODO: Document me.
  """

  alias ExAuthn.Protocol

  @type t :: %__MODULE__{
          id: String.t(),
          display_name: String.t(),
          icon: String.t(),
          origin: String.t(),
          attestation_preference: Protocol.conveyance_preference(),
          authenticator_selection: Protocol.authenticator_selection(),
          timeout: pos_integer()
        }

  @type relying_party :: %{
          id: String.t(),
          display_name: String.t(),
          icon: String.t()
        }

  defstruct id: nil,
            display_name: nil,
            icon: nil,
            origin: nil,
            attestation_preference: nil,
            authenticator_selection: nil,
            timeout: nil

  @spec relying_party() :: relying_party()
  def relying_party do
    %{
      id: "localhost",
      display_name: "Wiwatta Mongkhonchit",
      icon: ""
    }
  end

  @spec origin() :: String.t()
  def origin do
    "http://localhost:4000"
  end

  @spec timeout :: pos_integer()
  def timeout do
    60000
  end

  @spec attestation_preference() :: Protocol.conveyance_preference()
  def attestation_preference do
    :direct
  end

  @spec user_verification() :: Protocol.user_verification_requirement()
  def user_verification do
    :required
  end
end
