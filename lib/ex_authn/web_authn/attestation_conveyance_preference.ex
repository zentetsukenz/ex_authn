defmodule ExAuthn.WebAuthn.AttestationConveyancePreference do
  @moduledoc """
  `AttestationConveyancePreference` module defines possible values for
  attestation preference.

  Relying party can specify their preference regarding to how authenticator
  conveys attestation statement during credential generation.
  """
  @moduledoc since: "1.0.0"

  @type t :: :none | :indirect | :direct | :enterprise

  @spec default() :: :none
  def default(), do: :none
end
