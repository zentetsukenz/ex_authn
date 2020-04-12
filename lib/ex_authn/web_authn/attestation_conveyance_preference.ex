defmodule ExAuthn.WebAuthn.AttestationConveyancePreference do
  @moduledoc """
  `AttestationConveyancePreference` module defines possible values for
  attestation preference.

  Relying party can specify their preference regarding to how authenticator
  conveys attestation statement during credential generation.
  """
  @moduledoc since: "1.0.0"

  @type t :: :none | :indirect | :direct
  @t [:none, :indirect, :direct]

  @type parse_params :: t()

  @type error_code :: :invalid_argument
  @type error_message :: String.t()

  @doc """
  Parse attestation value.

  Possible options
    - :none
    - :indirect
    - :direct

  For each option meaning, please refer to Web Authentication specfication.

  ## Examples

      iex> ExAuthn.WebAuthn.AttestationConveyancePreference.parse(:direct)
      {:ok, :direct}

      iex> ExAuthn.WebAuthn.AttestationConveyancePreference.parse(:directly)
      {:error, :invalid_argument, "attestation must be one of :none, :indirect or :direct"}
  """
  @doc since: "1.0.0"
  @spec parse(t()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(attestation) when attestation in @t do
    {:ok, attestation}
  end

  def parse(_) do
    {:error, :invalid_argument, "attestation must be one of :none, :indirect or :direct"}
  end
end
