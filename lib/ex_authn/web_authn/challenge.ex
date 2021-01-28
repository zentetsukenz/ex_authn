defmodule ExAuthn.WebAuthn.Challenge do
  @moduledoc """
  A string intended to be used for generating the newly created credential's
  attestation object.
  """
  @moduledoc since: "1.0.0"

  @type t :: String.t()

  @minimum_size 16

  @doc """
  Generate challenge to be sent to authenticator as a part of attestation
  object.

  ## Examples

      iex> ExAuthn.WebAuthn.Challenge.generate(15)
      {:error, "length must be greater than or equal to 16"}

  """
  @doc since: "1.0.0"
  @spec generate(pos_integer()) :: {:ok, t()} | {:error, String.t()}
  def generate(length_in_byte \\ @minimum_size)

  def generate(length_in_byte) when length_in_byte < @minimum_size do
    {:error, "length must be greater than or equal to #{@minimum_size}"}
  end

  def generate(length_in_byte) do
    with {:ok, random_bytes} <- rand_bytes(length_in_byte),
         challenge <- Base.url_encode64(random_bytes) do
      {:ok, challenge}
    else
      {:error, :low_entropy} -> {:error, "low entropy"}
    end
  end

  defp rand_bytes(len) do
    try do
      bytes = :crypto.strong_rand_bytes(len)
      {:ok, bytes}
    rescue
      ErlangError -> {:error, :low_entropy}
    end
  end
end
