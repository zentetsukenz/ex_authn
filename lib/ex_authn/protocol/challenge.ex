defmodule ExAuthn.Protocol.Challenge do
  @type t :: String.t()

  @doc """
  Generate challenge to be sent to authenticator.

  ## Examples

      iex> ExAuthn.Protocol.Challenge.generate(15)
      {:error, "length must be at least 16"}
  """
  @spec generate(pos_integer()) :: {:ok, t()} | {:error, String.t()}
  def generate(length_in_byte \\ 16)

  def generate(length_in_byte) when length_in_byte < 16 do
    {:error, "length must be at least 16"}
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
