defmodule ExAuthn.Protocol.Crypto do
  @spec hash(binary()) :: binary()
  def hash(bytes) do
    :crypto.hash_init(:sha256)
    |> :crypto.hash_update(bytes)
    |> :crypto.hash_final()
  end
end
