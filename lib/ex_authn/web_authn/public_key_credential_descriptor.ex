defmodule ExAuthn.WebAuthn.PublicKeyCredentialDescriptor do
  @moduledoc """
  PublicKeyCredentialDescriptor contains the attributes that are specified by
  caller when referring to a public key credential.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
    type: public_key_credential_type(),
    id: binary(),
    transports: list(transport())
  }

  @type public_key_credential_type :: :public_key
  @public_key_credential_type :public_key

  @type transport :: :usb | :nfc | :ble | :internal
  @transports [:usb, :nfc, :ble, :internal]

  @type error_code :: :invalid_arguments
  @type error_message :: String.t()

  defstruct type: nil, id: nil, transports: nil

  @doc """
  Parse credential descriptor map and convert to public key credential
  descriptor struct.

  Returns ok if credential descriptor arguments conform credential description
  format and return error if credential arguments is invalid.

  ## Examples

  If public key type credential and valid id is sent to the function, ok will be
  returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :public_key,
      ...>   id: "\x01\x02\x03\x04"
      ...> })
      {:ok, %__MODULE__{type: :public_key, id: "\x01\x02\x03\x04", transports: []}}

  If credential type is not a public key, error will be returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :private_key,
      ...>   id: "\x01"
      ...> })
      {:error, :invalid_arguments, "type must be public_key"}

  When transport is not one of the supported types, error will be returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :public_key,
      ...>   id: "\x01",
      ...>   transports: [:5g]
      ...> })
      {:error, :invalid_arguments, "transport must be usb, nfc, ble, or internal"}
  """
  @doc since: "1.0.0"
  @spec parse(map()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(%{type: :public_key, id: id} = args) when not is_nil(id) and byte_size(id) > 0 do
    transports = Map.get(args, :transports, [])

    %__MODULE__{
      type: :public_key,
      id: id,
    }
    |> validate_transports(transports)
  end
  def parse(%{type: _}), do: {:error, :invalid_arguments, "type must be public_key"}
  def parse(%{id: _}), do: {:error, :invalid_arguments, "id must be present"}
  def parse(_), do: {:error, :invalid_arguments, "type and id must be present"}

  defp validate_transports(credential, []), do: {:ok, %{credential | transports: []}}
  defp validate_transports(credential, transports) do
    if Enum.all?(transports, fn t -> Enum.member?(@transports, t) end) do
      {:ok, %{credential | transports: transports}}
    else
      {:error, :invalid_arguments, "transport must be usb, nfc, ble, or internal"}
    end
  end
end
