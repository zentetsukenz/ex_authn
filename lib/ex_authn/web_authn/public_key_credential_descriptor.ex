defmodule ExAuthn.WebAuthn.PublicKeyCredentialDescriptor do
  @moduledoc """
  `PublicKeyCredentialDescriptor` describes credential specified by client.

  It mirrors the field of the `PublicKeyCredential`.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          type: public_key_credential_type(),
          id: binary(),
          transports: list(transport())
        }

  @type parse_params :: keyword() | %{optional(atom()) => any()}

  @type error_code :: :invalid_argument
  @type error_message :: String.t()

  @type public_key_credential_type :: :public_key

  @type transport :: :usb | :nfc | :ble | :internal
  @transports [:usb, :nfc, :ble, :internal]

  defstruct type: nil, id: nil, transports: []

  @doc """
  Parse credential descriptor in a form of map or keyword.

  Possible options
    - :type
    - :id
    - :transports

  Returns `%ExAuthn.WebAuthn.PublicKeyCredentialDescriptor{}` struct or error.

  ## Examples

  If public key type credential and valid id is sent to the function, ok will be
  returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :public_key,
      ...>   id: "\x01\x02\x03\x04"
      ...> })
      {:ok, %ExAuthn.WebAuthn.PublicKeyCredentialDescriptor{
        type: :public_key,
        id: "\x01\x02\x03\x04",
        transports: []
      }}

  If credential type is not a public key, error will be returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :private_key,
      ...>   id: "\x01"
      ...> })
      {:error, :invalid_argument, "type must be :public_key"}

  When transport is not one of the supported types, error will be returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :public_key,
      ...>   id: "\x01",
      ...>   transports: ["5g"]
      ...> })
      {:error, :invalid_argument, "transport must be one of :usb, :nfc, :ble, or :internal"}

  If type or id is missing, error will be returned.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   type: :public_key
      ...> })
      {:error, :invalid_argument, "type and id must be present"}

      iex> ExAuthn.WebAuthn.PublicKeyCredentialDescriptor.parse(%{
      ...>   id: "\x01\x02\x03\x04"
      ...> })
      {:error, :invalid_argument, "type and id must be present"}

  """
  @doc since: "1.0.0"
  @spec parse(parse_params()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(options) when is_list(options), do: do_parse(options)

  def parse(options) when is_map(options) do
    options
    |> Map.to_list()
    |> parse()
  end

  def parse(_) do
    {:error, :invalid_argument, "public_key_credential_descriptor must be a map or a keyword"}
  end

  defp do_parse(options, pkey_descriptor \\ %__MODULE__{})

  defp do_parse([], %{type: t, id: i} = pkey_descriptor) when not is_nil(t) and not is_nil(i) do
    {:ok, pkey_descriptor}
  end

  defp do_parse([], _), do: {:error, :invalid_argument, "type and id must be present"}

  defp do_parse([{:type, :public_key} | o], pkey_descriptor) do
    do_parse(o, %{pkey_descriptor | type: :public_key})
  end

  defp do_parse([{:type, _} | _], _), do: {:error, :invalid_argument, "type must be :public_key"}

  defp do_parse([{:id, id} | o], pkey_descriptor) when is_binary(id) and byte_size(id) > 0 do
    do_parse(o, %{pkey_descriptor | id: id})
  end

  defp do_parse([{:id, _} | _], _) do
    {:error, :invalid_argument, "id must be present"}
  end

  defp do_parse([{:transports, t} | o], pkey_descriptor) do
    case parse_transports(t) do
      {:ok, transports} -> do_parse(o, %{pkey_descriptor | transports: transports})
      {:error, code, message} -> {:error, code, message}
    end
  end

  defp parse_transports(ts, transports \\ [])
  defp parse_transports([], transports), do: {:ok, transports}

  defp parse_transports([t | ts], transports) when t in @transports do
    parse_transports(ts, transports ++ [t])
  end

  defp parse_transports(_, _) do
    {:error, :invalid_argument, "transport must be one of :usb, :nfc, :ble, or :internal"}
  end
end
