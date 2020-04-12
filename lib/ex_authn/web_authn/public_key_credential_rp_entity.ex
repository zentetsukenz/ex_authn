defmodule ExAuthn.WebAuthn.PublicKeyCredentialRpEntity do
  @moduledoc """
  `PublicKeyCredentialRpEntity` module used to specify Relying Party attributes
  when creating new credential.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          name: String.t(),
          id: String.t() | nil
        }

  @type parse_params :: keyword() | %{optional(atom()) => any()}

  @type error_code :: :invalid_argument
  @type error_message :: String.t()

  defstruct name: nil, id: nil

  @doc """
  Parse raw Rp Entity in form of map or keyword.

  Possible options
    - :name
    - :id

  Casts and validates rp argument, returns ok if success or error if rp is
  invalid.

  ## Examples

  When valid name and id, returns ok with Rp entity struct.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialRpEntity.parse(%{
      ...>   name: "Cat Trumpet",
      ...>   id: "localhost:4500"
      ...> })
      {:ok, %ExAuthn.WebAuthn.PublicKeyCredentialRpEntity{name: "Cat Trumpet", id: "localhost:4500"}}

  When id is invalid, returns an error.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialRpEntity.parse(%{
      ...>   name: "Cat Trumpet",
      ...>   id: nil
      ...> })
      {:error, :invalid_argument, "id must be a binary"}

  Returns error when name is missing.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialRpEntity.parse(%{
      ...>   id: "localhost:4500"
      ...> })
      {:error, :invalid_argument, "name must be present"}

  """
  @doc since: "1.0.0"
  @spec parse(parse_params()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(options) when is_list(options), do: do_parse(options)

  def parse(options) when is_map(options) do
    options
    |> Map.to_list()
    |> parse()
  end

  defp do_parse(options, rp \\ %__MODULE__{})
  defp do_parse([], %{name: name} = rp) when not is_nil(name), do: {:ok, rp}
  defp do_parse([], _), do: {:error, :invalid_argument, "name must be present"}

  defp do_parse([{:name, name} | o], m) do
    do_parse(o, %{m | name: name})
  end

  defp do_parse([{:id, id} | o], m) when is_binary(id) do
    # TODO: Validate that ID is a valid domain string. e.g. accounts.example.com
    do_parse(o, %{m | id: id})
  end

  defp do_parse([{:id, _} | _], _), do: {:error, :invalid_argument, "id must be a binary"}
end
