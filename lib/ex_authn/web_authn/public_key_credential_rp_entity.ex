defmodule ExAuthn.WebAuthn.PublicKeyCredentialRpEntity do
  @moduledoc """
  Rp Entity module used to supply Relying Party attributes when creating new
  credential.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
    name: String.t(),
    id: String.t() | nil,
  }

  @type error_code :: :invalid_id
  @type error_message :: String.t()

  defstruct name: nil, id: nil

  @doc """
  Parse raw Rp Entity to struct.

  Casts and validates rp argument, returns ok if success or error if rp is
  invalid.

  ## Examples

  When valid name and id, returns ok with Rp entity struct.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialRpEntity.parse(%{
      ...>   name: "Cat Trumpet",
      ...>   id: "localhost:4500"
      ...> })
      {:ok, %__MODULE__{name: "Cat Trumpet", id: "localhost:4500"}}

  When id is invalid, returns an error with id must be valid.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialRpEntity.parse(%{
      ...>   name: "Cat Trumpet",
      ...>   id: "http://localhost:4500"
      ...> })
      {:error, :invalid_id, "id must be a valid domain string"}
  """
  @doc since: "1.0.0"
  @spec parse(map()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(%{name: nil}) do
    {:error, :invalid_arguments, "name is required"}
  end
  def parse(%{id: id} = params) when not is_nil(id) do
    case validate_id(id) do
      {:ok, _} ->     parse(params)
      {:error, code, message} -> {:error, code, message}
    end
  end
  def parse(%{name: name} = params) do
    id = Map.get(params, :id, nil)

    %__MODULE__{
      name: name,
      id: id
    }
  end
  def parse(_) do
    {:error, :invalid_arguments, "invalid arguments"}
  end

  defp validate_id(id) do
    uri = URI.parse(id)

    if uri.host == id do
      {:ok, id}
    else
      {:error, :invalid_id, "id must be a valid domain string"}
    end
  end
end
