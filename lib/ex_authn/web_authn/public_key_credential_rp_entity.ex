defmodule ExAuthn.WebAuthn.PublicKeyCredentialRpEntity do
  @moduledoc """
  `PublicKeyCredentialRpEntity` module used to specify Relying Party attributes
  when creating new credential.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          id: String.t() | nil,
          name: String.t()
        }

  @type args :: %{
          optional(:id) => String.t(),
          required(:name) => String.t()
        }

  defstruct id: nil, name: nil

  @doc """
  Cast and validate raw Relying Party into PublicKeyCredentialRpEntity.

  Cast and validate relying party argument, returns ok if success or error if
  relying party is invalid.

  ## Examples

  When all attributes are present, returns ok.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialRpEntity.cast_and_validate(%{
      ...>   id: "rp.localhost",
      ...>   name: "Relying Party Testing"
      ...> })
      {:ok, %ExAuthn.WebAuthn.PublicKeyCredentialRpEntity{
        id: "rp.localhost",
        name: "Relying Party Testing"
      }}

  """
  @doc since: "1.0.0"
  @spec cast_and_validate(args()) :: {:ok, t()}
  def cast_and_validate(%{name: _} = args) do
    rp =
      args
      |> Enum.reduce_while(%__MODULE__{}, fn
        {:id, value}, rp ->
          {:cont, %{rp | id: value}}

        {:name, value}, rp ->
          {:cont, %{rp | name: value}}
      end)

    {:ok, rp}
  end
end
