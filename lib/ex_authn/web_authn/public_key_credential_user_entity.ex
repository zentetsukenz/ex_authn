defmodule ExAuthn.WebAuthn.PublicKeyCredentialUserEntity do
  @moduledoc """
  `PublicKeyCredentialUserEntity` module used to specify User attributes when
  creating a new credential.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          id: binary(),
          display_name: String.t()
        }

  @type args :: %{
          required(:id) => binary(),
          required(:display_name) => String.t()
        }

  @max_id_size 64

  defstruct id: nil, display_name: nil

  @doc """
  Cast and validate raw User into PublicKeyCredentialUserEntity.

  Cast and validate user argument, returns ok if success or error if user is
  invalid.

  ## Examples

  When all attributes are present, returns ok.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialUserEntity.cast_and_validate(%{
      ...>   id: "\x01",
      ...>   display_name: "Northern Lights"
      ...> })
      {:ok, %ExAuthn.WebAuthn.PublicKeyCredentialUserEntity{
        id: "\x01",
        display_name: "Northern Lights"
      }}

  When id is too long, returns error.

      iex> ExAuthn.WebAuthn.PublicKeyCredentialUserEntity.cast_and_validate(%{
      ...>   id: String.duplicate("\x01", 65),
      ...>   display_name: "Too Lonk"
      ...> })
      {:error, "id size must be less than or equal to 64 bytes"}

  """
  @doc since: "1.0.0"
  @spec cast_and_validate(args()) :: {:ok, t()} | {:error, String.t()}
  def cast_and_validate(%{id: _, display_name: _} = args) do
    args
    |> Enum.reduce_while(%__MODULE__{}, fn
      {:id, value}, user when byte_size(value) <= @max_id_size ->
        {:cont, %{user | id: value}}

      {:id, _}, _ ->
        {:halt, {:error, "id size must be less than or equal to #{@max_id_size} bytes"}}

      {:display_name, value}, user ->
        {:cont, %{user | display_name: value}}
    end)
    |> case do
      %__MODULE__{} = user -> {:ok, user}
      {:error, reason} -> {:error, reason}
    end
  end
end
