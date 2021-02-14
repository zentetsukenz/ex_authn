defmodule ExAuthn.WebAuthn.CollectedClientData do
  @moduledoc """
  CollectedClientData represents the contextual bindings of both relying party
  and client.
  """

  alias ExAuthn.WebAuthn.{
    Challenge
  }

  @type t :: %__MODULE__{
          type: ceremony_type(),
          challenge: Challenge.t(),
          origin: String.t(),
          token_binding: token_binding() | nil,
          cross_origin: boolean() | nil
        }

  @type ceremony_type :: String.t()

  @type token_binding :: %{
          optional(:id) => String.t(),
          status: token_binding_status()
        }

  @type token_binding_status :: :present | :support

  @type raw_client_data :: base64_encoded_json_string()
  @type base64_encoded_json_string :: String.t()
  @type hashed_client_data :: String.t()

  @ceremony_type_mapping %{
    "webauthn.create" => :create,
    "webauthn.get" => :get
  }

  defstruct type: nil, challenge: nil, origin: nil, token_binding: nil, cross_origin: nil

  @spec parse(raw_client_data()) :: {:ok, t()} | {:error, String.t()}
  def parse(raw_client_data) do
    with {:ok, decoded_client_data} <- Base.url_decode64(raw_client_data, padding: false),
         {:ok, client_data} <- Jason.decode(decoded_client_data, keys: :atoms),
         {:ok, raw_ceremony_type} <- fetch(client_data, :type),
         {:ok, type} <- fetch(@ceremony_type_mapping, raw_ceremony_type),
         {:ok, challenge} <- fetch(client_data, :challenge),
         {:ok, origin} <- fetch(client_data, :origin) do
      {:ok,
       %__MODULE__{
         type: type,
         challenge: challenge,
         origin: origin
       }}
    else
      {:error, exception} -> {:error, Jason.DecodeError.message(exception)}
      {:fetch_error, msg} -> {:error, msg}
      :error -> {:error, "cannot decode client data"}
    end
  end

  defp fetch(h, field) do
    case Map.fetch(h, field) do
      :error -> {:fetch_error, "field #{field} in client data is missing"}
      {:ok, value} -> {:ok, value}
    end
  end
end
