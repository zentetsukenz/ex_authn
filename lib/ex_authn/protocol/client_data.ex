defmodule ExAuthn.Protocol.ClientData do
  alias ExAuthn.Protocol.{
    Challenge
  }

  @type t :: %__MODULE__{
          type: ceremony_type(),
          challenge: Challenge.t(),
          origin: String.t(),
          token_binding: token_binding() | nil,
          cross_origin: boolean() | nil
        }

  @type ceremony_type :: :create | :assert

  @type token_binding :: %{
          optional(:id) => String.t(),
          status: token_binding_status()
        }

  @type token_binding_status :: :present | :support | :not_support

  @type raw_client_data :: base64_encoded_json_string()
  @type base64_encoded_json_string :: String.t()
  @type hashed_client_data :: String.t()

  @ceremony_type_mapping %{
    "webauthn.create" => :create,
    "webauthn.assert" => :assert
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

  @spec verify(
          t(),
          Challenge.t(),
          ceremony_type(),
          config_rp_id :: String.t(),
          config_rp_origin :: String.t()
        ) :: {:ok, t()} | {:error, String.t()}
  def verify(%{type: type}, _, :create, _, _) when type != :create do
    {:error, "expect ceremony type to be create"}
  end

  def verify(%{challenge: challenge}, session_challenge, :create, _, _)
      when challenge != session_challenge do
    {:error, "challenge mismatch"}
  end

  def verify(%{origin: origin}, _, :create, _, config_rp_origin)
      when origin != config_rp_origin do
    {:error, "origin mismatch"}
  end

  def verify(%{token_binding: token_binding}, _, :create, _, _) when token_binding != nil do
    %{status: status} = token_binding
    verify_token_binding_status(status)
  end

  def verify(client_data, _, :create, _, _) do
    {:ok, client_data}
  end

  defp verify_token_binding_status(nil) do
    {:error, "token binding present without status"}
  end

  defp verify_token_binding_status(status) do
    if !Enum.member?([:present, :supported, :not_supported], status) do
      {:error, "invalid token binding status"}
    end
  end
end
