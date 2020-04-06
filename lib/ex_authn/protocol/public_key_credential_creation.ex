defmodule ExAuthn.Protocol.PublicKeyCredentialCreation do
  alias ExAuthn.Protocol.{
    AuthenticatorAttestation,
    Extension
  }

  @type t :: %__MODULE__{
          id: binary(),
          type: type(),
          raw_id: binary(),
          extensions: Extension.t(),
          response: AuthenticatorAttestation.t()
        }

  @type raw_public_key_credential_creation :: %{
          id: String.t(),
          type: String.t(),
          raw_id: String.t(),
          extensions: Extension.t(),
          response: AuthenticatorAttestation.raw_authenticator_attestation()
        }

  @type type :: :public_key

  defstruct id: nil, type: nil, raw_id: nil, extensions: nil, response: nil

  @spec parse(nil) :: {:error, String.t()}
  @spec parse(raw_public_key_credential_creation()) :: {:ok, t()} | {:error, String.t()}
  def parse(nil) do
    {:error, "credential creation payload must be present"}
  end

  def parse(raw_credential_creation) do
    with {:ok, id} <- parse_id(Map.get(raw_credential_creation, "id")),
         {:ok, type} <- parse_type(Map.get(raw_credential_creation, "type")),
         {:ok, authenticator_attestation} <-
           AuthenticatorAttestation.parse(Map.get(raw_credential_creation, "response")) do
      {:ok,
       %__MODULE__{
         id: id,
         type: type,
         raw_id: Map.get(raw_credential_creation, "raw_id"),
         response: authenticator_attestation,
         extensions: Map.get(raw_credential_creation, "extensions")
       }}
    else
      {:error, msg} -> {:error, msg}
    end
  end

  defp parse_id(nil) do
    {:error, "id is missing"}
  end

  defp parse_id(raw_id) do
    with {:ok, _} <- Base.url_decode64(raw_id, padding: false) do
      {:ok, raw_id}
    else
      :error -> {:error, "id is not base64 encoded"}
    end
  end

  defp parse_type(nil) do
    {:error, "type is missing"}
  end

  defp parse_type(raw_type) do
    if raw_type == "public-key" do
      {:ok, :public_key}
    else
      {:error, "type is not public key"}
    end
  end
end
