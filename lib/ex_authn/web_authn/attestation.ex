defmodule ExAuthn.WebAuthn.Attestation do
  alias ExAuthn.WebAuthn.{
    AuthenticatorData,
    ClientData,
    Crypto
  }

  @type t :: %__MODULE__{
          authenticator_data: AuthenticatorData.t(),
          format: String.t(),
          attestation_statement: any() | nil
        }

  @type raw_attestation :: String.t()

  defstruct authenticator_data: nil, format: nil, attestation_statement: nil

  @spec parse(raw_attestation()) :: {:ok, t()} | {:error, String.t()}
  def parse(raw_attestation) do
    with {:ok, decoded_attestation} <- base64_decode(raw_attestation),
         {:ok, attestation} <- cbor_decode(decoded_attestation),
         {:ok, auth_data} <- fetch(attestation, "authData"),
         {:ok, format} <- fetch(attestation, "fmt"),
         {:ok, att_stmt} <- fetch(attestation, "attStmt"),
         {:ok, authenticator_data} <- AuthenticatorData.parse(auth_data.value) do
      {:ok,
       %__MODULE__{
         authenticator_data: authenticator_data,
         format: format,
         attestation_statement: att_stmt
       }}
    else
      {:error, msg} -> {:error, msg}
    end
  end

  defp base64_decode(raw_attestation) do
    case Base.url_decode64(raw_attestation, padding: false) do
      {:ok, decoded_attestation} -> {:ok, decoded_attestation}
      :error -> {:error, "cannot decode attestation"}
    end
  end

  defp cbor_decode(decoded_attestation) do
    case CBOR.decode(decoded_attestation) do
      {:ok, attestation, _} -> {:ok, attestation}
      {:error, atom_msg} -> {:error, to_string(atom_msg)}
    end
  end

  defp fetch(h, field) do
    case Map.fetch(h, field) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, "field #{field} in attestation is missing"}
    end
  end

  @spec verify(
          t(),
          relying_party_id :: String.t(),
          ClientData.hashed_client_data(),
          AuthenticatorData.user_verification_requirement()
        ) :: {:ok, t()} | {:error, String.t()}
  def verify(%{format: format, attestation_statement: att_statement}, _, _, _)
      when format == "none" and byte_size(att_statement) != 0 do
    {:error, "attestation format none with attestation present"}
  end

  def verify(attestation, rp_id, _client_data_hash, user_verification) do
    with {:ok, _} <-
           AuthenticatorData.verify(
             attestation.authenticator_data,
             Crypto.hash(rp_id),
             user_verification
           ) do
      # TODO: Verify client_data_hash with its own format.
      #
      #   {:ok, _} = AttestationStatement.verify(attestation.attestation_statement, client_data_hash)
      #
      {:ok, attestation}
    else
      {:error, msg} -> {:error, msg}
    end
  end
end
