defmodule ExAuthn.WebAuthn.AuthenticatorAttestation do
  alias ExAuthn.WebAuthn.{
    Attestation,
    ClientData
  }

  @type t :: %__MODULE__{
          client_data: ClientData.t(),
          attestation_object: Attestation.t()
        }

  @type raw_authenticator_attestation :: %{
          optional(String.t()) => String.t()
        }

  defstruct client_data: nil, attestation_object: nil

  @spec parse(nil) :: {:error, String.t()}
  @spec parse(raw_authenticator_attestation()) :: {:ok, t()} | {:error, String.t()}
  def parse(nil) do
    {:error, "authenticator attestation is missing"}
  end

  def parse(%{
        "client_data_json" => client_data_json,
        "attestation_object" => attestation_object
      }) do
    with {:ok, client_data} <- ClientData.parse(client_data_json),
         {:ok, attestation} <- Attestation.parse(attestation_object) do
      {:ok,
       %__MODULE__{
         client_data: client_data,
         attestation_object: attestation
       }}
    else
      {:error, msg} -> {:error, msg}
    end
  end

  def parse(_) do
    {:error, "client data or attestation object is missing"}
  end
end
