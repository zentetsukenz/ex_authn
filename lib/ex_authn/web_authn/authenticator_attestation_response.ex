defmodule ExAuthn.WebAuthn.AuthenticatorAttestationResponse do
  @moduledoc """
  AuthenticatorAttestationResponse represents the authenticator's response to
  the client request for the creation of a new public key credential.
  """

  @type t :: %__MODULE__{
          client_data_json: binary(),
          attestation_object: binary()
        }

  @type raw_authenticator_attestation :: %{
          optional(String.t()) => String.t()
        }

  defstruct client_data_json: nil, attestation_object: nil
end
