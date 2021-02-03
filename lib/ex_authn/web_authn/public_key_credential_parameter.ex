defmodule ExAuthn.WebAuthn.PublicKeyCredentialParameter do
  @moduledoc """
  Public key credential parameter is used to supplied additional paramter when
  creating credential.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          type: :public_key,
          alg: cose_algorithm_identifier()
        }

  @type cose_algorithm_identifier ::
          -7
          | -8
          | -35
          | -36
          | -37
          | -38
          | -39
  @cose_algorithm_identifiers [
    -7,
    -8,
    -35,
    -36,
    -37,
    -38,
    -39
  ]

  defstruct type: :public_key, alg: nil

  @doc """
  Return all algorithms.

  Returns recommended COSE algorithms.

  ## Examples

      iex> ExAuthn.WebAuthn.PublicKeyCredentialParameter.all()
      [
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -7},
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -8},
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -35},
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -36},
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -37},
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -38},
        %ExAuthn.WebAuthn.PublicKeyCredentialParameter{type: :public_key, alg: -39}
      ]
  """
  @spec all() :: list(t())
  def all, do: Enum.map(@cose_algorithm_identifiers, &%__MODULE__{alg: &1})
end
