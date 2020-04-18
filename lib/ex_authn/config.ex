defmodule ExAuthn.Config do
  @moduledoc """
  Configuration module used by ExAuthn library for every call.

  Only one function available for Config module, the `load` function.

  When called, it loads all :ex_authn application environment variables
  and performs a validation.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          rp: relying_party(),
          attestation: :none | :indirect | :direct,
          authenticator_selection: %{
            user_verification: :required | :preferred | :discouraged
          },
          timeout: pos_integer(),
          pub_key_cred_params: list(pub_key_cred_param())
        }

  @type relying_party :: %{
          id: String.t(),
          name: String.t(),
          origin: String.t()
        }

  @type pub_key_cred_param :: %{
          type: :public_key,
          alg: integer()
        }

  @app_name :ex_authn

  defstruct rp: nil,
            attestation: nil,
            authenticator_selection: nil,
            timeout: nil,
            pub_key_cred_params: []

  @doc """
  Loads `ExAuthn` configurations from application environment and validate value
  correctness according to Web Authn specification.

  Returns configurations.

  ## Examples

      iex> ExAuthn.Config.load()
      %ExAuthn.Config{
        rp: %{
          id: "localhost",
          name: "Ex Authn",
          origin: "http://localhost:4000"
        },
        timeout: 60000,
        attestation: :direct,
        authenticator_selection: %{
          user_verification: :preferred
        },
        pub_key_cred_params: [
          %{type: :public_key, alg: -7},
          %{type: :public_key, alg: -8},
          %{type: :public_key, alg: -35},
          %{type: :public_key, alg: -36},
          %{type: :public_key, alg: -37},
          %{type: :public_key, alg: -38},
          %{type: :public_key, alg: -39}
        ]
      }

  """
  @doc since: "1.0.0"
  @spec load() :: t()
  def load do
    @app_name
    |> Application.get_all_env()
    |> build_config()
  end

  defp build_config(envs, config \\ %__MODULE__{}) do
    config
    |> cast(envs)
    |> validate()
  end

  defp cast(config, envs) do
    config
    |> cast_relying_party(envs)
    |> cast_timeout(envs)
    |> cast_attestation(envs)
    |> cast_user_verification(envs)
    |> cast_public_key_credential_params(envs)
  end

  defp cast_relying_party(config, envs) do
    relying_party = %{
      id: envs |> Keyword.get(:relying_party_id),
      name: envs |> Keyword.get(:relying_party_name),
      origin: envs |> Keyword.get(:relying_party_origin)
    }

    %{config | rp: relying_party}
  end

  defp cast_timeout(config, envs) do
    %{config | timeout: envs |> Keyword.get(:timeout)}
  end

  defp cast_attestation(config, envs) do
    %{config | attestation: envs |> Keyword.get(:attestation)}
  end

  defp cast_user_verification(config, envs) do
    %{
      config
      | authenticator_selection: %{
          user_verification: envs |> Keyword.get(:user_verification)
        }
    }
  end

  defp cast_public_key_credential_params(config, envs) do
    %{config | pub_key_cred_params: envs |> Keyword.get(:public_key_credential_parameters)}
  end

  defp validate(config) do
    # TODO: Perform validation based on WebAuthn specification requirements.
    config
  end
end
