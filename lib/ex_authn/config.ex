defmodule ExAuthn.Config do
  @moduledoc """
  Configuration module used by ExAuthn library for every call.

  Only one function available for Config module, the `load` function.

  When called, it loads all :ex_authn application environment variables
  and performs a validation.
  """
  @moduledoc since: "1.0.0"

  alias ExAuthn.WebAuthn

  @type t :: %__MODULE__{
          rp: relying_party(),
          attestation: :none | :indirect | :direct,
          user_verification: :required | :preferred | :discouraged,
          timeout: pos_integer()
        }

  @type relying_party :: %{
          id: String.t(),
          name: String.t(),
          origin: String.t()
        }

  @app_name :ex_authn

  defstruct rp: nil,
            attestation: nil,
            user_verification: nil,
            timeout: nil

  @doc """
  Loads `ExAuthn` configurations from application environment and validate value
  correctness according to Web Authn specification.

  Returns configurations.

  ## Examples

      iex> ExAuthn.Config.load()
      %ExAuthn.Config{
        relying_party: %{
          id: "localhost",
          name: "Ex Authn",
          origin: "http://localhost:4000"
        },
        timeout: 60000,
        attestation: :direct,
        user_verification: :preferred
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
  end

  defp cast_relying_party(config, envs) do
    relying_party = %{
      id: envs |> Keyword.get(:relying_party_id),
      name: envs |> Keyword.get(:relying_party_name),
      origin: envs |> Keyword.get(:relying_party_origin)
    }

    %{config | relying_party: relying_party}
  end

  defp cast_timeout(config, envs) do
    %{config | timeout: envs |> Keyword.get(:timeout)}
  end

  defp cast_attestation(config, envs) do
    %{config | attestation: envs |> Keyword.get(:attestation)}
  end

  defp cast_user_verification(config, envs) do
    %{config | user_verification: envs |> Keyword.get(:user_verification)}
  end

  defp validate(config) do
    # TODO: Perform validation based on WebAuthn specification requirements.
    config
  end
end
