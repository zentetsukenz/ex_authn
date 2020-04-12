defmodule ExAuthn.BeginRegistrationOptions do
  @moduledoc """
  `BeginRegistrationOptions` module casts and validates relying party option for
  begin registration process.

  Relying party can specify runtime registration options. These options will
  override configuration values.

  Relying party can also specify `exclude_credentials` which will then be passed
  through client. Client will use these exclude credentials from the
  registration process. It's useful when relying party allows one user to have
  many credentials.
  """
  @moduledoc since: "1.0.0"

  alias ExAuthn.WebAuthn.{
    AuthenticatorSelectionCriteria,
    AttestationConveyancePreference,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialDescriptor
  }

  @type t :: %__MODULE__{
          rp: PublicKeyCredentialRpEntity.t() | nil,
          timeout: pos_integer() | nil,
          attestation: AttestationConveyancePreference.t() | nil,
          authenticator_selection:
            AuthenticatorSelectionCriteria.user_verification_requirement() | nil,
          exclude_credentials: list(PublicKeyCredentialDescriptor.t())
        }

  @type parse_params :: keyword() | %{optional(atom()) => any()}

  @type error_code :: :invalid_argument
  @type error_message :: String.t()

  defstruct rp: nil,
            timeout: nil,
            attestation: nil,
            authenticator_selection: nil,
            exclude_credentials: []

  @doc """
  Parse begin registration options in a form of map or keyword.

  Possible options
    - :rp
    - :authenticator_selection
    - :timeout
    - :attestation
    - :exclude_credentials
    - :extentions

  For the meanning of each key, please visit Web Authentication specification
  website.

  Some options will override the default configuration options. For example, if
  `:rp` is present, it will override rp configuration in application.

  Relying party can also exclude any credentials from registration process by
  passing `:exclude_credentials` options.

  All options are validated according to Web Authentication specification.

  Returns `%ExAuthn.BeginRegistrationOptions{}` struct or error.

  ## Examples

  Return ok and struct when parsing a valid option.

      iex> ExAuthn.BeginRegistrationOptions.parse(%{
      ...>   rp: %{name: "Ex Authn", id: "localhost:4500"},
      ...>   timeout: 59999,
      ...>   attestation: :indirect,
      ...>   user_verification: :required,
      ...>   exclude_credentials: [
      ...>     %{type: :public_key, id: "\x01\x02\x03\x04", transports: ["internal"]}
      ...>   ]
      ...> })
      {:ok, %ExAuthn.BeginRegistrationOptions{
        rp: %ExAuthn.WebAuthn.PublicKeyCredentialRpEntity{
          name: "Ex Authn",
          id: "localhost:4500"
        },
        timeout: 59999,
        attestation: :indirect,
        user_verification: :required,
        exclude_credentials: [
          %ExAuthn.WebAuthn.PublicKeyCredentialDescriptor{
            type: :public_key,
            id: "\x01\x02\x03\x04",
            transports: ["internal"]
          }
        ]
      }}

  And error with code and message describe the error when one of the option is
  invalid.

      iex> ExAuthn.BeginRegistrationOptions.parse(%{
      ...>   attestation: :i_dont_have_any_preference
      ...> })
      {:error, :invalid_argument, "attestation must be one of :none, :direct, or :indirect"}
  """
  @doc since: "1.0.0"
  @spec parse(parse_params()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(options) when is_map(options) do
    options
    |> Map.to_list()
    |> parse()
  end

  def parse(options) when is_list(options) do
    do_parse(options)
  end

  def parse(_) do
    {:error, :invalid_arguments, "options must be a map or a keyword"}
  end

  defp do_parse(options, begin_registration_options \\ %__MODULE__{})
  defp do_parse([], parsed_options), do: {:ok, parsed_options}

  defp do_parse([{:rp, raw_rp} | o], m) do
    case PublicKeyCredentialRpEntity.parse(raw_rp) do
      {:ok, rp} -> do_parse(o, %{m | rp: rp})
      {:error, code, message} -> {:error, code, message}
    end
  end

  defp do_parse([{:timeout, t} | o], m) when is_integer(t) and t > 0 do
    do_parse(o, %{m | timeout: t})
  end

  defp do_parse([{:timeout, _} | _], _) do
    {:error, :invalid_arguments, "timeout must be a positive integer"}
  end

  defp do_parse([{:attestation, attestation} | o], m) do
    case AttestationConveyancePreference.parse(attestation) do
      {:ok, _} -> do_parse(o, %{m | attestation: attestation})
      {:error, code, message} -> {:error, code, message}
    end
  end

  defp do_parse([{:authenticator_selection, a} | o], m) do
    case AuthenticatorSelectionCriteria.parse(a) do
      {:ok, authenticator_selection} ->
        do_parse(o, %{m | authenticator_selection: authenticator_selection})

      {:error, code, message} ->
        {:error, code, message}
    end
  end

  defp do_parse([{:exclude_credentials, c} | o], m) do
    case parse_exclude_credentials(c) do
      {:ok, credentials} -> do_parse(o, %{m | exclude_credentials: credentials})
      {:error, code, message} -> {:error, code, message}
    end
  end

  defp parse_exclude_credentials(credentials, credential_descriptors \\ [])
  defp parse_exclude_credentials([], credential_descriptors), do: {:ok, credential_descriptors}

  defp parse_exclude_credentials([c | cs], cds) do
    case PublicKeyCredentialDescriptor.parse(c) do
      {:ok, credential} -> parse_exclude_credentials(cs, cds ++ [credential])
      {:error, code, message} -> {:error, code, message}
    end
  end
end
