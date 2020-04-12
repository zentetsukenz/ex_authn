defmodule ExAuthn.WebAuthn.AuthenticatorSelectionCriteria do
  @moduledoc """
  `AuthenticatorSelectionCriteria` module defines options for client
  authenticator.

  Relying party can specify their requirement regarding authenticator
  attributes. For example, relying party can tell browser to force a use to use
  a cross platform authenticator, e.g. YubiKey by setting
  `:authenticator_attachment` option to `cross_platform`.

  `:user_verification` have a default value to `:preferred` but relying party
  can override it to `nil`. But please do aware that, doing so in registration
  or authentication process could allow authenticator to skip user verification
  process which could lead to user impersonation.
  """
  @moduledoc since: "1.0.0"

  @type t :: %__MODULE__{
          authenticator_attachment: authenticator_attachment() | nil,
          resident_key: resident_key_requirement() | nil,
          user_verification: user_verification_requirement() | nil
        }

  @type parse_params :: keyword() | %{optional(atom()) => any()}

  @type error_code :: :invalid_argument
  @type error_message :: String.t()

  @type authenticator_attachment :: :platform | :cross_platform
  @authenticator_attachment [:platform, :cross_platform]

  @type resident_key_requirement :: :required | :preferred | :discouraged
  @resident_key_requirement [:required, :preferred, :discouraged]

  @type user_verification_requirement :: :required | :preferred | :discouraged
  @user_verification_requirement [:required, :preferred, :discouraged]

  defstruct authenticator_attachment: nil, resident_key: nil, user_verification: :preferred

  @doc """
  Parse Authenticator Selection Criteria in a form of map or keyword.

  Possible options
    - :authenticator_attachment
    - :require_resident_key
    - :resident_key
    - :user_verification

  For the meanning of each key, please visit Web Authentication specification
  website.

  Returns `%ExAuthn.WebAuthn.AuthenticatorSelectionCriteria{}` struct or error.

  ## Examples

  The default value for user verification is preferred.

      iex> ExAuthn.WebAuthn.AuthenticatorSelectionCriteria.parse(authenticator_attachment: :cross_platform)
      {:ok, %ExAuthn.WebAuthn.AuthenticatorSelectionCriteria{
        authenticator_attachment: :cross_platform,
        resident_key: nil,
        user_verification: :preferred
      }}

  Require resident key is converted to resident key option since the former is
  deprecated.

      iex> ExAuthn.WebAuthn.AuthenticatorSelectionCriteria.parse(require_resident_key: true)
      {:ok, %ExAuthn.WebAuthn.AuthenticatorSelectionCriteria{
        authenticator_attachment: nil,
        resident_key: :required,
        user_verification: :preferred
      }}

  Error is returned upon undefined option.

      iex> ExAuthn.WebAuthn.AuthenticatorSelectionCriteria.parse(user_verification: :definitely)
      {:error, :invalid_argument, "user_verification must be one of :required, :preferred or :discouraged"}
  """
  @doc since: "1.0.0"
  @spec parse(parse_params()) :: {:ok, t()} | {:error, error_code(), error_message()}
  def parse(options) when is_list(options), do: do_parse(options)

  def parse(options) when is_map(options) do
    options
    |> Map.to_list()
    |> parse()
  end

  def parse(_) do
    {:error, :invalid_argument, "authenticator_selection_criteria must be a map or a keyword"}
  end

  defp do_parse(options, authenticator_selection_criteria \\ %__MODULE__{})
  defp do_parse([], a), do: {:ok, a}

  defp do_parse([{:authenticator_attachment, at} | o], m) when at in @authenticator_attachment do
    do_parse(o, %{m | authenticator_attachment: at})
  end

  defp do_parse([{:authenticator_attachment, _} | _], _) do
    {:error, :invalid_argument,
     "authenticator_attachment must be one of :platform or :cross_platform"}
  end

  defp do_parse([{:require_resident_key, rk} | o], m) when is_boolean(rk) do
    warn(~s"""
    require_resident_key is deprecated, use resident_key instead. Authenticator
    Selection Criteria convert this value to resident key with this condition.

    If require_resident_key is true then resident_key = :required
    Else resident_key = :discouraged

    However, if resident_key value is present, it will override this value.
    """)

    if Map.get(m, :resident_key, nil) == nil do
      if rk do
        do_parse(o, %{m | resident_key: :required})
      else
        do_parse(o, %{m | resident_key: :discouraged})
      end
    else
      do_parse(o, m)
    end
  end

  defp do_parse([{:require_resident_key, _} | _], _) do
    {:error, :invalid_argument, "require_resident key must be boolean"}
  end

  defp do_parse([{:resident_key, rk} | o], m) when rk in @resident_key_requirement do
    do_parse(o, %{m | resident_key: rk})
  end

  defp do_parse([{:resident_key, _} | _], _) do
    {:error, :invalid_argument,
     "resident_key must be one of :required, :preferred or :discouraged"}
  end

  defp do_parse([{:user_verification, ur} | o], m) when ur in @user_verification_requirement do
    do_parse(o, %{m | user_verification: ur})
  end

  defp do_parse([{:user_verification, _} | _], _) do
    {:error, :invalid_argument,
     "user_verification must be one of :required, :preferred or :discouraged"}
  end

  defp warn(message) do
    require Logger; Logger.warn(message)
  end
end
