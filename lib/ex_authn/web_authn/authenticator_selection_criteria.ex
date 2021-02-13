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

  alias ExAuthn.WebAuthn.{
    AuthenticatorAttachment,
    ResidentKeyRequirement,
    UserVerificationRequirement
  }

  @type t :: %__MODULE__{
          authenticator_attachment: AuthenticatorAttachment.t(),
          resident_key: ResidentKeyRequirement.t(),
          user_verification: UserVerificationRequirement.t()
        }

  defstruct authenticator_attachment: nil,
            resident_key: nil,
            user_verification: UserVerificationRequirement.default()
end
