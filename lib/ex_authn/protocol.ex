defmodule ExAuthn.Protocol do
  @moduledoc """
  Web Authentication specification module.
  """

  alias ExAuthn.Protocol.{
    Authenticator,
    Challenge,
    Options,
    Entity
  }

  # Type delegetion

  @type public_key_credential_creation_options :: Options.public_key_credential_creation_options()
  @type credential_creation :: Options.credential_creation()
  @type user_verification_requirement :: Authenticator.user_verification_requirement()
  @type conveyance_preference :: Options.conveyance_preference()
  @type authenticator_selection :: Options.authenticator_selection()

  defdelegate create_challenge(length_in_byte), to: Challenge, as: :generate
  defdelegate create_user(args), to: Entity
  defdelegate create_relying_party(args), to: Entity
  defdelegate create_authenticator_selection(args), to: Options

  defdelegate create_creation_options(args),
    to: Options,
    as: :create_public_key_credential_creation_options

  defdelegate create_credential_creation(args), to: Options
end
