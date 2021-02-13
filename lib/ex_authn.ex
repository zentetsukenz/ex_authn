defmodule ExAuthn do
  @moduledoc """
  `ExAuthn` module implements Web Authentication API for registration and
  authentication.

  The concept of Web Authentication is that, credentials belong to user and are
  managed by WebAuthn Authenticator, which the relying party can interact
  through the web application.

  You can read more info about Web Authentication API
  [here](https://w3c.github.io/webauthn/#sctn-api)
  """
  @moduledoc since: "1.0.0"

  alias ExAuthn.{
    RegistrationCeremony,
    Option,
    User
  }

  @doc """
  Build a credential creation options by to begin registration ceremony.

  Generate credential creation options and session data to be used in
  registration process.

  Relying party can override configuration by using `begin_registration/2`. Some
  options such as `exclude_credentials` are also available.
  """
  @spec begin_registration(ExAuthn.User.t(), ExAuthn.Option.t()) ::
          {:error, String.t()} | {:ok, ExAuthn.RegistrationCeremony.t()}
  def begin_registration(%User{} = user, %Option{} = option) do
    RegistrationCeremony.begin(user, option)
  end
end
