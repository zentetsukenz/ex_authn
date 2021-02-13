defmodule ExAuthn.Factory do
  use ExMachina

  def authenticator_selection_factory do
    %ExAuthn.WebAuthn.AuthenticatorSelectionCriteria{
      authenticator_attachment: :platform,
      resident_key: :preferred,
      user_verification: :preferred
    }
  end

  def option_factory do
    %ExAuthn.Option{
      rp: %{
        id: "test.localhost",
        name: "ExAuthnTest",
        origin: "https://test.localhost"
      },
      attestation_preference: :none,
      authenticator_selection: build(:authenticator_selection),
      timeout: 60000
    }
  end

  def user_factory do
    %ExAuthn.User{
      id: "user_id",
      name: "user@name",
      display_name: "User Name"
    }
  end
end
