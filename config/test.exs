import Config

config :ex_authn,
  rp: %{
    id: "localhost",
    name: "ExAuthnTest",
    origin: "http://localhost:4000"
  },
  timeout: 60000,
  attestation_preference: :direct,
  authenticator_selection: %{
    user_verification: :preferred
  }
