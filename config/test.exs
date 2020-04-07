import Config

config :ex_authn,
  relying_party_id: "localhost",
  relying_party_name: "Ex Authn",
  relying_party_origin: "http://localhost:4000",
  timeout: 60000,
  attestation_preference: :direct,
  user_verification_requirement: :preferred
