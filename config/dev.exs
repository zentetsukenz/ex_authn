import Config

config :ex_authn,
  relying_party_id: "localhost",
  relying_party_name: "Ex Authn",
  relying_party_origin: "http://localhost",
  timeout: 60000,
  attestation: :direct,
  user_verification: :preferred,
  public_key_credential_parameters: [
    %{type: :public_key, alg: -7},
    %{type: :public_key, alg: -8},
    %{type: :public_key, alg: -35},
    %{type: :public_key, alg: -36},
    %{type: :public_key, alg: -37},
    %{type: :public_key, alg: -38},
    %{type: :public_key, alg: -39}
  ]
