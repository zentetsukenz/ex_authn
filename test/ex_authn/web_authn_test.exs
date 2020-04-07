defmodule ExAuthn.WebAuthnTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn

  describe "parse/1" do
    setup do
      params = %{
        "id" =>
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        "raw_id" =>
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        "response" => %{
          "attestation_object" =>
            "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOXTBMnA6EihBVqknuxdbzLkn5V39V3NJOsohI-ZHnzfAiEAvxraExcTuAYCwExCkjj40WGt_Q6n7HC0QGEPXbdgwEloYXV0aERhdGFY3UmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV6KFUStzgACNbzGCmSLCyXx8FUDAFkBK44LylgloN-M9D0TKOhCRyoT-GS8pIZVwp-XUHHV9AGHnsQqI7winuLFp5x6__kziqW4zIsoLdt-XnvZYLwUDdpGFqSEZZDJ-pbr2RJ_X7P4eIi9-xA0KaUBAgMmIAEhWCCYhcobY1UkOAz6X7QKb9txhgMhz4Ve0_kCGy7fwnPHQSJYIPwg9xjeHRR_sULkhkSICtcyT36wBIyV4FGqEfprySTc",
          "client_data_json" =>
            "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
        },
        "type" => "public-key"
      }

      {:ok, params: params}
    end

    test "returns parsed public key creation", context do
      {:ok, public_key_creation} = WebAuthn.parse_client_credential_creation(context.params)

      assert public_key_creation.id ==
               "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk"

      assert public_key_creation.type == :public_key

      assert public_key_creation.raw_id ==
               "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk"

      assert public_key_creation.extensions == nil
      assert public_key_creation.response != nil
    end
  end

  describe "validate_credential_creation/6" do
    setup do
      pkey = %ExAuthn.WebAuthn.PublicKeyCredentialCreation{
        extensions: nil,
        id:
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        raw_id:
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        response: %ExAuthn.WebAuthn.AuthenticatorAttestation{
          attestation_object: %ExAuthn.WebAuthn.Attestation{
            attestation_statement: %{
              "alg" => -7,
              "sig" => %CBOR.Tag{
                tag: :bytes,
                value:
                  <<48, 70, 2, 33, 0, 229, 211, 4, 201, 192, 232, 72, 161, 5, 90, 164, 158, 236,
                    93, 111, 50, 228, 159, 149, 119, 245, 93, 205, 36, 235, 40, 132, 143, 153, 30,
                    124, 223, 2, 33, 0, 191, 26, 218, 19, 23, 19, 184, 6, 2, 192, 76, 66, 146, 56,
                    248, 209, 97, 173, 253, 14, 167, 236, 112, 180, 64, 97, 15, 93, 183, 96, 192,
                    73>>
              }
            },
            authenticator_data: %ExAuthn.WebAuthn.AuthenticatorData{
              attested_credential_data: %ExAuthn.WebAuthn.AttestedCredentialData{
                aaguid: <<173, 206, 0, 2, 53, 188, 198, 10, 100, 139, 11, 37, 241, 240, 85, 3>>,
                credential_id:
                  <<1, 43, 142, 11, 202, 88, 37, 160, 223, 140, 244, 61, 19, 40, 232, 66, 71, 42,
                    19, 248, 100, 188, 164, 134, 85, 194, 159, 151, 80, 113, 213, 244, 1, 135,
                    158, 196, 42, 35, 188, 34, 158, 226, 197, 167, 156, 122, 255, 249, 51, 138,
                    165, 184, 204, 139, 40, 45, 219, 126, 94, 123, 217, 96, 188, 20, 13, 218, 70,
                    22, 164, 132, 101, 144, 201, 250, 150, 235, 217, 18, 127, 95, 179, 248, 120,
                    136, 189, 251, 16, 52, 41>>,
                credential_id_length: 89,
                credential_public_key: %{
                  -3 => %CBOR.Tag{
                    tag: :bytes,
                    value:
                      <<252, 32, 247, 24, 222, 29, 20, 127, 177, 66, 228, 134, 68, 136, 10, 215,
                        50, 79, 126, 176, 4, 140, 149, 224, 81, 170, 17, 250, 107, 201, 36, 220>>
                  },
                  -2 => %CBOR.Tag{
                    tag: :bytes,
                    value:
                      <<152, 133, 202, 27, 99, 85, 36, 56, 12, 250, 95, 180, 10, 111, 219, 113,
                        134, 3, 33, 207, 133, 94, 211, 249, 2, 27, 46, 223, 194, 115, 199, 65>>
                  },
                  -1 => 1,
                  1 => 2,
                  3 => -7
                }
              },
              extensions: nil,
              flags: %{
                attested_credential_data: true,
                has_extensions: false,
                user_present: true,
                user_verified: true
              },
              rp_id_hash:
                <<73, 150, 13, 229, 136, 14, 140, 104, 116, 52, 23, 15, 100, 118, 96, 91, 143,
                  228, 174, 185, 162, 134, 50, 199, 153, 92, 243, 186, 131, 29, 151, 99>>,
              sign_count: 1_586_107_716
            },
            format: "packed"
          },
          client_data: %ExAuthn.WebAuthn.ClientData{
            challenge: "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo",
            cross_origin: nil,
            origin: "http://localhost:4000",
            token_binding: nil,
            type: :create
          }
        },
        type: :public_key
      }

      raw = %{
        "id" =>
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        "raw_id" =>
          "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk",
        "response" => %{
          "attestation_object" =>
            "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOXTBMnA6EihBVqknuxdbzLkn5V39V3NJOsohI-ZHnzfAiEAvxraExcTuAYCwExCkjj40WGt_Q6n7HC0QGEPXbdgwEloYXV0aERhdGFY3UmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV6KFUStzgACNbzGCmSLCyXx8FUDAFkBK44LylgloN-M9D0TKOhCRyoT-GS8pIZVwp-XUHHV9AGHnsQqI7winuLFp5x6__kziqW4zIsoLdt-XnvZYLwUDdpGFqSEZZDJ-pbr2RJ_X7P4eIi9-xA0KaUBAgMmIAEhWCCYhcobY1UkOAz6X7QKb9txhgMhz4Ve0_kCGy7fwnPHQSJYIPwg9xjeHRR_sULkhkSICtcyT36wBIyV4FGqEfprySTc",
          "client_data_json" =>
            "eyJjaGFsbGVuZ2UiOiIzUW1YbW1uYy1PZWJ6SzhiVFFzXzhwR3lySVQyLVl5aEUyMlpJa2xkQVlvIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo0MDAwIiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
        },
        "type" => "public-key"
      }

      c = "3QmXmmnc-OebzK8bTQs_8pGyrIT2-YyhE22ZIkldAYo"

      {:ok, pkey: pkey, raw: raw, challenge: c}
    end

    test "returns public creation", context do
      {:ok, pkey} =
        WebAuthn.validate_credential_creation(
          context.pkey,
          context.raw,
          context.challenge,
          :required,
          "localhost",
          "http://localhost:4000"
        )

      assert pkey.id ==
               "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk"

      assert pkey.type == :public_key

      assert pkey.raw_id ==
               "ASuOC8pYJaDfjPQ9EyjoQkcqE_hkvKSGVcKfl1Bx1fQBh57EKiO8Ip7ixaecev_5M4qluMyLKC3bfl572WC8FA3aRhakhGWQyfqW69kSf1-z-HiIvfsQNCk"

      assert pkey.extensions == nil
      assert pkey.response != nil
    end
  end
end
