defmodule ExAuthn.WebAuthn.AttestationTest do
  use ExUnit.Case, async: true

  alias ExAuthn.WebAuthn.{
    Attestation,
    Crypto
  }

  describe "parse/1" do
    setup do
      raw_attestation =
        "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAOXTBMnA6EihBVqknuxdbzLkn5V39V3NJOsohI-ZHnzfAiEAvxraExcTuAYCwExCkjj40WGt_Q6n7HC0QGEPXbdgwEloYXV0aERhdGFY3UmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRV6KFUStzgACNbzGCmSLCyXx8FUDAFkBK44LylgloN-M9D0TKOhCRyoT-GS8pIZVwp-XUHHV9AGHnsQqI7winuLFp5x6__kziqW4zIsoLdt-XnvZYLwUDdpGFqSEZZDJ-pbr2RJ_X7P4eIi9-xA0KaUBAgMmIAEhWCCYhcobY1UkOAz6X7QKb9txhgMhz4Ve0_kCGy7fwnPHQSJYIPwg9xjeHRR_sULkhkSICtcyT36wBIyV4FGqEfprySTc"

      {:ok, raw_attestation: raw_attestation}
    end

    test "returns attestation", context do
      {:ok, attestation} = Attestation.parse(context.raw_attestation)

      assert attestation.authenticator_data != nil
      assert attestation.format == "packed"

      assert attestation.attestation_statement == %{
               "alg" => -7,
               "sig" => %CBOR.Tag{
                 tag: :bytes,
                 value:
                   <<48, 70, 2, 33, 0, 229, 211, 4, 201, 192, 232, 72, 161, 5, 90, 164, 158, 236,
                     93, 111, 50, 228, 159, 149, 119, 245, 93, 205, 36, 235, 40, 132, 143, 153,
                     30, 124, 223, 2, 33, 0, 191, 26, 218, 19, 23, 19, 184, 6, 2, 192, 76, 66,
                     146, 56, 248, 209, 97, 173, 253, 14, 167, 236, 112, 180, 64, 97, 15, 93, 183,
                     96, 192, 73>>
               }
             }
    end
  end

  describe "verify/4" do
    test "returns error when format is none but statement is present" do
      {:error, msg} =
        Attestation.verify(
          %Attestation{format: "none", attestation_statement: <<1>>},
          "1234",
          "1234",
          :required
        )

      assert msg == "attestation format none with attestation present"
    end

    test "returns attestation" do
      {:ok, attestation} =
        Attestation.verify(
          %Attestation{
            format: "packed",
            authenticator_data: <<>>,
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
            }
          },
          Crypto.hash(<<1, 2, 3, 4>>),
          nil,
          :required
        )

      assert attestation.format == "packed"
      assert attestation.authenticator_data != nil

      assert attestation.attestation_statement == %{
               "alg" => -7,
               "sig" => %CBOR.Tag{
                 tag: :bytes,
                 value:
                   <<48, 70, 2, 33, 0, 229, 211, 4, 201, 192, 232, 72, 161, 5, 90, 164, 158, 236,
                     93, 111, 50, 228, 159, 149, 119, 245, 93, 205, 36, 235, 40, 132, 143, 153,
                     30, 124, 223, 2, 33, 0, 191, 26, 218, 19, 23, 19, 184, 6, 2, 192, 76, 66,
                     146, 56, 248, 209, 97, 173, 253, 14, 167, 236, 112, 180, 64, 97, 15, 93, 183,
                     96, 192, 73>>
               }
             }
    end
  end
end
