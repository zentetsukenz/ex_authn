defmodule ExAuthn.Protocol.AttestedCredentialData do
  @type t :: %__MODULE__{
          aaguid: binary(),
          credential_id_length: pos_integer(),
          credential_id: binary(),
          credential_public_key: public_key()
        }

  @type public_key :: %{integer() => any()}

  @min_data_length 18

  defstruct aaguid: nil, credential_id_length: nil, credential_id: nil, credential_public_key: nil

  @spec parse(binary()) :: {:ok, t(), binary()} | {:error, String.t()}
  def parse(raw_att_data) when byte_size(raw_att_data) < @min_data_length do
    {:error, "attested credential data too short"}
  end

  def parse(raw_att_data) do
    <<aaguid::binary-size(16), rest1::binary>> = raw_att_data
    <<credential_length::big-integer-size(16), rest2::binary>> = rest1
    <<credential_id::binary-size(credential_length), raw_pkey::binary>> = rest2

    case CBOR.decode(raw_pkey) do
      {:ok, pkey, ext} ->
        {:ok,
         %__MODULE__{
           aaguid: aaguid,
           credential_id_length: credential_length,
           credential_id: credential_id,
           credential_public_key: pkey
         }, ext}

      _ ->
        {:error, "cannot decode public key"}
    end
  end
end
