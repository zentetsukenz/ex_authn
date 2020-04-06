defmodule ExAuthn.Protocol.AuthenticatorData do
  use Bitwise

  alias ExAuthn.Protocol.AttestedCredentialData

  @type t :: %__MODULE__{
          rp_id_hash: binary(),
          flags: authenticator_flags(),
          sign_count: pos_integer(),
          attested_credential_data: AttestedCredentialData.t(),
          extensions: any() | nil
        }

  @type authenticator_attachment :: :platform | :cross_platform
  @type authenticator_transport :: :usb | :nfc | :ble | :internal
  @type user_verification_requirement :: :required | :preferred | :discouraged
  @type resident_key :: :required | :preferred | :discouraged

  @type authenticator_flags :: %{
          user_present: boolean(),
          user_verified: boolean(),
          attested_credential_data: boolean(),
          has_extensions: boolean()
        }

  @type raw_authenticator_data :: binary()

  @initial_flag %{
    user_present: 0b00000001,
    user_verified: 0b00000100,
    attested_credential_data: 0b01000000,
    has_extensions: 0b10000000
  }

  @min_data_length 37

  defstruct rp_id_hash: nil,
            flags: nil,
            sign_count: nil,
            attested_credential_data: nil,
            extensions: nil

  @spec parse(raw_authenticator_data()) :: {:ok, t()} | {:error, String.t()}
  def parse(raw_authenticator_data) when @min_data_length > byte_size(raw_authenticator_data) do
    {:error, "authenticator data length must be at least #{@min_data_length} bytes"}
  end

  def parse(raw_authenticator_data) do
    <<rp_id_hash::binary-size(32), rest1::binary>> = raw_authenticator_data
    <<raw_flags::binary-size(1), rest2::binary>> = rest1
    <<sign_count::big-integer-size(32), rest3::binary>> = rest2

    with {:ok, flags} <- parse_flags(raw_flags),
         {:ok, attested_credential_data, remaining} <-
           parse_att_data(flags, rest3),
         {:ok, ext} <- parse_ext_data(flags, remaining) do
      {:ok,
       %__MODULE__{
         rp_id_hash: rp_id_hash,
         flags: flags,
         sign_count: sign_count,
         attested_credential_data: attested_credential_data,
         extensions: ext
       }}
    else
      {:error, msg} -> {:error, msg}
    end
  end

  defp parse_flags(flags) do
    flag_int = :binary.decode_unsigned(flags)

    parsed_flag =
      @initial_flag
      |> Enum.reduce(%{}, fn {flag, bit}, acc ->
        if band(bit, flag_int) == bit do
          Map.put(acc, flag, true)
        else
          Map.put(acc, flag, false)
        end
      end)

    {:ok, parsed_flag}
  end

  defp parse_att_data(%{attested_credential_data: false, has_extensions: false}, att_data)
       when byte_size(att_data) > 0 do
    {:error, "attested credential flag not set"}
  end

  defp parse_att_data(%{attested_credential_data: true}, att_data)
       when byte_size(att_data) == 0 do
    {:error, "attested credential flag set but data is missing"}
  end

  defp parse_att_data(%{attested_credential_data: false}, att_data)
       when byte_size(att_data) == 0 do
    {:ok, nil, ""}
  end

  defp parse_att_data(%{attested_credential_data: true}, att_data)
       when byte_size(att_data) > 0 do
    AttestedCredentialData.parse(att_data)
  end

  defp parse_ext_data(%{has_extensions: false}, ext_data) when byte_size(ext_data) > 0 do
    {:error, "leftover bytes decoding authenticator data"}
  end

  defp parse_ext_data(%{has_extensions: true}, ext_data) when byte_size(ext_data) == 0 do
    {:error, "extensions flag set but no data remain"}
  end

  defp parse_ext_data(%{has_extensions: true}, ext_data) when byte_size(ext_data) > 0 do
    {:ok, ext_data}
  end

  defp parse_ext_data(%{has_extensions: false}, ext_data) when byte_size(ext_data) == 0 do
    {:ok, nil}
  end

  @spec verify(t(), hashed_config_rp_id :: String.t(), user_verification_requirement()) ::
          {:ok, t()} | {:error, String.t()}
  def verify(%{flags: %{user_verified: false}}, _, :required) do
    {:error, "user verification required"}
  end

  def verify(%{flags: %{user_present: false}}, _, _) do
    {:error, "user not present"}
  end

  def verify(%{rp_id_hash: rp_id_hash}, config_rp_id, _) when rp_id_hash != config_rp_id do
    {:error, "relying party id mismatch"}
  end

  def verify(auth_data, _, _) do
    {:ok, auth_data}
  end
end
