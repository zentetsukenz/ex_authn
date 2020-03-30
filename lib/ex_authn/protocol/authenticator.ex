defmodule ExAuthn.Protocol.Authenticator do
  @type authenticator_response :: %{
          client_data_json: String.t()
        }

  @type authenticator_data :: %{
          rp_id_hash: binary(),
          flags: authenticator_flags(),
          counter: pos_integer(),
          attested_credential_data: attested_credential_data(),
          ext_data: binary()
        }

  @type authenticator_attachment :: :platform | :cross_platform
  @type authenticator_transport :: :usb | :nfc | :ble | :internal
  @type user_verification_requirement :: :required | :preferred | :discouraged
  @type resident_key :: :required | :preferred | :discouraged

  @type attested_credential_data :: %{
          aaguid: binary(),
          credential_id: binary(),
          credential_public_key: binary()
        }

  @type authenticator_flags ::
          :user_present
          | :user_verified
          | :attested_credential_data
          | :has_extensions
end
