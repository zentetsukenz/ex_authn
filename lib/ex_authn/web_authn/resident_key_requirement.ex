defmodule ExAuthn.WebAuthn.ResidentKeyRequirement do
  @moduledoc """
  ResidentKeyRequirement describes the relying party requirements for
  client-side discoverable credentials.
  """

  @type t :: :required | :preferred | :discouraged
end
