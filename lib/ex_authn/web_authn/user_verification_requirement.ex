defmodule ExAuthn.WebAuthn.UserVerificationRequirement do
  @moduledoc """
  UserVerificationRequirement is a value relying party may use to require user
  verification for some of its operations.
  """

  @type t :: :required | :preferred | :discouraged

  @spec default :: :preferred
  def default(), do: :preferred
end
