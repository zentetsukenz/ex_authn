defmodule ExAuthn.WebAuthn.UserVerificationRequirement do
  @type t :: :required | :preferred | :discouraged

  @spec default :: :preferred
  def default(), do: :preferred
end
