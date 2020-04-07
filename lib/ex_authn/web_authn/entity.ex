defmodule ExAuthn.WebAuthn.Entity do
  @type relying_party :: %{
          id: String.t(),
          credential: credential()
        }

  @type user :: %{
          id: binary(),
          display_name: String.t(),
          credential: credential()
        }

  @type credential :: %{
          name: String.t(),
          icon: String.t()
        }

  @doc """
  Create user.

  ## Examples

      iex> ExAuthn.WebAuthn.Entity.create_user(%{id: <<1, 2, 3, 4>>, display_name: "iZen", name: "ZentetsuKen", icon: nil})
      {:ok, %{id: <<1, 2, 3, 4>>, display_name: "iZen", credential: %{name: "ZentetsuKen", icon: nil}}}

      iex> ExAuthn.WebAuthn.Entity.create_user(%{id: <<1, 2, 3, 4>>, display_name: "iZen", name: "ZentetsuKen"})
      {:error, "invalid user arguments"}
  """
  @spec create_user(%{id: binary(), name: String.t(), display_name: String.t(), icon: String.t()}) ::
          {:ok, user()} | {:error, String.t()}
  def create_user(args)

  def create_user(%{id: _, display_name: _, name: _, icon: _} = user) do
    {:ok,
     %{
       id: user.id,
       display_name: user.display_name,
       credential: %{
         name: user.name,
         icon: user.icon
       }
     }}
  end

  def create_user(_), do: {:error, "invalid user arguments"}

  @doc """
  Create relying party.

  ## Examples

      iex> ExAuthn.WebAuthn.Entity.create_relying_party(%{id: "zentetsuken", name: "ZentetsuKen", origin: "http://localhost"})
      {:ok, %{id: "zentetsuken", credential: %{name: "ZentetsuKen", icon: ""}}}

      iex> ExAuthn.WebAuthn.Entity.create_relying_party(%{id: "zentetsuken", name: "ZentetsuKen"})
      {:error, "invalid relying party arguments"}
  """
  @spec create_relying_party(%{
          id: String.t(),
          name: String.t(),
          origin: String.t()
        }) :: {:ok, relying_party()} | {:error, String.t()}
  def create_relying_party(args)

  def create_relying_party(%{id: _, name: _, origin: _} = rp) do
    {:ok,
     %{
       id: rp.id,
       credential: %{
         name: rp.name,
         icon: ""
       }
     }}
  end

  def create_relying_party(_), do: {:error, "invalid relying party arguments"}
end
