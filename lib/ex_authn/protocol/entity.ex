defmodule ExAuthn.Protocol.Entity do
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

      iex> ExAuthn.Protocol.Entity.create_user(%{id: <<1, 2, 3, 4>>, display_name: "iZen", name: "ZentetsuKen", icon: nil})
      {:ok, %{id: <<1, 2, 3, 4>>, display_name: "iZen", credential: %{name: "ZentetsuKen", icon: nil}}}

      iex> ExAuthn.Protocol.Entity.create_user(%{id: <<1, 2, 3, 4>>, display_name: "iZen", name: "ZentetsuKen"})
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

      iex> ExAuthn.Protocol.Entity.create_relying_party(%{id: "zentetsuken", display_name: "ZentetsuKen", icon: nil})
      {:ok, %{id: "zentetsuken", credential: %{name: "ZentetsuKen", icon: nil}}}

      iex> ExAuthn.Protocol.Entity.create_relying_party(%{id: "zentetsuken", display_name: "ZentetsuKen"})
      {:error, "invalid relying party arguments"}
  """
  @spec create_relying_party(%{
          id: String.t(),
          display_name: String.t(),
          icon: String.t()
        }) :: {:ok, relying_party()} | {:error, String.t()}
  def create_relying_party(args)

  def create_relying_party(%{id: _, display_name: _, icon: _} = rp) do
    {:ok,
     %{
       id: rp.id,
       credential: %{
         name: rp.display_name,
         icon: rp.icon
       }
     }}
  end

  def create_relying_party(_), do: {:error, "invalid relying party arguments"}
end
