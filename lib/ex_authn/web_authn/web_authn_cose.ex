defmodule ExAuthn.WebAuthn.WebAuthnCose do
  @type cose_algorithm ::
          :alg_es256
          | :alg_es384
          | :alg_es512
          | :alg_rs1
          | :alg_rs256
          | :alg_rs384
          | :alg_rs512
          | :alg_ps256
          | :alg_ps384
          | :alg_ps512
          | :alg_eddsa

  @type cose_algorithm_identifier ::
          -7
          | -35
          | -36
          | -65535
          | -257
          | -258
          | -259
          | -37
          | -38
          | -39
          | -8

  @cose_algorithm_to_identifier %{
    alg_es256: -7,
    alg_es384: -35,
    alg_es512: -36,
    alg_rs1: -65535,
    alg_rs256: -257,
    alg_rs384: -258,
    alg_rs512: -259,
    alg_ps256: -37,
    alg_ps384: -38,
    alg_ps512: -39,
    alg_eddsa: -8
  }

  @doc """
  Convert COSE Identifier to algorithm.

  ## Examples

      iex> ExAuthn.WebAuthn.WebAuthnCose.to_cose_algorithm(-7)
      {:ok, :alg_es256}

      iex> ExAuthn.WebAuthn.WebAuthnCose.to_cose_algorithm(999)
      {:error, "999 is invalid identifier"}
  """
  @spec to_cose_algorithm(cose_algorithm_identifier()) ::
          {:ok, cose_algorithm()} | {:error, String.t()}
  def to_cose_algorithm(identifier) do
    alg =
      @cose_algorithm_to_identifier
      |> Enum.find(fn {_, v} -> v == identifier end)

    if alg == nil do
      {:error, "#{identifier} is invalid identifier"}
    else
      {:ok, elem(alg, 0)}
    end
  end

  @doc """
  Convert COSE algorithm to identifier.

  ## Examples

      iex> ExAuthn.WebAuthn.WebAuthnCose.to_cose_identifier(:alg_es512)
      {:ok, -36}

      iex> ExAuthn.WebAuthn.WebAuthnCose.to_cose_identifier(:quantum_warp)
      {:error, "quantum_warp is invalid algorithm"}
  """
  @spec to_cose_identifier(cose_algorithm()) ::
          {:ok, cose_algorithm_identifier()} | {:error, String.t()}
  def to_cose_identifier(alg) do
    identifier = Map.get(@cose_algorithm_to_identifier, alg)

    if identifier == nil do
      {:error, "#{alg} is invalid algorithm"}
    else
      {:ok, identifier}
    end
  end

  @doc """
  Return all COSE identifiers.

  ## Examples

      iex> ExAuthn.WebAuthn.WebAuthnCose.all_cose_identifiers
      [-8, -7, -35, -36, -37, -38, -39, -65535, -257, -258, -259]
  """
  @spec all_cose_identifiers() :: list(cose_algorithm_identifier())
  def all_cose_identifiers do
    @cose_algorithm_to_identifier
    |> Map.values()
  end
end
