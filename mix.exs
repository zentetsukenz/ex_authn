defmodule ExAuthn.MixProject do
  use Mix.Project

  def project do
    [
      app: :ex_authn,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env())
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.2"},
      {:cbor, "~> 1.0"},
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:ex_machina, "~> 2.4", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "web", "test/support", "test/factories"]
  defp elixirc_paths(_), do: ["lib", "web"]
end
