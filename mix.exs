defmodule ExAws.ElasticLoadBalancing.Mixfile do
  use Mix.Project

  @source_url "https://github.com/fmcgeough/ex_aws_elastic_load_balancing"
  @version "2.2.1"

  def project do
    [
      app: :ex_aws_elastic_load_balancing,
      version: @version,
      elixir: "~> 1.5",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "AWS Elastic Load Balancing service for ex_aws",
      source_url: @source_url,
      homepage_url: @source_url,
      package: package(),
      docs: docs()
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:sweet_xml, "~> 0.6", optional: true},
      {:hackney, "1.6.3 or 1.6.5 or 1.7.1 or 1.8.6 or ~> 1.9", only: [:dev, :test]},
      {:poison, ">= 1.2.0", optional: true},
      {:ex_doc, "~> 0.34.2", only: [:dev, :test]},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:ex_aws, "~> 2.5"},
      {:dialyxir, "~> 1.4.3", only: [:dev, :test], runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Frank McGeough"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      name: "ExAws.CloudTrail",
      canonical: "http://hexdocs.pm/ex_aws_elastic_load_balancing",
      source_url: @source_url,
      main: "readme",
      extras: ["README.md", "CHANGELOG.md": [title: "Changelog"], LICENSE: [title: "License"]]
    ]
  end
end
