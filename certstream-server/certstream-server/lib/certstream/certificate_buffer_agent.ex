require Logger

defmodule Certstream.CertifcateBuffer do
  use Agent
  use Instruments

  @moduledoc """
    An agent designed to ring-buffer certificate updates as they come in so the most recent 25 certificates can be
    aggregated for the /example.json and /latest.json routes.
  """

  @doc "Starts the CertificateBuffer agent and creates an ETS table for tracking the certificates processed"
  def start_link(_opts) do
    Logger.info("Starting #{__MODULE__}...")
    Agent.start_link(
      fn ->
        :ets.new(:counter, [:named_table, :public])
        :ets.insert(:counter, processed_certificates: 0)
        []
      end,
      name: __MODULE__
    )
  end

  @doc "Adds a certificate update to the circular certificate buffer"
  def add_certs_to_buffer(certificates) do
    cert_count = length(certificates)

    :ets.update_counter(:counter, :processed_certificates, cert_count)
    Instruments.increment("certstream.all.processed_certificates", cert_count)

    Agent.update(__MODULE__, fn state ->
      state = certificates ++ state
      state |> Enum.take(25)
    end)
  end

  @doc "The number of certificates processed"
  def get_processed_certificates do
    :ets.lookup(:counter, :processed_certificates)
    |> Keyword.get(:processed_certificates)
  end

  @doc "Gets the latest certificate seen by Certstream, indented with 4 spaces"
  def get_example_json do
    Agent.get(__MODULE__,
      fn certificates ->
        certificates
        |> List.first
        |> Jason.encode!(pretty: true)
      end
    )
  end

  @doc "Gets the latest 25 cetficiates seen by Certstream, indented with 4 spaces"
  def get_latest_json do
    Agent.get(__MODULE__,
      fn certificates ->
        %{}
        |> Map.put(:messages, certificates)
        |> Jason.encode!(pretty: true)
      end
    )
  end
end
