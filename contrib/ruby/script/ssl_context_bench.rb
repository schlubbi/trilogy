require "json"
require "trilogy"
require_relative "../test/support/tls_server"

samples = Integer(ENV.fetch("SAMPLES", "100"))
threads = Integer(ENV.fetch("THREADS", "1"))
raise ArgumentError, "SAMPLES and THREADS must be positive" unless samples > 0 && threads > 0

server = TLSTestServer.new
options = server.options
network_options = options.reject { |key, _| [:ssl_mode, :ssl_ca, :tls_min_version, :tls_max_version].include?(key) }
clock = -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
results = {
  ruby: RUBY_DESCRIPTION,
  openssl: OpenSSL::OPENSSL_LIBRARY_VERSION,
  samples_per_thread: samples,
  threads: threads,
  ca_certificates: File.read(server.ca_file).scan("-----BEGIN CERTIFICATE-----").size,
  verification: "VERIFY_IDENTITY",
}

begin
  modes = [[:fresh, options]]
  unless ARGV.include?("--baseline")
    started = clock.call
    context = Trilogy::SSLContext.new(options.select { |key, _| [:ssl_mode, :ssl_ca, :tls_min_version, :tls_max_version].include?(key) })
    results[:shared_context_setup_ms] = (clock.call - started) * 1000
    modes << [:reuse, network_options.merge(ssl_context: context)]
  end

  modes.each do |mode, config|
    5.times do
      client = Trilogy.new(config.dup)
      client.ping
      client.close
    end
    started = clock.call
    workers = Array.new(threads) do
      Thread.new do
        Array.new(samples) do
          beginning = clock.call
          client = Trilogy.new(config.dup)
          elapsed = (clock.call - beginning) * 1000
          client.ping
          client.close
          elapsed
        end
      end
    end
    timings = workers.flat_map(&:value).sort
    results[mode] = {
      mean_connect_ms: timings.sum / timings.size,
      p50_connect_ms: timings[timings.size / 2],
      p95_connect_ms: timings[(timings.size * 0.95).floor],
      total_wall_ms: (clock.call - started) * 1000,
    }
  end
  if results[:reuse]
    results[:mean_connect_speedup] = results[:fresh][:mean_connect_ms] / results[:reuse][:mean_connect_ms]
  end
  puts JSON.pretty_generate(results)
  if ARGV.include?("--assert-speedup") && results.fetch(:mean_connect_speedup) < 1.5
    abort "context reuse failed to improve mean connection time by at least 1.5x"
  end
ensure
  server.close
end
